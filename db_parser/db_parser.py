import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from enum import Enum
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from urllib.parse import unquote

from charset_normalizer import from_bytes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import duckdb
from tqdm import tqdm
from transliterate import translit

import config


class SearchType(Enum):
    SYNC = 0
    NAME = 1
    PHONE = 2
    EMAIL = 3
    BIRTHDAY = 4


TRANSLATION_TABLE = str.maketrans({
    ",": " ",
    "\t": " ",
    "{": " ",
    "}": " ",
    "[": " ",
    "]": " ",
    '"': " ",
    "\r": " ",
    "\n": " ",
})


def derive_keys(password: str, salt: bytes) -> tuple[bytes, str]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config.KDF_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    duckdb_ascii_key = raw_key.hex()[:32]
    return raw_key, duckdb_ascii_key


def get_key_verify_path() -> Path:
    return config.PARQUET_DIR / "key.verify"


def store_key_verifier(aes_key: bytes) -> None:
    config.PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(aes_key).hexdigest()
    get_key_verify_path().write_text(digest, encoding="utf-8")


def verify_key_or_exit(aes_key: bytes | None) -> None:
    if not config.ENCRYPT_INDEX or aes_key is None:
        return
    verify_path = get_key_verify_path()
    digest = hashlib.sha256(aes_key).hexdigest()
    if verify_path.exists():
        expected = verify_path.read_text(encoding="utf-8").strip()
        if expected != digest:
            print("[ERROR] Invalid encryption password. Use 'passwd' command or set correct DB_PARSER_KEY.")
            sys.exit(1)
    else:
        store_key_verifier(aes_key)


def ensure_crypto_extension() -> None:
    if not config.ENCRYPT_INDEX:
        return
    con = duckdb.connect(":memory:")
    try:
        con.execute("LOAD httpfs")
    except Exception:
        try:
            con.execute("INSTALL httpfs; LOAD httpfs")
        except Exception:
            pass
    finally:
        con.close()


def configure_duckdb_session(
    con: duckdb.DuckDBPyConnection,
    encrypt_enabled: bool,
    duckdb_key: str,
    threads: int = 1,
    key_name: str = "idx_key",
) -> None:
    con.execute("SET enable_progress_bar = false")
    con.execute(f"PRAGMA threads={threads}")
    if encrypt_enabled:
        try:
            con.execute("LOAD httpfs")
        except Exception:
            con.execute("SET force_mbedtls_unsafe = 'true'")
        con.execute(f"PRAGMA add_parquet_key('{key_name}', '{duckdb_key}')")


def get_manifest_path(encrypted: bool | None = None) -> Path:
    is_enc = config.ENCRYPT_INDEX if encrypted is None else encrypted
    manifest_name = "manifest.enc" if is_enc else "manifest.json"
    return config.PARQUET_DIR / manifest_name


def load_manifest(manifest_path: Path, aes_key: bytes | None) -> dict[str, dict]:
    if not manifest_path.exists():
        return {}
    raw_bytes = manifest_path.read_bytes()
    if config.ENCRYPT_INDEX and aes_key is not None:
        try:
            nonce, ciphertext = raw_bytes[:12], raw_bytes[12:]
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode("utf-8"))
        except InvalidTag:
            print("[ERROR] Failed to decrypt manifest.enc: invalid password or corrupted file.")
            sys.exit(1)
    return json.loads(raw_bytes.decode("utf-8"))


def save_manifest(manifest_path: Path, manifest: dict[str, dict], aes_key: bytes | None) -> None:
    config.PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=2).encode("utf-8")
    if config.ENCRYPT_INDEX and aes_key is not None:
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, payload, None)
        manifest_path.write_bytes(nonce + ciphertext)
    else:
        manifest_path.write_bytes(payload)


def is_readable_text_file(file_path: Path) -> tuple[bool, str, str]:
    try:
        with file_path.open("rb") as f:
            sample = f.read(config.TEXT_CHECK_BYTES)
    except OSError as exc:
        return False, "", f"OS read error: {exc}"

    if not sample:
        return False, "", "Empty file"

    is_utf16_32 = sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"))
    if b"\x00" in sample and not is_utf16_32:
        return False, "", "Binary file detected (contains null bytes)"

    safe_samples = [sample]
    if len(sample) == config.TEXT_CHECK_BYTES and len(sample) > 4:
        safe_samples.extend([sample[:-1], sample[:-2], sample[:-3]])

    for encoding in ("utf-8-sig", "utf-8"):
        for chunk in safe_samples:
            try:
                chunk.decode(encoding)
                return True, encoding, ""
            except UnicodeDecodeError:
                continue

    match = from_bytes(sample).best()
    if match is not None:
        if match.chaos > config.MAX_CHAOS_THRESHOLD:
            return False, "", f"Binary or corrupted text detected (chaos={match.chaos:.2f})"
        return True, match.encoding, ""

    return False, "", "Unsupported or unrecognizable text encoding"


def read_as_utf8(file_path: Path) -> str:
    is_readable, encoding, error = is_readable_text_file(file_path)
    if not is_readable:
        raise ValueError(f"Cannot read {file_path}: {error}")

    raw_bytes = file_path.read_bytes()
    text = raw_bytes.decode(encoding, errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def flatten_json_record(record: object) -> str:
    if isinstance(record, dict):
        return " ".join(f"{k} {flatten_json_record(v)}" for k, v in record.items() if v is not None)
    if isinstance(record, list):
        return " ".join(flatten_json_record(v) for v in record if v is not None)
    return str(record)


def normalize_line(raw_line: str) -> str:
    if not raw_line:
        return ""
    if raw_line.startswith("\ufeff"):
        raw_line = raw_line[1:]
    if not raw_line.strip():
        return ""
    if "%" in raw_line:
        raw_line = unquote(raw_line)
    return " ".join(raw_line.translate(TRANSLATION_TABLE).upper().split())


def stream_normalize_to_tsv(src_path: Path, encoding: str, out_handle) -> int:
    file_name = src_path.name
    written = 0
    chunk_buffer = []

    if src_path.suffix.lower() == ".json":
        raw_text = src_path.read_text(encoding=encoding, errors="replace")
        if raw_text.startswith("\ufeff"):
            raw_text = raw_text[1:]
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                iterable = (flatten_json_record(item) for item in parsed)
            elif isinstance(parsed, dict):
                iterable = (flatten_json_record(v) for v in parsed.values())
            else:
                iterable = raw_text.splitlines()
        except Exception:
            iterable = raw_text.splitlines()

        for raw_line in iterable:
            cleaned = normalize_line(raw_line)
            if cleaned:
                chunk_buffer.append(f"{file_name}\t{cleaned}\n")
                written += 1
                if len(chunk_buffer) >= config.STREAM_CHUNK_LINES:
                    out_handle.writelines(chunk_buffer)
                    chunk_buffer.clear()
    else:
        with src_path.open("r", encoding=encoding, errors="replace", buffering=16 * 1024 * 1024) as f:
            for raw_line in f:
                cleaned = normalize_line(raw_line)
                if cleaned:
                    chunk_buffer.append(f"{file_name}\t{cleaned}\n")
                    written += 1
                    if len(chunk_buffer) >= config.STREAM_CHUNK_LINES:
                        out_handle.writelines(chunk_buffer)
                        chunk_buffer.clear()

    if chunk_buffer:
        out_handle.writelines(chunk_buffer)
        chunk_buffer.clear()

    return written


def process_group_worker(task: tuple) -> tuple[str, str, list[tuple[str, dict]], list[str], int]:
    (
        folder_name,
        out_parquet_str,
        file_entries,
        append_existing,
        encrypt_enabled,
        duckdb_key,
    ) = task

    warnings = []
    valid_entries = []
    total_lines = 0

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tsv", delete=False) as tmp:
        tmp_tsv_path = Path(tmp.name)
        for file_path_str, meta in file_entries:
            src_path = Path(file_path_str)
            ok, encoding, reason = is_readable_text_file(src_path)
            if not ok:
                warnings.append(f"[WARNING] Skipping '{src_path}': {reason}")
                continue
            count = stream_normalize_to_tsv(src_path, encoding, tmp)
            if count == 0:
                warnings.append(f"[WARNING] Skipping '{src_path}': No valid text lines extracted")
                continue
            total_lines += count
            valid_entries.append((file_path_str, meta))

    if not valid_entries:
        tmp_tsv_path.unlink(missing_ok=True)
        return folder_name, out_parquet_str, [], warnings, 0

    out_path = Path(out_parquet_str)
    tmp_parquet_path = out_path.with_suffix(out_path.suffix + ".tmp")

    try:
        con = duckdb.connect(":memory:")
        configure_duckdb_session(con, encrypt_enabled, duckdb_key, threads=1)
        enc_write = ", ENCRYPTION_CONFIG {footer_key: 'idx_key'}" if encrypt_enabled else ""
        enc_read = ", encryption_config = {footer_key: 'idx_key'}" if encrypt_enabled else ""

        new_records_sql = """
            SELECT
                ? AS folder_name,
                column0 AS source_file,
                column1 AS item
            FROM read_csv(
                ?,
                header = false,
                sep = '\t',
                quote = '',
                escape = '',
                columns = {'column0': 'VARCHAR', 'column1': 'VARCHAR'},
                ignore_errors = true
            )
        """
        sql_params = [folder_name, str(tmp_tsv_path)]

        if append_existing and out_path.exists():
            removed_sources = [Path(fp).name for fp, _ in valid_entries]
            source_query = f"""
                SELECT folder_name, source_file, item
                FROM read_parquet(?{enc_read})
                WHERE source_file NOT IN (SELECT UNNEST(?::VARCHAR[]))
                UNION
                {new_records_sql}
            """
            sql_params = [str(out_path), removed_sources, folder_name, str(tmp_tsv_path)]
        else:
            source_query = f"SELECT DISTINCT folder_name, source_file, item FROM ({new_records_sql})"

        con.execute(
            f"""
            COPY ({source_query}) TO ? (
                FORMAT PARQUET,
                COMPRESSION {config.COMPRESSION_CODEC},
                COMPRESSION_LEVEL {config.COMPRESSION_LEVEL}
                {enc_write}
            )
            """,
            [*sql_params, str(tmp_parquet_path)],
        )
        con.close()
        shutil.move(str(tmp_parquet_path), str(out_path))
    finally:
        tmp_tsv_path.unlink(missing_ok=True)
        tmp_parquet_path.unlink(missing_ok=True)

    return folder_name, out_parquet_str, valid_entries, warnings, total_lines


def get_parquet_filename(folder_name: str, resolved_file_path: str) -> str:
    parquet_ext = ".eparquet" if config.ENCRYPT_INDEX else ".parquet"
    if config.MERGE_FOLDER_PARQUET:
        return f"{folder_name}{parquet_ext}"
    file_id = hashlib.sha1(resolved_file_path.encode("utf-8")).hexdigest()[:16]
    return f"{folder_name}_{file_id}{parquet_ext}"


def collect_folder_parquets(manifest: dict[str, dict]) -> dict[str, list[Path]]:
    folder_parquets: dict[str, set[Path]] = {}
    for meta in manifest.values():
        if meta.get("encrypted") == config.ENCRYPT_INDEX:
            p_path = config.PARQUET_DIR / meta["parquet_file"]
            if p_path.exists():
                folder_parquets.setdefault(meta["folder"], set()).add(p_path)
    return {folder: sorted(paths) for folder, paths in folder_parquets.items()}


def sync_parquet_store(
    aes_key: bytes | None = None,
    duckdb_key: str = "",
    extra_sources: list[tuple[str, Path]] | None = None,
) -> dict[str, list[Path]]:
    if config.ENCRYPT_INDEX and (aes_key is None or not duckdb_key):
        aes_key, duckdb_key = derive_keys(config.ENCRYPTION_PASSWORD, config.ENCRYPTION_SALT)
    verify_key_or_exit(aes_key)

    store_dir = config.PARQUET_DIR
    store_dir.mkdir(parents=True, exist_ok=True)
    ensure_crypto_extension()

    manifest_path = get_manifest_path()
    manifest = load_manifest(manifest_path, aes_key)

    candidate_files: list[tuple[str, Path]] = []
    if extra_sources is not None:
        candidate_files.extend(extra_sources)
    elif config.DB_PATH.exists():
        folders = sorted(x for x in config.DB_PATH.iterdir() if x.is_dir())
        for folder in folders:
            db_chunks_counter = 0
            files = sorted(
                x for x in folder.iterdir()
                if x.is_file() and (not config.SUPPORTED_EXTENSIONS or x.suffix.lower() in config.SUPPORTED_EXTENSIONS)
            )
            for file in files:
                db_chunks_counter += 1
                if config.DEMO and db_chunks_counter > 3:
                    break
                candidate_files.append((folder.name, file))

    grouped_pending: dict[str, list[tuple[str, dict]]] = {}
    scan_bar = tqdm(candidate_files, desc="Scanning source files", unit="file")
    for folder_name, file in scan_bar:
        scan_bar.set_postfix_str(f"{folder_name}/{file.name}", refresh=False)
        resolved = str(file.resolve())
        stat = file.stat()
        parquet_name = get_parquet_filename(folder_name, resolved)
        prev = manifest.get(resolved)
        if (
            prev
            and prev.get("size") == stat.st_size
            and prev.get("mtime_ns") == stat.st_mtime_ns
            and prev.get("encrypted") == config.ENCRYPT_INDEX
            and prev.get("parquet_file") == parquet_name
            and (store_dir / parquet_name).exists()
        ):
            continue

        ok, detected_encoding, reason = is_readable_text_file(file)
        if not ok:
            tqdm.write(f"[WARNING] Skipping unreadable or binary file '{folder_name}/{file.name}': {reason}")
            continue

        meta = {
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "parquet_file": parquet_name,
            "folder": folder_name,
            "source_file": file.name,
            "encoding": detected_encoding,
            "encrypted": config.ENCRYPT_INDEX,
        }
        grouped_pending.setdefault(parquet_name, []).append((resolved, meta))

    if not grouped_pending:
        print("Parquet index is already up to date.")
        return collect_folder_parquets(manifest)

    worker_tasks = []
    for parquet_name, entries in grouped_pending.items():
        folder_name = entries[0][1]["folder"]
        out_parquet_str = str((store_dir / parquet_name).resolve())
        append_existing = config.MERGE_FOLDER_PARQUET and (store_dir / parquet_name).exists()
        worker_tasks.append((
            folder_name,
            out_parquet_str,
            entries,
            append_existing,
            config.ENCRYPT_INDEX,
            duckdb_key,
        ))

    with ProcessPoolExecutor(config.CPU_CORES) as executor:
        future_to_label = {}
        for task in worker_tasks:
            folder_name = task[0]
            file_names = ", ".join(Path(fp).name for fp, _ in task[2][:2])
            if len(task[2]) > 2:
                file_names += f" (+{len(task[2]) - 2} more)"
            label = f"{folder_name}[{file_names}]"
            future = executor.submit(process_group_worker, task)
            future_to_label[future] = label

        idx_bar = tqdm(as_completed(future_to_label), total=len(future_to_label), desc="Indexing to Parquet", unit="task")
        for future in idx_bar:
            label = future_to_label[future]
            idx_bar.set_postfix_str(label, refresh=True)
            _, _, valid_entries, warnings, _ = future.result()
            for w in warnings:
                tqdm.write(w)
            for resolved_path, meta in valid_entries:
                manifest[resolved_path] = meta
            save_manifest(manifest_path, manifest, aes_key)

    return collect_folder_parquets(manifest)


def get_indexed_parquets(aes_key: bytes | None, duckdb_key: str) -> dict[str, list[Path]]:
    manifest_path = get_manifest_path()
    if manifest_path.exists():
        manifest = load_manifest(manifest_path, aes_key)
        folder_parquets = collect_folder_parquets(manifest)
        if folder_parquets:
            return folder_parquets
    return sync_parquet_store(aes_key, duckdb_key)


def parse_terms(terms_str: str) -> list[str]:
    return [t.strip() for t in terms_str.split("\n") if t.strip()]


def build_duckdb_condition(terms: list[str], params: list, mode_all: bool = False) -> str:
    if not terms:
        return ""
    sub_clauses = []
    for term in terms:
        alt_term = term.replace(" ", "_")
        if alt_term != term:
            sub_clauses.append("(contains(item, ?) OR contains(item, ?))")
            params.extend([term, alt_term])
        else:
            sub_clauses.append("contains(item, ?)")
            params.append(term)
    joiner = " AND " if mode_all else " OR "
    return "(" + joiner.join(sub_clauses) + ")"


def search(
    terms_required: str,
    terms_removed: str = "\n",
    terms_negatives: str = "\n",
    terms_positives: str = "\n",
    require_all: bool = False,
) -> dict[str, list[set[str]]]:
    print(f"CPU_CORES={config.CPU_CORES} | ENCRYPT_INDEX={config.ENCRYPT_INDEX} | MERGE_FOLDER={config.MERGE_FOLDER_PARQUET}")

    aes_key, duckdb_key = (
        derive_keys(config.ENCRYPTION_PASSWORD, config.ENCRYPTION_SALT)
        if config.ENCRYPT_INDEX
        else (None, "")
    )
    verify_key_or_exit(aes_key)

    folder_parquets = get_indexed_parquets(aes_key, duckdb_key)
    if not folder_parquets:
        return {}

    req_list = parse_terms(terms_required)
    rem_list = parse_terms(terms_removed)
    neg_list = parse_terms(terms_negatives)
    pos_list = parse_terms(terms_positives)

    filter_params: list = []
    where_parts = []

    req_sql = build_duckdb_condition(req_list, filter_params, mode_all=require_all)
    if req_sql:
        where_parts.append(req_sql)

    rem_sql = build_duckdb_condition(rem_list, filter_params, mode_all=False)
    if rem_sql:
        where_parts.append(f"NOT {rem_sql}")

    neg_sql = build_duckdb_condition(neg_list, filter_params, mode_all=False)
    if neg_sql:
        pos_sql = build_duckdb_condition(pos_list, filter_params, mode_all=False)
        if pos_sql:
            where_parts.append(f"NOT ({neg_sql} AND NOT {pos_sql})")
        else:
            where_parts.append(f"NOT {neg_sql}")

    where_clause = " WHERE " + " AND ".join(where_parts) if where_parts else ""
    read_opts = ", encryption_config = {footer_key: 'idx_key'}" if config.ENCRYPT_INDEX else ""

    con = duckdb.connect(":memory:")
    configure_duckdb_session(con, config.ENCRYPT_INDEX, duckdb_key, threads=config.CPU_CORES)

    data: dict[str, list[set[str]]] = {}
    search_bar = tqdm(folder_parquets.items(), desc="Searching databases", unit="db")
    for folder_name, p_files in search_bar:
        search_bar.set_postfix_str(folder_name, refresh=False)
        file_list_str = [str(p) for p in p_files]
        query = f"SELECT DISTINCT source_file, item FROM read_parquet(?{read_opts}){where_clause}"
        rows = con.execute(query, [file_list_str, *filter_params]).fetchall()
        for source_file, item in rows:
            key_label = f"{folder_name}[{source_file}]"
            if key_label not in data:
                data[key_label] = [set()]
            data[key_label][0].add(item)

    con.close()
    return data


def build_terms_for_search_type(search_value: str, search_type: SearchType) -> str:
    match search_type:
        case SearchType.NAME:
            name_parts = search_value.split(" ")
            name_len = len(name_parts)
            match name_len:
                case 1:
                    terms_required = " ".join(name_parts) + "\n" + translit(" ".join(name_parts), "ru", True)
                case 2:
                    terms_required = " ".join(name_parts) + "\n" + " ".join(name_parts[::-1])
                    terms_required += "\n"
                    terms_required += (
                        translit(" ".join(name_parts), "ru", True)
                        + "\n"
                        + translit(" ".join(name_parts[::-1]), "ru", True)
                    )
                case 3:
                    terms_required = " ".join(name_parts) + "\n" + translit(" ".join(name_parts), "ru", True)
                case _:
                    terms_required = " ".join(name_parts)
            return terms_required.upper()
        case SearchType.PHONE:
            phone = search_value.replace("(", "").replace(")", "").replace("-", "").replace(" ", "").strip()
            if phone.startswith("+"):
                phone = phone[1:]
            return phone.upper()
        case SearchType.EMAIL:
            return search_value.replace(" ", "").strip().upper()
        case SearchType.BIRTHDAY:
            return search_value.replace(",", ".").replace(" ", "").strip().upper()
        case _:
            return search_value.upper()


def execute_and_report(search_value: str, search_type: SearchType) -> None:
    start_time = time.time()
    print(f'FIND "{search_value}" BY {search_type.name}')
    terms_required = build_terms_for_search_type(search_value, search_type)
    summary = f"search_type: {search_type.name}\nsearch_values: {terms_required.replace(chr(10), ', ')}\n\n"
    print(summary)
    result = search(terms_required)
    summary += "\n".join(
        f"{k}:\n{chr(10).join(chr(10).join(i) for i in v)}" for k, v in sorted(result.items()) if v != []
    )
    summary = f"{80 * '*'}\n{summary}\n{80 * '*'}\n"
    print(summary)
    with open(config.REPORT_FILE, "+a", -1, "utf-8") as f:
        f.write(summary)
    elapsed_time = time.time() - start_time
    print(f"Finished at: {elapsed_time:.3f} seconds")


def cli_list_databases() -> None:
    aes_key, _ = (
        derive_keys(config.ENCRYPTION_PASSWORD, config.ENCRYPTION_SALT)
        if config.ENCRYPT_INDEX
        else (None, "")
    )
    verify_key_or_exit(aes_key)
    manifest = load_manifest(get_manifest_path(), aes_key)
    if not manifest:
        print("No indexed databases or tables found.")
        return

    grouped: dict[str, list[dict]] = {}
    for meta in manifest.values():
        grouped.setdefault(meta["folder"], []).append(meta)

    print(f"Indexed databases ({len(grouped)}):")
    for folder, tables in sorted(grouped.items()):
        p_files = {t["parquet_file"] for t in tables}
        print(f"  DB: {folder} -> {', '.join(sorted(p_files))} ({len(tables)} source table(s))")
        for t in sorted(tables, key=lambda x: x.get("source_file", "")):
            size_mb = t.get("size", 0) / (1024 * 1024)
            enc_label = t.get("encoding", "unknown")
            print(f"    - {folder}[{t.get('source_file', 'unknown')}] ({size_mb:.2f} MB, {enc_label})")


def cli_add_source(target_path: Path, db_name: str | None) -> None:
    if not target_path.exists():
        print(f"[ERROR] Path does not exist: {target_path}")
        sys.exit(1)

    extra_sources: list[tuple[str, Path]] = []
    if target_path.is_file():
        folder_label = db_name or target_path.parent.name
        extra_sources.append((folder_label, target_path))
    else:
        folder_label = db_name or target_path.name
        for f in sorted(target_path.iterdir()):
            if f.is_file() and (not config.SUPPORTED_EXTENSIONS or f.suffix.lower() in config.SUPPORTED_EXTENSIONS):
                extra_sources.append((folder_label, f))

    if not extra_sources:
        print("[WARNING] No matching files found to add.")
        return

    sync_parquet_store(extra_sources=extra_sources)
    print(f"Successfully processed {len(extra_sources)} file(s) for database '{folder_label}'.")


def cli_remove_source(db_name: str, table_name: str | None = None) -> None:
    aes_key, duckdb_key = (
        derive_keys(config.ENCRYPTION_PASSWORD, config.ENCRYPTION_SALT)
        if config.ENCRYPT_INDEX
        else (None, "")
    )
    verify_key_or_exit(aes_key)
    manifest_path = get_manifest_path()
    manifest = load_manifest(manifest_path, aes_key)
    if not manifest:
        print("Index is empty.")
        return

    keys_to_delete = []
    affected_parquets = set()

    for resolved_path, meta in manifest.items():
        if meta.get("folder") == db_name:
            if table_name is None or meta.get("source_file") == table_name or Path(resolved_path).name == table_name:
                keys_to_delete.append(resolved_path)
                affected_parquets.add(meta["parquet_file"])

    if not keys_to_delete:
        target_desc = f"{db_name}[{table_name}]" if table_name else db_name
        print(f"[WARNING] Target '{target_desc}' not found in index.")
        return

    for k in keys_to_delete:
        del manifest[k]

    remaining_by_parquet: dict[str, set[str]] = {}
    for meta in manifest.values():
        remaining_by_parquet.setdefault(meta["parquet_file"], set()).add(meta.get("source_file", ""))

    ensure_crypto_extension()
    for p_name in affected_parquets:
        p_path = config.PARQUET_DIR / p_name
        if not p_path.exists():
            continue
        if p_name not in remaining_by_parquet or table_name is None:
            p_path.unlink(missing_ok=True)
            print(f"Removed Parquet file: {p_name}")
        else:
            tmp_out = p_path.with_suffix(p_path.suffix + ".tmp")
            con = duckdb.connect(":memory:")
            configure_duckdb_session(con, config.ENCRYPT_INDEX, duckdb_key, threads=config.CPU_CORES)
            enc_read = ", encryption_config = {footer_key: 'idx_key'}" if config.ENCRYPT_INDEX else ""
            enc_write = ", ENCRYPTION_CONFIG {footer_key: 'idx_key'}" if config.ENCRYPT_INDEX else ""
            con.execute(
                f"""
                COPY (
                    SELECT folder_name, source_file, item
                    FROM read_parquet(?{enc_read})
                    WHERE source_file != ?
                ) TO ? (
                    FORMAT PARQUET,
                    COMPRESSION {config.COMPRESSION_CODEC},
                    COMPRESSION_LEVEL {config.COMPRESSION_LEVEL}
                    {enc_write}
                )
                """,
                [str(p_path), table_name, str(tmp_out)],
            )
            con.close()
            shutil.move(str(tmp_out), str(p_path))
            print(f"Removed table '{db_name}[{table_name}]' from '{p_name}'.")

    save_manifest(manifest_path, manifest, aes_key)
    print(f"Removed {len(keys_to_delete)} entry(s) from manifest.")


def cli_rename_database(old_db: str, new_db: str, new_filename: str | None = None) -> None:
    aes_key, duckdb_key = (
        derive_keys(config.ENCRYPTION_PASSWORD, config.ENCRYPTION_SALT)
        if config.ENCRYPT_INDEX
        else (None, "")
    )
    verify_key_or_exit(aes_key)
    manifest_path = get_manifest_path()
    manifest = load_manifest(manifest_path, aes_key)
    if not manifest:
        print("Index is empty.")
        return

    parquet_ext = ".eparquet" if config.ENCRYPT_INDEX else ".parquet"
    target_parquet_name = new_filename or f"{new_db}{parquet_ext}"
    if not target_parquet_name.endswith(parquet_ext):
        target_parquet_name += parquet_ext

    matched_keys = [k for k, meta in manifest.items() if meta.get("folder") == old_db]
    if not matched_keys:
        print(f"[WARNING] Database '{old_db}' not found in index.")
        return

    old_parquets = {manifest[k]["parquet_file"] for k in matched_keys}
    if len(old_parquets) > 1:
        print("[ERROR] Multiple Parquet files belong to this DB. Merge them or rename with MERGE_FOLDER_PARQUET=True.")
        sys.exit(1)

    old_parquet_name = next(iter(old_parquets))
    old_path = config.PARQUET_DIR / old_parquet_name
    new_path = config.PARQUET_DIR / target_parquet_name

    if old_path != new_path and new_path.exists():
        print(f"[ERROR] Target file already exists: {new_path}")
        sys.exit(1)

    if old_path.exists():
        ensure_crypto_extension()
        tmp_out = new_path.with_suffix(new_path.suffix + ".tmp")
        con = duckdb.connect(":memory:")
        configure_duckdb_session(con, config.ENCRYPT_INDEX, duckdb_key, threads=config.CPU_CORES)
        enc_read = ", encryption_config = {footer_key: 'idx_key'}" if config.ENCRYPT_INDEX else ""
        enc_write = ", ENCRYPTION_CONFIG {footer_key: 'idx_key'}" if config.ENCRYPT_INDEX else ""
        con.execute(
            f"""
            COPY (
                SELECT ? AS folder_name, source_file, item
                FROM read_parquet(?{enc_read})
            ) TO ? (
                FORMAT PARQUET,
                COMPRESSION {config.COMPRESSION_CODEC},
                COMPRESSION_LEVEL {config.COMPRESSION_LEVEL}
                {enc_write}
            )
            """,
            [new_db, str(old_path), str(tmp_out)],
        )
        con.close()
        shutil.move(str(tmp_out), str(new_path))
        if old_path != new_path:
            old_path.unlink(missing_ok=True)

    for k in matched_keys:
        manifest[k]["folder"] = new_db
        manifest[k]["parquet_file"] = target_parquet_name

    save_manifest(manifest_path, manifest, aes_key)
    print(f"Renamed '{old_db}' ({old_parquet_name}) -> '{new_db}' ({target_parquet_name}).")


def cli_change_password(old_password: str | None = None, new_password: str | None = None) -> None:
    if not config.ENCRYPT_INDEX:
        print("[ERROR] ENCRYPT_INDEX is disabled in config.py.")
        sys.exit(1)

    current_pwd = old_password or getpass.getpass("Current encryption password: ")
    old_aes_key, old_duckdb_key = derive_keys(current_pwd, config.ENCRYPTION_SALT)
    verify_key_or_exit(old_aes_key)

    manifest_path = get_manifest_path(encrypted=True)
    manifest = load_manifest(manifest_path, old_aes_key)

    if new_password is None:
        new_pwd = getpass.getpass("New encryption password: ")
        confirm_pwd = getpass.getpass("Confirm new encryption password: ")
        if new_pwd != confirm_pwd:
            print("[ERROR] Passwords do not match.")
            sys.exit(1)
    else:
        new_pwd = new_password

    if not new_pwd:
        print("[ERROR] Password cannot be empty.")
        sys.exit(1)

    new_aes_key, new_duckdb_key = derive_keys(new_pwd, config.ENCRYPTION_SALT)
    ensure_crypto_extension()

    eparquet_files = sorted(config.PARQUET_DIR.glob("*.eparquet"))
    con = duckdb.connect(":memory:")
    configure_duckdb_session(con, True, old_duckdb_key, threads=config.CPU_CORES, key_name="old_key")
    con.execute(f"PRAGMA add_parquet_key('new_key', '{new_duckdb_key}')")

    rekey_bar = tqdm(eparquet_files, desc="Re-encrypting Parquet files", unit="file")
    for p_path in rekey_bar:
        rekey_bar.set_postfix_str(p_path.name, refresh=False)
        tmp_out = p_path.with_suffix(".eparquet.tmp")
        con.execute(
            f"""
            COPY (
                SELECT * FROM read_parquet(?, encryption_config = {{footer_key: 'old_key'}})
            ) TO ? (
                FORMAT PARQUET,
                COMPRESSION {config.COMPRESSION_CODEC},
                COMPRESSION_LEVEL {config.COMPRESSION_LEVEL},
                ENCRYPTION_CONFIG {{footer_key: 'new_key'}}
            )
            """,
            [str(p_path), str(tmp_out)],
        )
        shutil.move(str(tmp_out), str(p_path))

    con.close()
    save_manifest(manifest_path, manifest, new_aes_key)
    store_key_verifier(new_aes_key)
    print("Password updated successfully. Update DB_PARSER_KEY or config.ENCRYPTION_PASSWORD for future runs.")


def interactive_loop() -> None:
    search_prompt = f"Search type: {', '.join([f'{st.value} - by {st.name}' for st in SearchType])}"
    while True:
        print("\nSearch value (or 0 to sync index, q to quit): ")
        search_value = input().strip()
        if not search_value:
            continue
        if search_value.lower() in {"q", "quit", "exit"}:
            break
        if search_value == "0":
            start_time = time.time()
            sync_parquet_store()
            print(f"Sync finished at: {time.time() - start_time:.3f} seconds")
            continue

        print(search_prompt)
        try:
            search_type = SearchType(int(input().strip()))
        except Exception:
            print("[WARNING] Invalid search type selected.")
            continue

        if search_type == SearchType.SYNC:
            start_time = time.time()
            sync_parquet_store()
            print(f"Sync finished at: {time.time() - start_time:.3f} seconds")
            continue

        execute_and_report(search_value, search_type)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="High-speed Parquet/DuckDB search and index manager.")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("sync", help="Synchronize source folders with Parquet index")
    subparsers.add_parser("list", help="List all indexed databases and tables")

    search_p = subparsers.add_parser("search", help="Run a search query from CLI")
    search_p.add_argument("value", help="Value to search for")
    search_p.add_argument(
        "-t",
        "--type",
        choices=["name", "phone", "email", "birthday"],
        default="name",
        help="Search type (default: name)",
    )

    add_p = subparsers.add_parser("add", help="Add a new database folder or table file to the index")
    add_p.add_argument("path", type=Path, help="Path to file or folder to import")
    add_p.add_argument("--db", help="Target database name (defaults to folder name)")

    rem_p = subparsers.add_parser("remove", help="Remove a database or specific table from the index")
    rem_p.add_argument("--db", required=True, help="Database (folder) name to remove from")
    rem_p.add_argument("--table", help="Specific table filename (e.g. users.csv) to remove; omit to remove entire DB")

    ren_p = subparsers.add_parser("rename", help="Rename an indexed database and its Parquet file")
    ren_p.add_argument("--db", required=True, help="Current database name")
    ren_p.add_argument("--new-db", required=True, help="New database name")
    ren_p.add_argument("--file", help="Custom Parquet filename (defaults to <new-db>.eparquet)")

    pwd_p = subparsers.add_parser("passwd", help="Change encryption password and re-encrypt index")
    pwd_p.add_argument("--old-password", help="Current password (prompted if omitted)")
    pwd_p.add_argument("--new-password", help="New password (prompted if omitted)")

    return parser


if __name__ == "__main__":
    parser = build_arg_parser()
    args = parser.parse_args()

    match args.command:
        case "sync":
            t0 = time.time()
            sync_parquet_store()
            print(f"Sync finished at: {time.time() - t0:.3f} seconds")
        case "list":
            cli_list_databases()
        case "search":
            st = SearchType[args.type.upper()]
            execute_and_report(args.value, st)
        case "add":
            cli_add_source(args.path, args.db)
        case "remove":
            cli_remove_source(args.db, args.table)
        case "rename":
            cli_rename_database(args.db, args.new_db, args.file)
        case "passwd":
            cli_change_password(args.old_password, args.new_password)
        case _:
            interactive_loop()