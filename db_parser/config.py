import os
from pathlib import Path

DEMO = False
CPU_CORES = os.cpu_count() or 4

DB_PATH = Path(os.path.expanduser("~/databases"))
PARQUET_DIR = Path("parquet_store")
REPORT_FILE = Path("report.txt")

MERGE_FOLDER_PARQUET = True
STREAM_CHUNK_LINES = 250_000
TEXT_CHECK_BYTES = 8192
MAX_CHAOS_THRESHOLD = 0.5

COMPRESSION_CODEC = "ZSTD"
COMPRESSION_LEVEL = 9

ENCRYPT_INDEX = True
ENCRYPTION_PASSWORD = os.environ.get("DB_PARSER_KEY", "password")
ENCRYPTION_SALT = b"db_parser_static_salt_v1"
KDF_ITERATIONS = 600_000

SUPPORTED_EXTENSIONS = {".csv", ".tsv", ".txt", ".json", ".jsonl"}