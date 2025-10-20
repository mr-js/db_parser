from pathlib import Path
from enum import Enum
import os
from urllib.parse import unquote
from transliterate import translit
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import time
import tomllib


DEMO = False
CPU_CORES = os.cpu_count()
class SearchType(Enum):
    NAME = 1
    PHONE = 2
    EMAIL = 3
    BIRTHDAY = 4


def request(filename, terms_required, terms_removed, terms_negatives, terms_positives):
    items = set(unquote(item) for item in Path(filename).read_text('utf-8').replace(',', ' ').upper().split('\n'))
    # items_filter_all = lambda items, terms: set(filter(lambda item: item if all(set(map(lambda term: (term in item or term.replace(' ', '_') in item), terms))) else None, items))
    items_filter_any = lambda items, terms: set(filter(lambda item: item if any(set(map(lambda term: (term in item or term.replace(' ', '_') in item), terms))) else None, items))
    terms_filter     = lambda terms: set(filter(None, terms.split('\n'))) if len(set(filter(None, terms.split('\n')))) != 0 else {}
    terms_required   = terms_filter(terms_required); terms_removed = terms_filter(terms_removed); terms_negatives = terms_filter(terms_negatives); terms_positives = terms_filter(terms_positives)
    items_required   = items_filter_any(items, terms_required) if len(terms_required) > 0 else set(items)
    items_removed    = items_filter_any(items, terms_removed)
    items_negatives  = items_filter_any(items, terms_negatives)
    items_positives  = items_filter_any(items, terms_positives)
    items_result     = (items_required - items_removed) - (items_negatives - items_positives)
    return items_result


def search(terms_required, terms_removed='\n', terms_negatives='\n', terms_positives='\n'):
    print(f'{CPU_CORES=}')
    settings = tomllib.loads(Path('db_parser.toml').read_text('utf-8'))
    root = os.path.expanduser(settings['COMMON']['DB_PATH'])
    data = {}
    for folder in [x for x in Path(root).iterdir() if x.is_dir()]:
        data[folder.name] = []
        print(f'CURRENT DB: {folder.name}')
        db_chunks_counter = 0 
        with ProcessPoolExecutor(CPU_CORES) as executor:
            futures = []
            for file in [x for x in folder.iterdir() if x.is_file()]:
                db_chunks_counter += 1
                if DEMO and db_chunks_counter > 3:
                    break
                filename = os.path.join(folder, file)
                future = executor.submit(request, filename, terms_required, terms_removed, terms_negatives, terms_positives)
                futures.append(future)
            for future in futures:
                result = future.result()
                if len(result) > 0:
                    data[folder.name].append(result)
    return data



if __name__ == '__main__':
    while(True):
        print('\nSearch value: ')
        search_value = input().strip()
        search_type = -1
        search_promt = f"Search type: {', '.join([f'{st.value} - by {st.name}' for st in SearchType])}"
        while (True):
            print(search_promt)
            try:
                search_type = SearchType(int(input().strip()))
            except:
                break
            start_time = time.time()
            print(f'FIND "{search_value}" BY {search_type.name}')
            match search_type:
                case SearchType.NAME:
                    name_parts = search_value.split(' ')
                    name_len = len(name_parts)
                    match name_len:
                        case 1:
                            terms_required = ' '.join(name_parts) + '\n' + translit(' '.join(name_parts), 'ru', True)
                        case 2:
                            terms_required = ' '.join(name_parts) + '\n' + ' '.join(name_parts[::-1])
                            terms_required += '\n'
                            terms_required += translit(' '.join(name_parts), 'ru', True) + '\n' + translit(' '.join(name_parts[::-1]), 'ru', True)
                        case 3:
                            terms_required = ' '.join(name_parts) + '\n' + translit(' '.join(name_parts), 'ru', True)
                        case _:
                            terms_required = ' '.join(name_parts)
                    terms_required = terms_required.upper()
                case SearchType.PHONE:
                    phone = search_value.replace('(', '').replace(')', '').replace('-', '').replace(' ', '').strip()
                    if phone.startswith('+'):
                        phone = phone[1:]
                    terms_required = phone.upper()
                case SearchType.EMAIL:
                    email = search_value.replace(' ', '').strip()
                    if '@' not in email and '.' not in email:
                        ...
                    terms_required = email.upper()
                case SearchType.BIRTHDAY:
                    birthday = search_value.replace(',', '.').replace(' ', '').strip()
                    if '.' not in birthday:
                        ...
                    terms_required = birthday.upper()
                case _:
                    continue
            summary = f'search_type: {search_type.name}\nsearch_values: {terms_required.replace(chr(10), ", ")}\n\n'
            print(summary)
            result = search(terms_required)
            summary += '\n'.join(f'{k}:\n{chr(10).join(chr(10).join(i) for i in v)}' for k, v in result.items() if v != [])
            summary = f'{80*"*"}\n{summary}\n{80*"*"}\n'
            print(summary)
            with open('report.txt', '+a', -1, 'utf-8') as f:
                f.write(summary)
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f'Finished at: {round(elapsed_time)} seconds')
