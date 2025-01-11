from pathlib import Path
import os
from urllib.parse import unquote
from transliterate import translit
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import time
import tomllib


DEMO = False
CPU_CORES = os.cpu_count()


def search(filename, terms_required, terms_removed, terms_negatives, terms_positives):
    items = set(unquote(item) for item in Path(filename).read_text('utf-8').replace(',', ' ').upper().split('\n'))
    items_filter_all = lambda items, terms: set(filter(lambda item: item if all(set(map(lambda term: (term in item or term.replace(' ', '_') in item), terms))) else None, items))
    items_filter_any = lambda items, terms: set(filter(lambda item: item if any(set(map(lambda term: (term in item or term.replace(' ', '_') in item), terms))) else None, items))
    terms_filter     = lambda terms: set(filter(None, terms.split('\n'))) if len(set(filter(None, terms.split('\n')))) != 0 else {}
    terms_required   = terms_filter(terms_required); terms_removed = terms_filter(terms_removed); terms_negatives = terms_filter(terms_negatives); terms_positives = terms_filter(terms_positives)
    items_required   = items_filter_any(items, terms_required) if len(terms_required) > 0 else set(items)
    items_removed    = items_filter_any(items, terms_removed)
    items_negatives  = items_filter_any(items, terms_negatives)
    items_positives  = items_filter_any(items, terms_positives)
    items_result     = (items_required - items_removed) - (items_negatives - items_positives)
    return items_result


def request(terms_required, terms_removed='\n', terms_negatives='\n', terms_positives='\n'):
    summary = f'terms_required:\n{terms_required}\nterms_removed:\n{terms_removed}\nterms_negatives:\n{terms_negatives}\nterms_positives:\n{terms_positives}\n\n'
    print(summary)
    print(f'{CPU_CORES=}')
    data = tomllib.loads(Path('db_parser.toml').read_text('utf-8'))
    root = data['COMMON']['DB_PATH']
    for folder in [x for x in Path(root).iterdir() if x.is_dir()]:
        data = []
        print(f'CURRENT DB: {folder}')
        db_chunks_counter = 0 
        with ProcessPoolExecutor(CPU_CORES) as executor:
            futures = []
            for file in [x for x in Path(root).joinpath(folder).iterdir() if x.is_file()]:
                db_chunks_counter += 1
                if DEMO and db_chunks_counter > 3:
                    break
                filename = os.path.join(root, folder, file)
                future = executor.submit(search, filename, terms_required, terms_removed, terms_negatives, terms_positives)
                futures.append(future)
            for future in futures:
                result = future.result()
                if len(result) > 0:
                    summary += f'{result}\n'
    Path('report.txt').write_text(summary, 'utf-8')


def find_by_name(name):
    print(f'FIND BY NAME: {name}')
    name_parts = name.split(' ')
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
    request(terms_required)


def find_by_phone(phone):
    print(f'FIND BY PHONE: {phone}')
    phone_number = phone.replace('(', '').replace(')', '').replace('-', '').replace(' ', '').strip()
    if phone_number.startswith('+'):
        phone_number = phone_number[1:]
    terms_required = phone_number.upper()
    request(terms_required)


def find_by_email(email):
    print(f'FIND BY EMAIL: {email}')
    email = email.replace(' ', '').strip()
    if '@' not in email and '.' not in email:
        ...
    terms_required = email.upper()
    request(terms_required)


def find_by_birthday(birthday):
    print(f'FIND BY BIRTHDAY: {birthday}')
    phone_number = birthday.replace(',', '.').replace(' ', '').strip()
    if '.' not in birthday:
        ...
    terms_required = birthday.upper()
    request(terms_required)


if __name__ == '__main__':
    while(True):
        print('\nSearch value: ')
        search_value = input()
        search_type = -1
        while (search_type < 0 or search_type > 4):
            print('Search type: 1 - by Name, 2 - by Phone, 3 - by Email, 4 - by Birthday')
            search_type = int(input())
            start_time = time.time()
            match search_type:
                case 1:
                    find_by_name(search_value)
                case 2:
                    find_by_phone(search_value)
                case 3:
                    find_by_email(search_value)
                case 4:
                    find_by_birthday(search_value)
                case _:
                    ...
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f'Finished at: {round(elapsed_time)} seconds')
