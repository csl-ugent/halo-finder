#!/usr/bin/env python3

import sys
import re
from collections import defaultdict, Counter


def cleanup_struct_name(name):
    return re.sub(r'\w+(\(\d+\))', '\\1', name)


#assert len(sys.argv) == 2, 'Requires the file name as an argument'

categories = dict()
probable_set_complement = set()


with open('bug-studies/categorisatie', 'r') as file:
    for line in file:
        data_array = re.split('\t+', line.rstrip('\n'))
        if len(data_array) != 2:
            continue
        struct, category = data_array
        struct = cleanup_struct_name(struct)
        categories[struct] = category.split('|')
        if any('probable' in category for category in categories[struct]):
            probable_set_complement.add(struct)

#print(categories)

categorisation_map = defaultdict(list)
counts = defaultdict(int)

counts_super_categories = {'fp': 0, 'unknown': 0, 'uncategorised': 0, 'probable': 0}
total_count = 0


# Split reports individually
def read_report(file):
    current_report_buffer = []
    reports = [current_report_buffer]
    with open(file, 'r', errors='ignore') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if line.startswith('[F]%struct.') and 'Cover' in lines[i + 1]:
                reports.append(current_report_buffer)
                current_report_buffer = [line]
            else:
                current_report_buffer.append(line)
    reports.append(current_report_buffer)
    reports = reports[2:]
    return reports

reports = read_report(sys.argv[1])

### DIFF CODE START
#reports_base = read_report(sys.argv[2])
#reports_base_set = set()
#for report in reports_base:
#    struct = cleanup_struct_name(report[0].rstrip('\n'))[3:]
#    reports_base_set.add(struct)
#print(len(reports_base_set))
### DIFF CODE END

# Loop over reports and generate stats
unknown_set = set()
probable_set = set()
fp_set = set()
tags = dict()
for report in reports:
    struct = cleanup_struct_name(report[0].rstrip('\n'))[3:]

    ### DIFF CODE START
    #if struct in reports_base_set:
    #    continue
    ### DIFF CODE END

    count_names = ['uncategorised'] if struct not in categories else categories[struct]
    for count_index, count_name in enumerate(count_names):
        if count_index == 0:
            if count_name.startswith('fp'):
                counts_super_categories['fp'] += 1
            elif count_name.startswith('unknown'):
                counts_super_categories['unknown'] += 1
            elif count_name.startswith('probable'):
                counts_super_categories['probable'] += 1
            elif count_name.startswith('uncategorised'):
                counts_super_categories['uncategorised'] += 1
                if struct not in tags:
                    tags[struct] = []
                if any(('stop' in line) or ('suspend' in line) or ('cleanup' in line) or ('free' in line) or ('deinit' in line) for line in report):
                    tags[struct].append('cleanup')
                if any(('init' in line) or ('alloc' in line) or ('resume' in line) or ('setup' in line) for line in report):
                    tags[struct].append('init')
                if any('drivers' in line for line in report):
                    tags[struct].append('driver')

            if not count_name.startswith('ignore'):
                total_count += 1

        counts[count_name] += 1
        categorisation_map[count_name].append(struct)
        if count_name.startswith('probable'):
            if struct in probable_set_complement:
                probable_set_complement.remove(struct)
            probable_set.add(report[0])
        elif count_name.startswith('unknown'):
            unknown_set.add(report[0])
        elif count_name.startswith('fp'):
            fp_set.add(report[0])

def figure_out_main_folders(filter_set):
    # Figure out main folder of reports
    sources = set()
    for report in reports:
        if report[0] not in filter_set:
            continue
        for line in report:
            # Must be a path entry
            if ' => ' not in line:
                continue
            parts = line.split(' => ')
            source = parts[-1].rstrip()
            sources.add(source)

    # Aggregate sources to folders
    folder_counter = Counter()
    for source in sources:
        #print(source)
        filename = source.split(':')[0]
        folders = filename.split('/')
        main_folder = folders[0] if folders[0] != '.' else folders[2] # either main folder or part in include
        #print(main_folder)
        folder_counter[main_folder] += 1

    return folder_counter

print('Unknown cases distribution:', figure_out_main_folders(unknown_set))
print('Fp cases distribution:', figure_out_main_folders(fp_set))
print('Probable cases distribution:', figure_out_main_folders(probable_set))

print('------------------------------------------------')
for name, list in categorisation_map.items():
    print(f'{name} {len(list)}')

print('------------------------------------------------')

print(counts_super_categories)
print(f'\t{counts_super_categories["fp"] / total_count * 100} fp rate')
print(f'\t{counts_super_categories["unknown"] / total_count * 100} unknown rate')
print(f'\t{counts_super_categories["probable"] / total_count * 100} probable rate')
print(f'\t{counts_super_categories["uncategorised"] / total_count * 100} uncategorised rate')
print(f'\tWithout uncategorised and unknown: {counts_super_categories["fp"] / (counts_super_categories["fp"] + counts_super_categories["probable"]) * 100} fp rate')

for name, list in categorisation_map.items():
    print('------------------------------------------------')
    print(f'{name} ({len(list)}):')
    #print('\n'.join(list))
    for entry in list:
        if entry in tags:
            print(f'[{",".join(tags[entry])}?]', end='')
        print(entry)
    print()

print('------------------------------------------------')
print('Not found probable list:')

print('\n'.join(probable_set_complement))
