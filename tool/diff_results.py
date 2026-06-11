#!/usr/bin/env python3

import sys
import re
from collections import defaultdict


def cleanup_struct_name(name):
    return re.sub(r'\w+(\(\d+\))', '\\1', name)


assert len(sys.argv) == 4, 'Requires the file names as arguments and which set (probables, fp, unknown)'

categories = dict()


with open('bug-studies/categorisatie', 'r') as file:
    for line in file:
        data_array = re.split('\t+', line.rstrip('\n'))
        if len(data_array) != 2:
            continue
        struct, category = data_array
        struct = cleanup_struct_name(struct)
        categories[struct] = category.split('|')

categorisation_map = defaultdict(list)
counts = defaultdict(int)

def create_interested_set(filename, filter):
    result = set()
    with open(filename, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if line.startswith('[F]%struct.') and 'Cover' in lines[i + 1]:
                struct = cleanup_struct_name(line.rstrip('\n'))[3:]
                count_names = ['uncategorised'] if struct not in categories else categories[struct]
                for count_name in count_names:
                    counts[count_name] += 1
                    categorisation_map[count_name].append(struct)
                    if count_name.startswith(filter):
                        result.add(struct)
    return result


filter = sys.argv[3]
set1 = create_interested_set(sys.argv[1], filter)
set2 = create_interested_set(sys.argv[2], filter)

print(f'Unique to {sys.argv[1]}:')
for entry in set1 - set2:
    print(entry)
print()
print(f'Unique to {sys.argv[2]}:')
for entry in set2 - set1:
    print(entry)
