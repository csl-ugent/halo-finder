#!/usr/bin/env python3

import sys
import re
from collections import defaultdict, Counter


def cleanup_struct_name(name):
    return re.sub(r'\w+(\(\d+\))', '\\1', name)


assert len(sys.argv) == 2, 'Requires the file name as an argument'

categories = dict()


with open('bug-studies/categorisatie', 'r') as file:
    for line in file:
        data_array = re.split('\t+', line.rstrip('\n'))
        if len(data_array) != 2:
            continue
        struct, category = data_array
        struct = cleanup_struct_name(struct)
        categories[struct] = category.split('|')

# Split reports individually
current_report_buffer = []
reports = [current_report_buffer]
with open(sys.argv[1], 'r', errors='ignore') as file:
    lines = file.readlines()
    for i, line in enumerate(lines):
        if line.startswith('[F]%struct.') and 'Cover' in lines[i + 1]:
            reports.append(current_report_buffer)
            current_report_buffer = [line]
        else:
            current_report_buffer.append(line)
reports.append(current_report_buffer)
reports = reports[2:]
current_report_buffer = []

sorted_reports = []
for report in reports:
    struct = cleanup_struct_name(report[0].rstrip('\n'))[3:]
    if struct not in categories:
        sorted_reports.append([struct, report])

sorted_reports.sort(key=lambda k: k[0])

for _, report in sorted_reports:
    print(''.join(report))
