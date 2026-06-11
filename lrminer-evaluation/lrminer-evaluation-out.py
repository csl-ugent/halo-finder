#!/usr/bin/env python3

import csv
from collections import defaultdict
import sys


assert len(sys.argv) == 2


category_map = dict()
counter = defaultdict(int)

with open('export-lrminer.csv', 'r') as categorisation:
    reader = csv.reader(categorisation)
    header = True
    for row in reader:
        if header:
            header = False
            continue
        file, field, category, *_ = row
        category_map[(file, field)] = category

#print(category_map)

with open(sys.argv[1], 'r') as bugfile:
    state = 'search_start'
    current_location = ''
    current_field = ''

    for line in bugfile:
        line = line.rstrip()
        #print(line)
        if state == 'search_start':
            if line == '======== DATA_RACE ========':
                state = 'search_location_field'
        elif state == 'search_location_field':
            if line.startswith('Access location: '):
                current_location = line[len('Access location: '):]
            elif line.startswith('Field: '):
                current_field = line[len('Field: '):].split()[0]

            if current_field and current_location:
                #print(category_map[(current_location, current_field)])
                counter[category_map[(current_location, current_field)]] += 1
                state = 'search_start'
                current_location = ''
                current_field = ''

for k, v in counter.items():
    print(f'{k}:\t{v}')

#fp:incorrect-rule
#fp:cleanup
#fp:safe
#fp:tool-bug
#fp:init
#fp:read_once
#fp:cant-change
#fp:barriers
#fp:comment
#fp:atomics
#fp:is-lock
#fp:recheck
#fp:tool-limitation
#fp:debug
#probable
#unknown:procfs
#unknown:sudden-rcu
#unknown:sysfs
#unknown:uninterpretable
#unknown:lack-knowledge

fps = [
    'fp:incorrect-rule',
    'fp:cleanup',
    'fp:safe',
    'fp:tool-bug',
    'fp:init',
    'fp:read_once',
    'fp:cant-change',
    'fp:barriers',
    'fp:comment',
    'fp:atomics',
    'fp:is-lock',
    'fp:recheck',
    'fp:tool-limitation',
    'fp:debug',
]
tps = [
    'probable',
]
unknowns = [
    'unknown:procfs',
    'unknown:sudden-rcu',
    'unknown:sysfs',
    'unknown:uninterpretable',
    'unknown:lack-knowledge',
]

fp_count = 0
tp_count = 0
unknown_count = 0
total_count = 0
for fp_cat in fps:
    fp_count += counter[fp_cat]
    total_count += counter[fp_cat]
for tp_cat in tps:
    tp_count += counter[tp_cat]
    total_count += counter[tp_cat]
for unknown_cat in unknowns:
    unknown_count += counter[unknown_cat]
    total_count += counter[unknown_cat]

fpr = 100 * fp_count / (fp_count + tp_count)
print(f'FPR: {fpr:.2f}%')

fp_count -= counter['fp:safe']
tp_count += counter['fp:safe']
fp_count -= counter['fp:debug']
tp_count += counter['fp:debug']
fpr = 100 * fp_count / (fp_count + tp_count)
print(f'FPR met fp:safe & fp:debug als probable: {fpr:.2f}%')
print(f'\tTotaal aantal reports (excl unknowns): {fp_count+tp_count}')
print(f'\tTotaal aantal reports (incl unknowns): {total_count}')

tp_count += counter['unknown:sysfs']
tp_count += counter['unknown:procfs']
fpr = 100 * fp_count / (fp_count + tp_count)
print(f'FPR met fp:safe & fp:debug & unknown:sysfs & unknown:procfs als probable: {fpr:.2f}%')
print(f'\tTotaal aantal reports (excl unknowns): {fp_count+tp_count}')
print(f'\tTotaal aantal reports (incl unknowns): {total_count}')

fp_count -= counter['fp:cleanup']
fp_count -= counter['fp:init']
fp_count -= counter['fp:tool-bug']
fpr = 100 * fp_count / (fp_count + tp_count)
print(f'FPR met fp:safe & fp:debug & unknown:sysfs & unknown:procfs als probable & geen fp:init & fp:cleanup & fp:tool-bug: {fpr:.2f}%')
