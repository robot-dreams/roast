from collections import defaultdict

import csv
import os

subdir = 'summarized'

# For each (t, n, level) configuration, generate an output .dat file
# that can be directly used by a LaTeX plot.
def generate_data(t, n):
    all_levels = set()

    # key is (attacker_level, f)
    counts = defaultdict(int)
    sums = defaultdict(float)

    def handle_row(row):
        f = int(row[2])
        level = row[3].split('.')[1].lower()
        elapsed = float(row[4])
        all_levels.add(level)
        key = (level, f)
        counts[key] += 1
        sums[key] += elapsed

    with open(f'roast_{t}_{n}.csv') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader, None)
        for row in reader:
            handle_row(row)

    try:
        os.mkdir(subdir)
    except FileExistsError:
        pass
    for level in all_levels:
        filename = f'{subdir}/benchmark-{level}-{t}-{n}.dat'
        with open(filename, 'w') as outfile:
            print('frac\telapsed', file=outfile)
            for f in range(0, n - t + 1):
                key = (level, f)
                avg = sums[key] / counts[key]
                print(f'{f / (n - t):.6f}\t{avg:.12f}', file=outfile)

if __name__ == '__main__':
    for t, n in [(3, 5), (11, 15), (34, 50), (67, 100)]:
        generate_data(t, n)
