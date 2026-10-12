"""Selects samples from the APT groups best separated by EMBER similarity, skipping near-duplicates.
Usage: python3 experiments/llm_report_analysis/select_batch.py > experiments/llm_report_analysis/batch100.csv
"""
import argparse
import csv
import os
import random
import sys
from collections import defaultdict

parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
parser.add_argument("--results", default="experiments/sample_analysis/results")
parser.add_argument("--workdir", default="workdir")
parser.add_argument("--total", type=int, default=100, help="Samples to select (default: 100)")
parser.add_argument("--per-group", type=int, default=20, help="Maximum samples per group (default: 20)")
parser.add_argument("--max-similarity", type=float, default=0.99, help="Near-duplicate threshold (default: 0.99)")
parser.add_argument("--seed", type=int, default=0)
args = parser.parse_args()

within, cross_sum, cross_pairs = {}, defaultdict(float), defaultdict(int)
with open(os.path.join(args.results, "sample_similarity_groups.csv")) as f:
    for row in csv.DictReader(f):
        a, b, pairs, mean = row["apt_group_a"], row["apt_group_b"], int(row["pairs"]), float(row["mean_similarity"])
        if a == b:
            within[a] = mean
        else:
            for g in (a, b):
                cross_sum[g] += mean * pairs
                cross_pairs[g] += pairs
gap = {g: within[g] - cross_sum[g] / cross_pairs[g] for g in within}
groups = sorted(gap, key=gap.get, reverse=True)
print(f"# groups by gap: {', '.join(f'{g} ({gap[g]:+.3f})' for g in groups)}", file=sys.stderr)

members, similarity = defaultdict(set), {}
with open(os.path.join(args.results, "sample_similarity.csv")) as f:
    for row in csv.DictReader(f):
        a, b = row["md5_a"], row["md5_b"]
        members[row["apt_group_a"]].add(a)
        members[row["apt_group_b"]].add(b)
        if row["apt_group_a"] == row["apt_group_b"]:
            similarity[frozenset((a, b))] = float(row["similarity"])

rng = random.Random(args.seed)
writer = csv.writer(sys.stdout)
writer.writerow(["md5", "apt_group"])
total = 0
for g in groups:
    if total == args.total:
        break
    candidates = sorted(m for m in members[g]
                        if os.path.exists(os.path.join(args.workdir, f"{m}.cgcompressed.pickle")))
    rng.shuffle(candidates)
    selected = []
    for m in candidates:
        if all(similarity.get(frozenset((m, s)), 0.0) < args.max_similarity for s in selected):
            selected.append(m)
        if len(selected) == min(args.per_group, args.total - total):
            break
    total += len(selected)
    print(f"# {g}: {len(selected)} selected of {len(candidates)} with a dump", file=sys.stderr)
    for m in selected:
        writer.writerow([m, g])
