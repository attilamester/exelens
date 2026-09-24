import argparse
import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import numpy as np

from sample_analysis.features import PEFeatureExtractor

# Samples unzipped by dataset/APTMalware-analysis/unzip_samples.py: samples/<APT group>/<sha256>
DEFAULT_SAMPLES = Path("dataset/APTMalware/samples")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def find_samples(paths):
    files = (f for p in paths for f in (p.rglob("*") if p.is_dir() else [p]))
    return sorted(f for f in files if f.is_file() and SHA256_RE.match(f.name))


def cosine_similarity_matrix(vectors):
    # EMBER features have very different scales (timestamps vs. histogram ratios),
    # so standardize each feature across the samples before comparing them.
    x = np.vstack(vectors).astype(np.float64)
    std = x.std(axis=0)
    x = (x - x.mean(axis=0)) / np.where(std == 0, 1, std)
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    x = x / np.where(norms == 0, 1, norms)
    return x @ x.T


def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def group_similarity(similarity, groups):
    """Pair count and mean similarity for every APT group pair (a group with itself = within-group pairs)."""
    names = sorted(set(groups))
    indices = {name: np.array([i for i, g in enumerate(groups) if g == name]) for name in names}
    rows = []
    for a_pos, a in enumerate(names):
        for b in names[a_pos:]:
            block = similarity[np.ix_(indices[a], indices[b])]
            values = block[np.triu_indices(len(indices[a]), k=1)] if a == b else block.ravel()
            rows.append((a, b, len(values), round(float(values.mean()), 6) if len(values) else ""))
    return rows


def permutation_test(similarity, groups, permutations, seed=0):
    """Is within-APT-group similarity higher than chance? Shuffles the group labels (group sizes kept)
    and compares, per shuffle, the within-group mean similarity against the observed one."""
    names = sorted(set(groups))
    labels = np.array([names.index(g) for g in groups])
    one_hot_eye, diagonal = np.eye(len(names)), np.diag(similarity)
    sizes = np.bincount(labels, minlength=len(names))
    within_pairs = sizes * (sizes - 1) / 2
    total_pairs = len(labels) * (len(labels) - 1) / 2
    total_sum = (similarity.sum() - diagonal.sum()) / 2

    def statistics(lbl):
        one_hot = one_hot_eye[lbl]
        block_sums = np.diag(one_hot.T @ similarity @ one_hot)
        within_sums = (block_sums - np.bincount(lbl, weights=diagonal, minlength=len(names))) / 2
        within_mean = within_sums.sum() / within_pairs.sum()
        cross_mean = (total_sum - within_sums.sum()) / (total_pairs - within_pairs.sum())
        return within_mean - cross_mean, within_sums / np.where(within_pairs == 0, 1, within_pairs)

    observed_gap, observed_groups = statistics(labels)
    rng = np.random.default_rng(seed)
    null = [statistics(rng.permutation(labels)) for _ in range(permutations)]
    null_gaps = np.array([gap for gap, _ in null])
    null_groups = np.array([group_means for _, group_means in null])

    def p_value(observed, null_values):
        return (1 + int((null_values >= observed).sum())) / (1 + permutations)

    return {
        "permutations": permutations,
        "seed": seed,
        "within_minus_cross": {"observed": float(observed_gap), "null_mean": float(null_gaps.mean()),
                               "null_max": float(null_gaps.max()), "p_value": p_value(observed_gap, null_gaps)},
        "within_group_mean": {name: {"samples": int(sizes[k]), "observed": float(observed_groups[k]),
                                     "null_mean": float(null_groups[:, k].mean()),
                                     "null_max": float(null_groups[:, k].max()),
                                     "p_value": p_value(observed_groups[k], null_groups[:, k])}
                              for k, name in enumerate(names) if sizes[k] > 1},
    }


def markdown_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def write_markdown(path, n_samples, group_rows, permutation=None):
    """Human-readable summary of the group comparison (and permutation test) as markdown tables."""
    within = [(pairs, mean) for a, b, pairs, mean in group_rows if a == b and pairs]
    cross = [(pairs, mean) for a, b, pairs, mean in group_rows if a != b and pairs]

    def pooled(rows):
        pairs = sum(p for p, _ in rows)
        return pairs, f"{sum(p * m for p, m in rows) / pairs:+.3f}" if pairs else ""

    buffer = "# Sample similarity (EMBER cosine)\n\n"
    buffer += f"{n_samples} samples, {n_samples * (n_samples - 1) // 2} pairs.\n\n## Within vs. cross APT group\n\n"
    buffer += markdown_table(["Pair type", "Pairs", "Mean similarity"],
                             [("within group", *pooled(within)), ("cross group", *pooled(cross))])
    if permutation:
        gap = permutation["within_minus_cross"]
        buffer += (f"\nPermutation test ({permutation['permutations']} random APT-group label shuffles, "
                   f"seed {permutation['seed']}): within − cross = {gap['observed']:+.3f}, "
                   f"random labels {gap['null_mean']:+.3f} (max {gap['null_max']:+.3f}), p = {gap['p_value']:.4f}\n")

    buffer += "\n## Within-group similarity per APT group\n\n"
    means = {(a, b): mean for a, b, _, mean in group_rows}
    names = sorted({a for a, _, _, _ in group_rows})
    per_group = sorted(((a, pairs, mean) for a, b, pairs, mean in group_rows if a == b and pairs),
                       key=lambda row: -row[2])
    if permutation:
        tests = permutation["within_group_mean"]
        buffer += markdown_table(
            ["APT group", "Samples", "Pairs", "Mean similarity", "Random-label mean", "Random-label max", "p-value"],
            [(name, tests[name]["samples"], pairs, f"{mean:+.3f}", f"{tests[name]['null_mean']:+.3f}",
              f"{tests[name]['null_max']:+.3f}", f"{tests[name]['p_value']:.4f}") for name, pairs, mean in per_group])
    else:
        buffer += markdown_table(["APT group", "Pairs", "Mean similarity"],
                                 [(name, pairs, f"{mean:+.3f}") for name, pairs, mean in per_group])

    buffer += "\n## Within-group vs. other APT groups\n\n"
    rows = []
    for name, pairs, mean in per_group:
        others = [(b if a == name else a, p, m) for a, b, p, m in group_rows if a != b and name in (a, b) and p]
        other_pairs = sum(p for _, p, _ in others)
        other_mean = sum(p * m for _, p, m in others) / other_pairs
        closest, _, closest_mean = max(others, key=lambda row: row[2])
        rows.append((name, mean, other_mean, closest, closest_mean))
    buffer += markdown_table(
        ["APT group", "Within group", "Against all other groups", "Gap", "Most similar other group"],
        [(name, f"{mean:+.3f}", f"{other_mean:+.3f}", f"{mean - other_mean:+.3f}", f"{closest} ({closest_mean:+.3f})")
         for name, mean, other_mean, closest, closest_mean in sorted(rows, key=lambda row: row[2] - row[1])])

    buffer += "\n## Mean similarity between APT groups\n\n"
    buffer += markdown_table(["APT group"] + names,
                             [[a] + [f"{means.get((a, b), means.get((b, a))):+.3f}"
                                     if means.get((a, b), means.get((b, a))) != "" else "" for b in names]
                              for a in names])
    with open(path, "w") as f:
        f.write(buffer)


def sample_similarity(sample_paths, out_path, permutations=0):
    """Pairwise cosine similarity of EMBER feature vectors, keyed by md5 (as exelens names its reports).
    The APT group of a sample is its folder name (samples/<APT group>/<sha256>)."""
    extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    md5s, groups, vectors = [], [], []
    for path in sample_paths:
        bytez = path.read_bytes()
        md5s.append(hashlib.md5(bytez).hexdigest())
        groups.append(path.parent.name)
        vectors.append(extractor.feature_vector(bytez))

    if len(md5s) < 2:
        print(f"Error: need at least 2 unzipped samples, found {len(md5s)}.", file=sys.stderr)
        return 1

    similarity = cosine_similarity_matrix(vectors)
    n = len(md5s)
    write_csv(out_path, ["md5_a", "apt_group_a", "md5_b", "apt_group_b", "similarity"],
              ((md5s[i], groups[i], md5s[j], groups[j], round(float(similarity[i, j]), 6))
               for i in range(n) for j in range(i + 1, n)))
    print(f"Wrote {n * (n - 1) // 2} sample pairs of {n} samples to {out_path}")

    groups_path = os.path.splitext(out_path)[0] + "_groups.csv"
    group_rows = group_similarity(similarity, groups)
    write_csv(groups_path, ["apt_group_a", "apt_group_b", "pairs", "mean_similarity"], group_rows)
    print(f"Wrote APT group comparison to {groups_path}")

    result = None
    if permutations:
        result = permutation_test(similarity, groups, permutations)
        permutation_path = os.path.splitext(out_path)[0] + "_permutation.json"
        with open(permutation_path, "w") as f:
            json.dump(result, f, indent=2)
        print(json.dumps(result["within_minus_cross"], indent=2))
        print(f"Wrote permutation test to {permutation_path}")

    markdown_path = os.path.splitext(out_path)[0] + ".md"
    write_markdown(markdown_path, n, group_rows, result)
    print(f"Wrote markdown summary to {markdown_path}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="sample_analysis",
                                     description="EMBER-based sample-sample similarity of unzipped samples.")
    parser.add_argument("paths", nargs="*", type=Path, default=[DEFAULT_SAMPLES],
                        help=f"unzipped sample files and/or folders searched recursively (default: {DEFAULT_SAMPLES})")
    parser.add_argument("--out", default=str(RESULTS_DIR / "sample_similarity.csv"),
                        help="Output CSV; the groups CSV, permutation JSON and markdown summary are written next to it")
    parser.add_argument("--permutations", type=int, default=1000,
                        help="Random APT-group label shuffles for the within-group permutation test (0 = skip)")
    args = parser.parse_args()
    return sample_similarity(find_samples(args.paths), args.out, args.permutations)


if __name__ == "__main__":
    sys.exit(main())
