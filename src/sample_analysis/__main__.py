import argparse
import csv
import hashlib
import os
import re
import sys
from pathlib import Path

import numpy as np

from sample_analysis.features import PEFeatureExtractor

# Samples unzipped by dataset/APTMalware-analysis/unzip_samples.py: samples/<APT group>/<sha256>
DEFAULT_SAMPLES = Path("dataset/APTMalware/samples")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def sample_similarity(sample_paths, out_path):
    """Pairwise cosine similarity of EMBER feature vectors, keyed by md5 (as exelens names its reports)."""
    extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    md5s, vectors = [], []
    for path in sample_paths:
        bytez = path.read_bytes()
        md5s.append(hashlib.md5(bytez).hexdigest())
        vectors.append(extractor.feature_vector(bytez))

    if len(md5s) < 2:
        print(f"Error: need at least 2 unzipped samples, found {len(md5s)}.", file=sys.stderr)
        return 1

    similarity = cosine_similarity_matrix(vectors)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["md5_a", "md5_b", "similarity"])
        writer.writerows((md5s[i], md5s[j], round(float(similarity[i, j]), 6))
                         for i in range(len(md5s)) for j in range(i + 1, len(md5s)))
    print(f"Wrote {len(md5s) * (len(md5s) - 1) // 2} sample pairs of {len(md5s)} samples to {out_path}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="sample_analysis",
                                     description="EMBER-based sample-sample similarity of unzipped samples.")
    parser.add_argument("paths", nargs="*", type=Path, default=[DEFAULT_SAMPLES],
                        help=f"unzipped sample files and/or folders searched recursively (default: {DEFAULT_SAMPLES})")
    parser.add_argument("--out", default="results/sample_similarity.csv", help="Output CSV")
    args = parser.parse_args()
    return sample_similarity(find_samples(args.paths), args.out)


if __name__ == "__main__":
    sys.exit(main())
