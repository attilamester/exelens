import argparse
import csv
import glob
import json
import os
import re
import sys
import time
from pathlib import Path

import numpy as np

REPORT_PATTERN = re.compile(r"exelens_report_([0-9a-f]{32})\.txt$")
RESULTS_DIR = Path(__file__).resolve().parent / "results"
EMBEDDING_BATCH_SIZE = 100
SAMPLE_SIMILARITY = Path(__file__).resolve().parent.parent / "sample_analysis" / "results" / "sample_similarity.csv"


def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def load_reports(reports_dir):
    """{md5: text} of the reports under reports_dir."""
    reports = {}
    for path in sorted(glob.glob(os.path.join(reports_dir, "**", "exelens_report_*.txt"), recursive=True)):
        match = REPORT_PATTERN.search(os.path.basename(path))
        if match:
            with open(path, encoding="utf-8") as f:
                reports[match.group(1)] = f.read()
    return reports


def json_values(value):
    """All values of a JSON report, recursively."""
    if isinstance(value, dict):
        return [v for item in value.values() for v in json_values(item)]
    if isinstance(value, list):
        return [v for item in value for v in json_values(item)]
    return [] if value is None else [str(value)]


def report_text(raw):
    """The report's JSON values (keys are the same in all reports), else its raw text."""
    from exelens.core.grounding import parse_report

    report = parse_report(raw)
    return raw if report is None else "\n".join(json_values(report))


def jaccard_similarity_matrix(texts):
    token_sets = [set(re.findall(r"[a-z0-9_]+", text.lower())) for text in texts]
    n = len(token_sets)
    similarity = np.eye(n)
    for i in range(n):
        for j in range(i + 1, n):
            union = token_sets[i] | token_sets[j]
            similarity[i, j] = similarity[j, i] = len(token_sets[i] & token_sets[j]) / len(union) if union else 0.0
    return similarity


def embedding_similarity_matrix(texts, model, pause):
    from exelens.core.llm import LlmClient

    client = LlmClient().client
    embeddings = []
    for start in range(0, len(texts), EMBEDDING_BATCH_SIZE):
        if start:
            time.sleep(pause)
        response = client.embeddings.create(model=model, input=texts[start:start + EMBEDDING_BATCH_SIZE])
        embeddings += [item.embedding for item in response.data]
    x = np.array(embeddings, dtype=np.float64)
    x = x / np.linalg.norm(x, axis=1, keepdims=True)
    return x @ x.T


def load_sample_similarity(path, md5s):
    """{frozenset((md5_a, md5_b)): (similarity, same_apt_group)} of the pairs with two reports."""
    pairs = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["md5_a"] in md5s and row["md5_b"] in md5s:
                pairs[frozenset((row["md5_a"], row["md5_b"]))] = (float(row["similarity"]),
                                                                  row["apt_group_a"] == row["apt_group_b"])
    return pairs


def average_ranks(values):
    _, inverse, counts = np.unique(values, return_inverse=True, return_counts=True)
    return (np.cumsum(counts) - (counts - 1) / 2)[inverse]


def correlate(x, y):
    x, y = np.array(x), np.array(y)
    if len(x) < 3 or x.std() == 0 or y.std() == 0:
        return {"pairs": len(x), "pearson": None, "spearman": None}
    return {
        "pairs": len(x),
        "pearson": float(np.corrcoef(x, y)[0, 1]),
        "spearman": float(np.corrcoef(average_ranks(x), average_ranks(y))[0, 1]),
    }


def main():
    parser = argparse.ArgumentParser(prog="report_analysis",
                                     description="Report-report similarity and its correlation with sample similarity.")
    parser.add_argument("--reports", default=str(RESULTS_DIR / "reports"),
                        help="Directory searched for exelens_report_<md5>.txt")
    parser.add_argument("--sample-similarity", default=str(SAMPLE_SIMILARITY),
                        help="Pairwise CSV from `python -m sample_analysis`")
    parser.add_argument("--method", choices=["jaccard", "embedding"], default="jaccard")
    parser.add_argument("--embedding-model", default="gemini-embedding-2",
                        help="Embedding model for --method embedding")
    parser.add_argument("--embedding-pause", type=float, default=60,
                        help=f"Seconds between batches of {EMBEDDING_BATCH_SIZE} embeddings (default: 60, for Gemini's "
                             "free tier limit of 100 embedded texts per minute; 0 on a paid tier)")
    parser.add_argument("--out", default=str(RESULTS_DIR), help="Output directory")
    args = parser.parse_args()

    reports = load_reports(args.reports)
    if len(reports) < 2:
        print(f"Error: need at least 2 reports in '{args.reports}', found {len(reports)}.", file=sys.stderr)
        return 1

    md5s = list(reports)
    texts = [report_text(reports[md5]) for md5 in md5s]
    if args.method == "jaccard":
        similarity = jaccard_similarity_matrix(texts)
    else:
        similarity = embedding_similarity_matrix(texts, args.embedding_model, args.embedding_pause)

    rows = [(md5s[i], md5s[j], round(float(similarity[i, j]), 6))
            for i in range(len(md5s)) for j in range(i + 1, len(md5s))]
    report_csv = os.path.join(args.out, f"report_similarity_{args.method}.csv")
    write_csv(report_csv, ["md5_a", "md5_b", "similarity"], rows)
    print(f"Wrote {len(rows)} report pairs to {report_csv}")

    report_similarity = {frozenset((a, b)): value for a, b, value in rows}
    sample_similarity = load_sample_similarity(args.sample_similarity, set(md5s))
    result = {"method": args.method}
    for name, keep in [("all", lambda same: True), ("within_group", lambda same: same),
                       ("cross_group", lambda same: not same)]:
        pairs = [p for p, (_, same) in sample_similarity.items() if keep(same) and p in report_similarity]
        result[name] = correlate([sample_similarity[p][0] for p in pairs], [report_similarity[p] for p in pairs])
    result_path = os.path.join(args.out, f"correlation_{args.method}.json")
    with open(result_path, "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.splitext(result_path)[0] + ".md", "w") as f:
        f.write(f"# Report ({args.method}) vs. sample (EMBER) similarity correlation\n\n"
                "| Pair type | Pairs | Pearson | Spearman |\n|---|---|---|---|\n")
        for name in ["all", "within_group", "cross_group"]:
            r = result[name]
            f.write(f"| {name.replace('_', ' ')} | {r['pairs']} | "
                    + " | ".join(f"{r[k]:+.3f}" if r[k] is not None else "n/a" for k in ["pearson", "spearman"])
                    + " |\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
