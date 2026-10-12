import argparse
import glob
import json
import os
import re
from typing import Optional


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def parse_report(report_text: str) -> Optional[dict]:
    """The report's JSON object, or None. Parses only the first object: some reports end with a stray "}"."""
    try:
        report, _ = json.JSONDecoder().raw_decode(report_text.strip())
    except ValueError:
        return None
    return report if isinstance(report, dict) else None


def check_grounding(report_text: str, context: str) -> Optional[dict]:
    """Which cited IOC values and function names do not appear in the report's context (None if not JSON)."""
    report = parse_report(report_text)
    try:
        cited = [v["value"] for ioc in report.get("ioc", []) for v in ioc.get("values", [])]
        cited += [f["name"] for f in report.get("important_functions", [])]
    except (TypeError, KeyError, AttributeError):
        return None
    normalized_context = normalize(context)
    cited = [str(c) for c in cited if normalize(str(c))]
    ungrounded = [c for c in cited if normalize(c) not in normalized_context]
    return {
        "cited": len(cited),
        "ungrounded": ungrounded,
        "grounded_ratio": round(1 - len(ungrounded) / len(cited), 3) if cited else None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the grounding of existing ExeLens reports in their contexts.")
    parser.add_argument("directory", help="Output directory of the ExeLens runs (with context/ and reports/)")
    args = parser.parse_args()

    ratios = []
    for report_path in sorted(glob.glob(os.path.join(args.directory, "reports", "exelens_report_*.txt"))):
        md5 = os.path.basename(report_path)[len("exelens_report_"):-len(".txt")]
        context_path = os.path.join(args.directory, "context", f"{md5}.txt")
        if not os.path.exists(context_path):
            continue
        with open(report_path) as f, open(context_path) as g:
            result = check_grounding(f.read(), g.read())
        if result is None:
            print(f"{md5}: not a JSON report")
            continue
        if result["grounded_ratio"] is not None:
            ratios.append(result["grounded_ratio"])
        print(f"{md5}: grounded {result['grounded_ratio']} of {result['cited']} cited, ungrounded: {result['ungrounded']}")
    if ratios:
        print(f"Mean grounded ratio: {sum(ratios) / len(ratios):.3f} over {len(ratios)} reports")
