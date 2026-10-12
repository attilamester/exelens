import argparse
import glob
import hashlib
import sys
import os

from exelens import __version__
from exelens.core.analyzer import analyze_file
from exelens.core.llm import DailyQuotaExceeded

class ArgumentParserWithHelp(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        self.exit(2, f'\n{self.prog}: error: {message}\n')

def create_parser():
    parser = ArgumentParserWithHelp(
        prog="exelens",
        description="ExeLens - An AI-powered executable analysis tool.",
    )
    parser.add_argument("-i", "--input", help="Path to the PE file (or <md5>.cgcompressed.pickle dump) to analyze, "
                                              "or a directory to analyze all the dumps in it")
    parser.add_argument("--md5", help="MD5 of the PE file to analyze (if fetching from remote)")
    parser.add_argument("-m", "--model", help="LLM model to be used; e.g. gemini-3.1-flash-lite or openai/gpt-4o-mini")
    parser.add_argument("-o", "--output-dir", help="Directory to write the drawing/, context/ and reports/ outputs to "
                                                   "(default: alongside the input file)")
    parser.add_argument("--prompt-only", action="store_true",
                        help="Only write the SVG and the LLM input context (context/<md5>.txt), without calling the LLM "
                             "(no API key needed)")
    parser.add_argument("--sample", help="Original PE file of a dump given as --input, read (never executed) for its "
                                         "sections, resources and overlay")
    parser.add_argument("--samples-dir", help="Directory searched (recursively, by md5) for the original PE files of "
                                              "the dumps given as --input")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser

def index_samples(samples_dir: str) -> dict:
    """md5 -> path of every file under samples_dir."""
    index = {}
    for path in glob.glob(os.path.join(samples_dir, "**", "*"), recursive=True):
        if os.path.isfile(path) and not path.endswith(".zip"):
            with open(path, "rb") as f:
                index[hashlib.md5(f.read()).hexdigest()] = path
    print(f"Indexed {len(index)} samples in {samples_dir}")
    return index

def analyze_directory(directory: str, model_name: str, output_dir: str, prompt_only: bool, samples: dict) -> int:
    """Analyzes every dump in directory, skipping finished samples."""
    output_dir = output_dir or directory
    # report metadata also exists for blocked samples, so they are not retried
    output_name = os.path.join("context", "{}.txt") if prompt_only else os.path.join("reports", "exelens_report_{}.json")
    dumps = sorted(glob.glob(os.path.join(directory, "*.cgcompressed.pickle")))
    done, skipped, failed = 0, 0, []
    for i, dump in enumerate(dumps, 1):
        md5 = os.path.basename(dump).split(".")[0]
        if os.path.exists(os.path.join(output_dir, output_name.format(md5))):
            skipped += 1
            continue
        print(f"[{i}/{len(dumps)}] {md5}")
        try:
            status = analyze_file(file_path=dump, model_name=model_name, output_dir=output_dir, prompt_only=prompt_only,
                                  sample_path=samples.get(md5))
        except DailyQuotaExceeded:
            print("Daily LLM quota used up (free tier: resets at midnight Pacific time); stopping - re-run to resume.",
                  file=sys.stderr)
            failed.append(md5)
            break
        except Exception as e:
            print(f"Error analyzing {dump}: {e}", file=sys.stderr)
            status = 1
        if status == 0:
            done += 1
        else:
            failed.append(md5)
    print(f"Done. total={len(dumps)} analyzed={done} skipped(existing)={skipped} failed={len(failed)} {failed}")
    return 1 if failed else 0

def main():
    parser = create_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    if not args.input and not args.md5:
        parser.print_help()
        print("\nError: Please provide an existing file path (-i) or md5 (--md5).", file=sys.stderr)
        return 1

    file_path = args.input

    samples = index_samples(args.samples_dir) if args.samples_dir else {}

    if file_path and os.path.isdir(file_path):
        return analyze_directory(file_path, model_name=args.model, output_dir=args.output_dir, prompt_only=args.prompt_only,
                                 samples=samples)

    # Basic file check
    if file_path and not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.", file=sys.stderr)
        return 1
        
    sample_path = args.sample or samples.get(os.path.basename(file_path).split(".")[0])
    try:
        return analyze_file(file_path=file_path, md5=args.md5, model_name=args.model, output_dir=args.output_dir,
                            prompt_only=args.prompt_only, sample_path=sample_path)
    except DailyQuotaExceeded:
        print("Daily LLM quota used up (free tier: resets at midnight Pacific time).", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
