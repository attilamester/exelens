import argparse
import sys
import os

from exelens import __version__
from exelens.core.analyzer import analyze_file

class ArgumentParserWithHelp(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        self.exit(2, f'\n{self.prog}: error: {message}\n')

def create_parser():
    parser = ArgumentParserWithHelp(
        prog="exelens",
        description="ExeLens - An AI-powered executable analysis tool.",
    )
    parser.add_argument("-i", "--input", help="Path to the PE file to analyze")
    parser.add_argument("--md5", help="MD5 of the PE file to analyze (if fetching from remote)")
    parser.add_argument("-m", "--model", help="LLM model to be used; e.g. openai/gpt-4o-mini or google/gemini-2.5-flash")
    parser.add_argument("-o", "--output-dir", help="Directory to write the report/SVG to (default: alongside the input file)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser

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

    # Basic file check
    if file_path and not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.", file=sys.stderr)
        return 1
        
    return analyze_file(file_path=file_path, md5=args.md5, model_name=args.model, output_dir=args.output_dir)

if __name__ == "__main__":
    sys.exit(main())
