import argparse
import os
import sys
import time

from google import genai
from malflow.cli import commands as malflow_commands
from malflow.cli.formatters import print_error, print_info

from exelens.core.analyzer import call_graph_info, measure_node_centrality, get_important_functions, get_entrypoints, \
    MAX_INSTRUCTIONS, dfs_call_graph_instruction_traversal, MAX_FUNCTIONS, build_analysis_context, \
    format_analysis_message, PE_AGENT_PROMPT
from exelens.core.drawing import draw_svg, get_selected_node_labels
from exelens.core.llm import LlmClient
from exelens.model.llm import LlmModels


class ArgumentParserWithHelp(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        self.exit(2, f'\n{self.prog}: error: {message}\n')


def main():
    parser = ArgumentParserWithHelp(
        prog="exelens",
        description="exelens",
    )
    parser.add_argument("-i", "--input", help="Path to the PE file to analyze")
    parser.add_argument("--md5", help="MD5 of the PE file to analyze")
    parser.add_argument("-m", "--model", help="Gemini model to be used; default: gemini-2.5-flash")
    parser.print_help()
    sys.stdout.flush()
    args = parser.parse_args()

    if not args.model:
        model = LlmModels.GEMINI_2_5_FLASH
    else:
        try:
            model = LlmModels(args.model)
        except:
            print(f"\nUnsupported model: {args.model}")
            return 1

    if not args.input and not args.md5:
        parser.print_help()
        print("\nError: Please provide an existing file path or md5.", file=sys.stderr)
        return 1

    if "GOOGLE_API_KEY" not in os.environ:
        print_error("Please set the GOOGLE_API_KEY env variable for further analysis.")
        return 1
    GOOGLE_API_KEY = os.environ["GOOGLE_API_KEY"].strip()
    if not GOOGLE_API_KEY:
        print_error("GOOGLE_API_KEY env variable is empty.")
        return 1

    file_path = args.input
    if not os.path.isfile(file_path):
        print(f"Error: File '{args.input}' does not exist.", file=sys.stderr)
        return 1

    args.verbose = False

    ts_start = time.perf_counter()

    cg = malflow_commands.load_callgraph(file_path, force_rescan=True, verbose=False)

    args.ep = False
    args.imports = False
    args.dump = False
    malflow_commands.cmd_info(args, cg)

    pe_info = call_graph_info(cg)
    centrality_metrics, sorted_node_labels = measure_node_centrality(cg)
    important_functions = get_important_functions(cg, centrality_metrics, sorted_node_labels, top_n=20)
    entrypoints = get_entrypoints(cg)

    svg_path = os.path.join(os.path.dirname(file_path), f"{cg.md5}.cg-sfdp.svg")
    draw_svg(cg, svg_path, centrality_metrics, sorted_node_labels)

    if pe_info.instructions <= MAX_INSTRUCTIONS:
        dfs_summary = dfs_call_graph_instruction_traversal(cg)
    else:
        dfs_summary = None

    functions_to_analyze = list(get_selected_node_labels(cg, centrality_metrics, sorted_node_labels, MAX_FUNCTIONS))

    analysis_context = build_analysis_context(cg,
                                              pe_info,
                                              entrypoints,
                                              important_functions,
                                              functions_to_analyze,
                                              dfs_summary)
    analysis_message = format_analysis_message(analysis_context)

    # ================================
    # LLM summary
    # ================================

    final_prompt = PE_AGENT_PROMPT + "\n" + analysis_message
    print_info(f"Analyzing code ... ")

    llm_client = LlmClient(model_name=model.name)
    ts_llm = time.perf_counter()
    report_text = llm_client.generate_summary(final_prompt)
    dt_llm = time.perf_counter() - ts_llm

    # ================================
    # Result
    # ================================
    output_file_path = os.path.join(os.path.dirname(file_path), f"exelens_report_{cg.md5}.txt")
    with open(output_file_path, "w") as f:
        f.write(report_text)

    dt_all = time.perf_counter() - ts_start

    final_message = f"Analysis completed in **{dt_all:.2f}s** (LLM: **{dt_llm:.2f}s**)"
    print_info(f"Report written to {output_file_path}")
    print_info(final_message)

    return 0


if __name__ == "__main__":
    sys.exit(main())
