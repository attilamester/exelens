import hashlib
import itertools
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Set

import networkx as nx
from malflow import CallGraph, CallGraphCompressed, Instruction, InstructionParameter, InstructionPrefix, InstructionReference
from malflow.cli import commands as malflow_commands
from malflow.cli.formatters import print_info, print_success
from malflow.core.model.function import CGNode, FunctionType
from malflow.core.model.radare2_definitions import Mnemonics

from exelens.core.cost import billed_output_tokens, estimate_cost, estimate_tokens
from exelens.core.drawing import draw_svg, get_selected_node_labels, shorten_function_label
from exelens.core.file_info import file_info_markdown
from exelens.core.grounding import check_grounding
from exelens.core.llm import LlmClient
from exelens.model.pe import NodeCentrality
from exelens.prompting import load_system_prompt


# --- Data Models ---
@dataclass
class PEInfo:
    md5: str
    scan_time: float
    entrypoints: List[str]
    functions: int
    calls: int
    instructions: int
    avg_instructions_per_function: float
    median_instructions_per_function: float
    min_instructions_per_function: int
    max_instructions_per_function: int


@dataclass
class PEFunctionInfo:
    label: str
    rva: str
    type: str
    instructions: int
    dll_calls: List[str]
    subroutine_calls: List[str]
    centrality_metrics: Dict = None

    def display_markdown(self):
        return f"- **{self.label}** (RVA: {self.rva}, Type: {self.type}, Inst: {self.instructions}, DLL Calls: {len(self.dll_calls)})"


from exelens.util.stats import list_stats


# --- Analysis Methods ---

def measure_node_centrality(cg: CallGraph) -> Tuple[Dict[str, NodeCentrality], List[str]]:
    G = nx.DiGraph()
    for _, node in cg.nodes.items():
        G.add_node(node.label)
        for callee_label, callee in node.calls.items():
            if callee.label not in G:
                G.add_node(callee.label)
            G.add_edge(node.label, callee.label)

    in_degree = dict(G.in_degree())
    out_degree = dict(G.out_degree())
    degree_centrality = nx.degree_centrality(G)
    closeness_centrality = nx.closeness_centrality(G)
    eigenvector_centrality = nx.eigenvector_centrality(G, tol=1e-4, max_iter=500)

    centrality_metrics = {}
    for label, node in cg.nodes.items():
        centrality_metrics[node.label] = NodeCentrality(
            degree_in=in_degree.get(node.label, 0),
            degree_out=out_degree.get(node.label, 0),
            dll_calls=len([callee for callee in node.get_calls() if callee.type == FunctionType.DLL]),
            instructions=len(node.instructions),
            degree_centrality=degree_centrality.get(node.label, 0.0),
            closeness_centrality=closeness_centrality.get(node.label, 0.0),
            eigenvector_centrality=eigenvector_centrality.get(node.label, 0.0)
        )

    sorted_centrality_items = sorted(centrality_metrics.items(), key=lambda i: i[1].score, reverse=True)
    sorted_node_labels = [label for label, _ in sorted_centrality_items]

    return centrality_metrics, sorted_node_labels


def display_function_label(cg_node: CGNode) -> str:
    return f"{shorten_function_label(cg_node)} (RVA: {cg_node.rva.value})"


def call_graph_info(cg: CallGraph) -> PEInfo:
    instr_stats = list_stats([len(n.instructions) for n in cg.nodes.values()], round_decimal=2)

    return PEInfo(
        md5=cg.md5,
        scan_time=cg.scan_time,
        entrypoints=[display_function_label(n) for n in cg.entrypoints],
        functions=len(cg.nodes),
        calls=sum(len(n.get_calls()) for n in cg.nodes.values()),
        instructions=sum(len(n.instructions) for n in cg.nodes.values()),
        avg_instructions_per_function=instr_stats["avg"],
        median_instructions_per_function=instr_stats["median"],
        min_instructions_per_function=instr_stats["min"],
        max_instructions_per_function=instr_stats["max"]
    )


def delete_strings_from_string(original: str, to_delete: List[str]) -> str:
    buff = original
    for token in to_delete:
        buff = buff.replace(token, "")
    return buff


def replace_strings_in_string(original: str, replacements: List[Tuple[str, str]]) -> str:
    buff = original
    for token, replacement in replacements:
        buff = buff.replace(token, replacement)
    return buff


def shorten_instruction2(i: Instruction) -> str:
    buff = i.disasm
    buff = delete_strings_from_string(buff, ["byte ", "dword ", "qword ", "word ", "ptr ", "sym.imp."])
    buff = replace_strings_in_string(buff, [
        ("push", "pus"),
        ("call", "cal"),
        ("test", "tst")
    ])
    return buff


def display_instructions(instructions: List[Instruction]) -> str:
    """One line per instruction; a run of identical instructions is shown once, with its repeat count."""
    buffer = ""
    for line, run in itertools.groupby(shorten_instruction2(i) for i in instructions):
        repeats = sum(1 for _ in run) - 1
        buffer += f"{line} (repeated {repeats}x more times)\n" if repeats else f"{line}\n"
    return buffer


def function_instruction_summary(cg_node: CGNode):
    if len(cg_node.instructions) <= 100:
        return display_instructions(cg_node.instructions[:10])
    else:
        buffer = f"(Total instructions: {len(cg_node.instructions)}, Showing only extracts:\n"

        def add_instruction_segment(buffer, i, segment_size=30):
            buffer += f"[{i} - {i + segment_size}]\n"
            buffer += display_instructions(cg_node.instructions[i:i + segment_size])
            buffer += "...\n"
            return buffer

        buffer = add_instruction_segment(buffer, 0, 30)
        middle_start = len(cg_node.instructions) // 2 - 15
        buffer = add_instruction_segment(buffer, middle_start, 30)
        buffer = add_instruction_segment(buffer, len(cg_node.instructions) - 30, 30)
        return buffer


def function_info(cg: CallGraph, function_label: str) -> PEFunctionInfo:
    node = cg.nodes.get(function_label)
    if not node:
        return PEFunctionInfo("error", "0", "error", 0, [], [])

    return PEFunctionInfo(
        label=shorten_function_label(node),
        rva=node.rva.value,
        type=node.type.name,
        instructions=len(node.instructions),
        dll_calls=[c.label for c in node.get_calls() if c.type == FunctionType.DLL],
        subroutine_calls=[c.label for c in node.get_calls() if c.type == FunctionType.SUBROUTINE],
    )


def function_instructions(cg: CallGraph, function_label: str) -> str:
    node = cg.nodes.get(function_label)
    if not node:
        return "error"
    return function_instruction_summary(node)


def function_register_types(cg_node: CGNode) -> List[str]:
    register_types = set()
    for instr in cg_node.instructions:
        for key in Mnemonics:
            if key.name == "_ALL" or key.name == "ORACLE_INTEL_AMD__GENERAL_PURPOSE":
                continue
            if instr.mnemonic in key.value:
                register_types.add(delete_strings_from_string(key.name, ["ORACLE", "INTEL", "AMD", "__"]))
    return sorted(register_types)


def dfs_call_graph_instruction_traversal(cg: CallGraph) -> str:
    buffer = ""
    instructions = []  # consecutive instructions, displayed together so that repeats are collapsed
    for instr in cg.dfs_instructions(max_instructions=None, allow_multiple_visits=False, store_call=True, store_cg_node=True):
        if isinstance(instr, Instruction):
            instructions.append(instr)
        else:
            buffer += display_instructions(instructions)
            instructions = []
            cg_node, depth = instr
            register_types = function_register_types(cg_node)
            rt_str = " " + ", ".join(register_types) if register_types else ""
            buffer += f"\n> D{depth} {shorten_function_label(cg_node)}{rt_str}\n"
    buffer += display_instructions(instructions)
    return buffer.strip()


def get_important_functions(cg, centrality_metrics, sorted_node_labels, top_n=10) -> List[PEFunctionInfo]:
    important_nodes = []
    for label in sorted_node_labels[:top_n]:
        metrics = centrality_metrics[label]
        data = function_info(cg, label)
        if data.label != "error":
            data.centrality_metrics = metrics
            important_nodes.append(data)
    return important_nodes


def get_entrypoints(cg) -> List[PEFunctionInfo]:
    entrypoints_info = []
    for node in cg.entrypoints:
        info = function_info(cg, node.label)
        if info.label != "error":
            entrypoints_info.append(info)
    return entrypoints_info


# Upper bound of system prompt + analysis message, in estimated tokens (Gemini Pro prices rise above 200k).
MAX_PROMPT_TOKENS = 200_000
# Cheap pre-check before building the full DFS traversal: at ~8 tokens/instruction, larger files cannot fit.
MAX_INSTRUCTIONS = 100_000
MAX_FUNCTIONS = 1000

def imports_markdown(cg: CallGraph) -> str:
    """The imported (DLL) functions of the call graph, grouped by DLL."""
    imports: Dict[str, List[str]] = {}
    for node in cg.nodes.values():
        if node.type == FunctionType.DLL:
            dll, _, api = shorten_function_label(node).rpartition(".dll_")
            imports.setdefault(f"{dll}.dll" if dll else "other", []).append(api)
    buffer = f"## Imports ({sum(len(apis) for apis in imports.values())}):\n"
    for dll in sorted(imports):
        buffer += f"- {dll}: {', '.join(sorted(imports[dll]))}\n"
    return buffer


def build_analysis_context(cg, pe_info: PEInfo,
                           entrypoints: List[PEFunctionInfo],
                           important_functions: List[PEFunctionInfo],
                           functions_to_analyze: List[str],
                           dfs_summary: str,
                           file_info: str) -> Dict:
    context = {
        "md5": cg.md5,
        "entrypoints": entrypoints,
        "total_functions": pe_info.functions,
        "total_function_calls": pe_info.calls,
        "total_instructions": pe_info.instructions,
        "important_functions": important_functions,
        "dfs_summary": dfs_summary,
        "imports": imports_markdown(cg),
        "file_info": file_info,
        "functions_analyzed": {},
    }

    # Kept even when the full DFS is available: it is the fallback if the DFS does not fit the token budget.
    for f_label in [f.label for f in entrypoints[:10]] + functions_to_analyze:
        node = cg.nodes.get(f_label)
        if node and node.label not in context["functions_analyzed"]:
            context["functions_analyzed"][f_label] = {}
            if node.type != FunctionType.DLL:
                context["functions_analyzed"][f_label]["assembly"] = function_instructions(cg, node.label)

    return context


def format_analysis_message(context: Dict, max_tokens: int) -> Tuple[str, Dict]:
    """Returns the analysis message, within max_tokens (estimated), and stats about what it contains."""
    entrypoints_string = '\n'.join([f.display_markdown() for f in context["entrypoints"]])
    important_functions_string = '\n'.join([f.display_markdown() for f in context["important_functions"]])

    task = f"""# PE Analysis Task

## MD5: {context["md5"]}
## Entrypoints: {entrypoints_string}
## Functions: {context["total_functions"]}
## Instructions: {context["total_instructions"]}
## Function Calls: {context["total_function_calls"]}
## Important Functions: {important_functions_string}
{context["imports"]}{context["file_info"]}"""
    if context["dfs_summary"] is not None:
        full_dfs = f"## Full DFS Traversal\n---\n{context['dfs_summary']}\n---\n"
        if estimate_tokens(task + full_dfs) <= max_tokens:
            return task + full_dfs, {"mode": "full_dfs"}

    # Functions are added in priority order (entrypoints, then by centrality score) while they fit the budget.
    functions = []
    budget = max_tokens - estimate_tokens(task + "## Analyzed Functions\n---\n---\n")
    for label, function in context["functions_analyzed"].items():
        block = f"### Function: {label}\n"
        if "assembly" in function:
            block += f"- Assembly:\n---\n{function['assembly']}\n---\n"
        block_tokens = estimate_tokens(block)
        if block_tokens > budget:
            break
        functions.append(block)
        budget -= block_tokens
    task += f"## Analyzed Functions\n---\n{''.join(functions)}---\n"
    return task, {"mode": "selective", "functions_included": len(functions),
                  "functions_selected": len(context["functions_analyzed"])}


def write_drawing_and_context(cg: CallGraph, drawing_dir: str, context_dir: str, system_prompt: str,
                              sample_path: str = None) -> str:
    """Draws the call graph SVG (unless it exists) into drawing_dir and writes the LLM input context (the
    analysis message) and its stats into context_dir. Returns the analysis message."""
    pe_info = call_graph_info(cg)
    centrality_metrics, sorted_node_labels = measure_node_centrality(cg)
    important_functions = get_important_functions(cg, centrality_metrics, sorted_node_labels, top_n=20)
    entrypoints = get_entrypoints(cg)

    os.makedirs(drawing_dir, exist_ok=True)
    svg_path = os.path.join(drawing_dir, f"{cg.md5}.cg-sfdp.svg")
    if os.path.exists(svg_path):
        print_info(f"Call graph SVG already exists, not redrawn: {svg_path}")
    else:
        try:
            draw_svg(cg, svg_path, centrality_metrics, sorted_node_labels)
        except Exception as e:
            print(f"Warning: Could not draw SVG: {e}")

    if pe_info.instructions <= MAX_INSTRUCTIONS:
        dfs_summary = dfs_call_graph_instruction_traversal(cg)
    else:
        dfs_summary = None

    # Sorted by centrality score, so the functions kept within the token budget are the same on every run.
    selected_node_labels = get_selected_node_labels(cg, centrality_metrics, sorted_node_labels, MAX_FUNCTIONS)
    functions_to_analyze = [label for label in sorted_node_labels if label in selected_node_labels]

    file_info = "## Sections, Resources, Overlay: not available (original file not provided)\n"
    if sample_path:
        try:
            file_info = file_info_markdown(sample_path)
        except Exception as e:
            print(f"Warning: Could not read sections/resources of {sample_path}: {e}")

    analysis_context = build_analysis_context(
        cg, pe_info, entrypoints, important_functions, functions_to_analyze, dfs_summary, file_info
    )
    analysis_message, context_stats = format_analysis_message(
        analysis_context, MAX_PROMPT_TOKENS - estimate_tokens(system_prompt))

    context_meta = {
        "md5": cg.md5,
        **context_stats,
        "prompt_chars": len(system_prompt) + len(analysis_message),
        "estimated_prompt_tokens": estimate_tokens(system_prompt) + estimate_tokens(analysis_message),
    }
    print_info(f"Context: {context_stats}, ~{context_meta['estimated_prompt_tokens']:,} tokens")

    os.makedirs(context_dir, exist_ok=True)
    context_path = os.path.join(context_dir, f"{cg.md5}.txt")
    with open(context_path, "w") as f:
        f.write(analysis_message)
    with open(os.path.join(context_dir, f"{cg.md5}.json"), "w") as f:
        json.dump(context_meta, f, indent=2)
    print_success(f"LLM input context written to {context_path}")
    return analysis_message


def analyze_file(file_path: str, md5: str = None, model_name: str = None, output_dir: str = None,
                 prompt_only: bool = False, sample_path: str = None) -> int:
    if not file_path:
        # --md5-only (fetch-by-hash) mode is not implemented yet - fail clearly
        # instead of crashing on os.path.* calls below with file_path=None.
        print("Error: analyzing by --md5 alone is not supported yet; pass -i/--input.", file=sys.stderr)
        return 1

    ts_start = time.perf_counter()
    input_dir = os.path.dirname(os.path.abspath(file_path))
    output_dir = output_dir or input_dir
    if os.path.exists(output_dir) and not os.path.isdir(output_dir):
        print(f"Error: --output-dir '{output_dir}' exists and is not a directory.", file=sys.stderr)
        return 1
    os.makedirs(output_dir, exist_ok=True)

    cg = malflow_commands.load_callgraph(file_path, force_rescan=False, verbose=False)
    if cg is None:
        print(f"Error: could not load/scan '{file_path}'.", file=sys.stderr)
        return 1

    class DummyArgs:
        ep = False
        imports = False
        # malflow's own cache lookup (inside load_callgraph, force_rescan=False) always
        # checks input_dir, so the compressed-cache dump below is kept there too - not
        # in output_dir - to guarantee they stay in sync regardless of --output-dir.
        # Always re-dumped (not skipped on a cache hit) so a corrupted/stale cache file
        # self-heals instead of being reused forever. The drawing/, context/ and reports/
        # outputs below are unaffected and still go to output_dir.
        # An input that is already a compressed dump is not re-dumped over itself.
        dump = not file_path.endswith(CallGraphCompressed.COMPRESSED_EXTENSION)
        input = file_path
        output = None
        verbose = False

    malflow_commands.cmd_info(DummyArgs(), cg)

    drawing_dir, context_dir, reports_dir = (os.path.join(output_dir, d) for d in ("drawing", "context", "reports"))
    context_path = os.path.join(context_dir, f"{cg.md5}.txt")
    system_prompt = load_system_prompt()

    if prompt_only or not os.path.exists(context_path):
        if not file_path.endswith(CallGraphCompressed.COMPRESSED_EXTENSION):
            sample_path = sample_path or file_path  # the input itself is the original sample
        analysis_message = write_drawing_and_context(cg, drawing_dir, context_dir, system_prompt, sample_path)
        if prompt_only:
            return 0
    else:
        with open(context_path) as f:
            analysis_message = f.read()
        print_info(f"Using existing context: {context_path}")

    # LLM summary
    llm_client = LlmClient(model_name=model_name)
    print_info(f"Analyzing code with {llm_client.model_name}...")

    ts_llm = time.perf_counter()
    report_text, usage, finish_reason = llm_client.generate_summary(system_prompt, analysis_message)
    dt_llm = time.perf_counter() - ts_llm
    if usage is None:
        # The call failed (e.g. network, quota): nothing is written, so a batch re-run retries this sample.
        return 1

    # Result: the report (unless the LLM returned none) and its metadata, which also marks a sample without a report
    # (blocked, or cut off at the output cap) as done - a batch re-run skips it instead of paying for it again.
    os.makedirs(reports_dir, exist_ok=True)
    output_file_path = os.path.join(reports_dir, f"exelens_report_{cg.md5}.txt")
    if report_text is not None:
        with open(output_file_path, "w") as f:
            f.write(report_text)

    report_meta = {
        "md5": cg.md5,
        "model": llm_client.model_name,
        "system_prompt_sha256": hashlib.sha256(system_prompt.encode()).hexdigest(),
        "prompt_chars": len(system_prompt) + len(analysis_message),
        "estimated_prompt_tokens": estimate_tokens(system_prompt) + estimate_tokens(analysis_message),
        "llm_seconds": round(dt_llm, 2),
        "finish_reason": finish_reason,
        "report_written": report_text is not None,
        "grounding": check_grounding(report_text, analysis_message) if report_text is not None else None,
        "usage": usage,
        "cost_usd": estimate_cost(llm_client.model_name, usage["prompt_tokens"], billed_output_tokens(usage)),
    }
    with open(os.path.join(reports_dir, f"exelens_report_{cg.md5}.json"), "w") as f:
        json.dump(report_meta, f, indent=2)

    if report_text is None:
        print(f"Error: no report for {cg.md5} (finish_reason: {finish_reason}); recorded in its metadata")
        return 1

    dt_all = time.perf_counter() - ts_start

    final_message = f"Analysis completed in **{dt_all:.2f}s** (out of which LLM took **{dt_llm:.2f}s**)"
    print_info(f"Report written to {output_file_path}")
    print_success(final_message)

    return 0
