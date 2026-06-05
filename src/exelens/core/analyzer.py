import os
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Set

import networkx as nx
from malflow import CallGraph, Instruction, InstructionParameter, InstructionPrefix, InstructionReference
from malflow.cli import commands as malflow_commands
from malflow.cli.formatters import print_info, print_success
from malflow.core.model.function import CGNode, FunctionType
from malflow.core.model.radare2_definitions import Mnemonics

from exelens.core.drawing import draw_svg, get_selected_node_labels
from exelens.core.llm import LlmClient
from exelens.model.pe import NodeCentrality


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


def shorten_function_label(cg_node: CGNode) -> str:
    if cg_node.type == FunctionType.DLL:
        return cg_node.label.replace("sym.imp.", "")
    return cg_node.label


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


def display_instruction(i: Instruction) -> str:
    return f"{shorten_instruction2(i)}\n"


def function_instruction_summary(cg_node: CGNode):
    if len(cg_node.instructions) <= 100:
        buffer = ""
        for instr in cg_node.instructions[:10]:
            buffer += display_instruction(instr)
        return buffer
    else:
        buffer = f"(Total instructions: {len(cg_node.instructions)}, Showing only extracts:\n"

        def add_instruction_segment(buffer, i, segment_size=30):
            buffer += f"[{i} - {i + segment_size}]\n"
            for instr in cg_node.instructions[i:i + segment_size]:
                buffer += display_instruction(instr)
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
    for instr in cg.dfs_instructions(max_instructions=None, allow_multiple_visits=False, store_call=True, store_cg_node=True):
        if isinstance(instr, Instruction):
            buffer += f"{display_instruction(instr)}"
        else:
            cg_node, depth = instr
            register_types = function_register_types(cg_node)
            rt_str = " " + ", ".join(register_types) if register_types else ""
            buffer += f"\n> D{depth} {shorten_function_label(cg_node)}{rt_str}\n"
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


MAX_INSTRUCTIONS = 50000
MAX_FUNCTIONS = 1000

def build_analysis_context(cg, pe_info: PEInfo,
                           entrypoints: List[PEFunctionInfo],
                           important_functions: List[PEFunctionInfo],
                           functions_to_analyze: List[str],
                           dfs_summary: str) -> Dict:
    context = {
        "md5": cg.md5,
        "entrypoints": entrypoints,
        "total_functions": pe_info.functions,
        "total_function_calls": pe_info.calls,
        "total_instructions": pe_info.instructions,
        "important_functions": important_functions,
    }

    if dfs_summary is not None:
        context["full_dfs"] = True
        context["dfs_summary"] = dfs_summary
        return context

    context["functions_analyzed"] = {}
    instruction_budget = MAX_INSTRUCTIONS

    for f_info in entrypoints[:10]:
        if instruction_budget <= 0: break
        node = cg.nodes.get(f_info.label)
        if node:
            func_instructions = function_instructions(cg, node.label)
            context["functions_analyzed"][f_info.label] = {
                "info": f_info,
                "assembly": func_instructions
            }
            instruction_budget -= 100

    for f_label in functions_to_analyze:
        if instruction_budget <= 0: break
        node = cg.nodes.get(f_label)
        if node and node.label not in context["functions_analyzed"]:
            func_instructions = function_instructions(cg, node.label)
            context["functions_analyzed"][f_label] = {}
            if node.type != FunctionType.DLL:
                context["functions_analyzed"][f_label]["assembly"] = func_instructions
            instruction_budget -= 100

    return context


def format_analysis_message(context: Dict):
    entrypoints_string = '\n'.join([f.display_markdown() for f in context["entrypoints"]])
    important_functions_string = '\n'.join([f.display_markdown() for f in context["important_functions"]])

    task = f"""# PE Analysis Task

## MD5: {context["md5"]}
## Entrypoints: {entrypoints_string}
## Functions: {context["total_functions"]}
## Instructions: {context["total_instructions"]}
## Function Calls: {context["total_function_calls"]}
## Important Functions: {important_functions_string}
"""
    if context.get("full_dfs", None):
        task += f"## Full DFS Traversal\n---\n{context['dfs_summary']}\n---\n"
    else:
        functions = []
        for label, function in context["functions_analyzed"].items():
            functions.append(f"### Function: {label}\n")
            if "assembly" in function:
                functions.append(f"- Assembly:\n---\n{function['assembly']}\n---\n")
        task += f"## Analyzed Functions\n---\n{''.join(functions)}---\n"
    return task


PE_AGENT_PROMPT = "You are a malware analyst. Analyze the following PE file summary."


def analyze_file(file_path: str, md5: str = None, model_name: str = None) -> int:
    ts_start = time.perf_counter()

    cg = malflow_commands.load_callgraph(file_path, force_rescan=True, verbose=False)

    class DummyArgs:
        ep = False
        imports = False
        dump = False
        verbose = False

    malflow_commands.cmd_info(DummyArgs(), cg)

    pe_info = call_graph_info(cg)
    centrality_metrics, sorted_node_labels = measure_node_centrality(cg)
    important_functions = get_important_functions(cg, centrality_metrics, sorted_node_labels, top_n=20)
    entrypoints = get_entrypoints(cg)

    svg_path = os.path.join(os.path.dirname(file_path), f"{cg.md5}.cg-sfdp.svg")
    try:
        draw_svg(cg, svg_path, centrality_metrics, sorted_node_labels)
    except Exception as e:
        print(f"Warning: Could not draw SVG: {e}")

    if pe_info.instructions <= MAX_INSTRUCTIONS:
        dfs_summary = dfs_call_graph_instruction_traversal(cg)
    else:
        dfs_summary = None

    functions_to_analyze = list(get_selected_node_labels(cg, centrality_metrics, sorted_node_labels, MAX_FUNCTIONS))

    analysis_context = build_analysis_context(
        cg, pe_info, entrypoints, important_functions, functions_to_analyze, dfs_summary
    )
    analysis_message = format_analysis_message(analysis_context)

    # LLM summary
    final_prompt = PE_AGENT_PROMPT + "\n" + analysis_message
    print_info(f"Analyzing code with {model_name or 'default'}...")

    llm_client = LlmClient(model_name=model_name)

    ts_llm = time.perf_counter()
    report_text = llm_client.generate_summary(final_prompt)
    dt_llm = time.perf_counter() - ts_llm

    # Result
    output_file_path = os.path.join(os.path.dirname(file_path), f"exelens_report_{cg.md5}.txt")
    with open(output_file_path, "w") as f:
        f.write(report_text)

    dt_all = time.perf_counter() - ts_start

    final_message = f"Analysis completed in **{dt_all:.2f}s** (out of which LLM took **{dt_llm:.2f}s**)"
    print_info(f"Report written to {output_file_path}")
    print_success(final_message)

    return 0
