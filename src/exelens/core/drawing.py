import warnings
from typing import Dict, List, Set

import pygraphviz
from malflow import CallGraph
from malflow.core.model.function import CGNode, FunctionType

from exelens.model.pe import NodeCentrality


MIN_SIZE = 2
MAX_SIZE = 6
MIN_COLOR = 10
MAX_COLOR = 200


def shorten_function_label(cg_node: CGNode) -> str:
    if cg_node.type == FunctionType.DLL:
        return cg_node.label.replace("sym.imp.", "")
    return cg_node.label


def scale_value(value: float, min_val: float, max_val: float, min_output: float, max_output: float) -> float:
    if max_val == min_val:
        return (min_output + max_output) / 2
    normalized = (value - min_val) / (max_val - min_val)
    return min_output + normalized * (max_output - min_output)


def get_node_sizes(cg: CallGraph,
                   centrality_metrics: Dict[str, NodeCentrality]) -> Dict[str, float]:
    scores = [m.score for m in centrality_metrics.values()]
    min_score = min(scores)
    max_score = max(scores)

    node_sizes = {}
    for label, node in cg.nodes.items():
        score = centrality_metrics[label].score
        size = scale_value(score, min_score, max_score, MIN_SIZE, MAX_SIZE)
        node_sizes[label] = size
    return node_sizes


def get_node_colors(cg: CallGraph,
                    centrality_metrics: Dict[str, NodeCentrality]) -> Dict[str, str]:
    scores = [m.score for m in centrality_metrics.values()]
    sorted_scores = sorted(scores)
    score_median = sorted_scores[len(scores) // 2]
    score_p90 = sorted_scores[int(len(scores) * 0.9)]

    ins = [m.degree_in for m in centrality_metrics.values()]
    sorted_ins = sorted(ins)
    in_median = sorted_ins[len(ins) // 2]
    in_p90 = sorted_ins[int(len(ins) * 0.9)]

    node_colors = {}
    for label, node in cg.nodes.items():
        score = centrality_metrics[label].score
        d_in = centrality_metrics[label].degree_in

        if node.type == FunctionType.DLL:
            if d_in > in_p90:
                node_colors[label] = f"#00CC00"
            elif d_in > in_median:
                node_colors[label] = f"#99FF99"
            else:
                node_colors[label] = f"lightblue"
        else:
            if score > score_p90:
                node_colors[label] = f"#CC0000"
            elif score > score_median:
                node_colors[label] = f"#FF9999"
            else:
                node_colors[label] = f"black"

    return node_colors


def get_selected_node_labels(cg: CallGraph,
                             centrality_metrics: Dict[str, NodeCentrality],
                             sorted_node_labels: List[str], top_important_subroutines: int = 1000) -> Set[str]:
    if len(cg.nodes) <= top_important_subroutines:
        return set(cg.nodes.keys())

    selected_nodes = set(sorted_node_labels[:top_important_subroutines])
    for node in cg.nodes.values():
        if node.type == FunctionType.DLL:
            selected_nodes.add(node.label)
        elif node.type == FunctionType.SUBROUTINE and centrality_metrics[node.label].dll_calls > 0:
            selected_nodes.add(node.label)
    return selected_nodes


def draw_svg(cg: CallGraph,
             file_path: str,
             centrality_metrics: Dict[str, NodeCentrality],
             sorted_node_labels: List[str]) -> pygraphviz.AGraph:
    ag = pygraphviz.AGraph(directed=True, outputorder="edgesfirst")
    ag.graph_attr.update({
        'K': '0.3',  # Spring constant (controls spacing)
        'overlap': 'false',  # How to handle overlaps
        'sep': '+5',  # Separation between nodes
        'esep': '+3',  # Separation for edges
        'splines': 'false',  # Smooth edges
        'start': 'random42'  # Fixed random seed for reproducibility
    })

    def get_label(node: CGNode, node_centrality: NodeCentrality) -> str:
        dlls = len(
            [callee_label for callee_label, callee in node.calls.items() if callee.type == FunctionType.DLL]
        )
        buffer = shorten_function_label(node)
        if node.type == FunctionType.DLL:
            if "." in buffer:
                dll_name, api_name = buffer.split(".", maxsplit=1)
                api_name = api_name.replace(".dll_", "")
                buffer = f"{dll_name}\n.{api_name}"

        buffer += "\n"
        if node.type == FunctionType.DLL:
            buffer += f"{node.rva.value}\n"
            buffer += f"In: {node_centrality.degree_in}\n"
        else:
            buffer += f"RVA: {node.rva.value}\n"
            buffer += f"In: {node_centrality.degree_in}, Out: {node_centrality.degree_out}\n"
            buffer += f"{dlls} DLLs\n"
            buffer += f"{len(node.instructions)} instructions\n"
        return buffer

    def get_tooltip(node: CGNode) -> str:
        if node.instructions:
            buff = "\n".join([instr.disasm for instr in node.instructions[:100]])
            if len(node.instructions) > 100:
                buff += "\n..."
            return buff
        return "-"

    selected_nodes = get_selected_node_labels(cg, centrality_metrics, sorted_node_labels)
    node_sizes = get_node_sizes(cg, centrality_metrics)
    node_colors = get_node_colors(cg, centrality_metrics)

    for label, node in cg.nodes.items():
        if label not in selected_nodes:
            continue

        ag.add_node(label, shape="circle", style="filled",
                    fillcolor="lightblue" if node.type == FunctionType.DLL else "black",
                    color=node_colors[label],
                    fontcolor="white" if node.type != FunctionType.DLL else "black",
                    width=str(node_sizes[label]),
                    height=str(node_sizes[label]),
                    fixedsize="true",
                    penwidth=10,
                    label=get_label(node, centrality_metrics[label]),
                    tooltip=get_tooltip(node))

    for (a, b) in cg.get_edges():
        if a.label not in selected_nodes or b.label not in selected_nodes:
            continue
        ag.add_edge(a.label, b.label, tooltip=f"{a.label} ➔ {b.label}")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ag.layout(prog="sfdp")
        ag.draw(file_path, format="svg")

    return ag
