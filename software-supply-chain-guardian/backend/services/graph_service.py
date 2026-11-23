"""Dependency graph: construction (NetworkX), statistics, export and Plotly drawing.

Beginner notes
--------------
* A *directed graph* has nodes (components) and arrows (A -> B means "A depends on B").
* Because node IDs come from Package URLs, a package used by many parents is
  ONE node with several incoming arrows (no duplicates).
* Cycles (A -> B -> A) are legal in some ecosystems; we find them with
  strongly-connected components and the layout uses BFS depth, so they can
  never cause infinite loops.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Optional

import networkx as nx

from backend.models import (
    DiscoveryResult, GraphEdge, GraphNode, GraphResponse, GraphStats, ROOT_ID,
)

TABLE_FALLBACK_NODES = 250  # above this the dashboard shows a table instead of a hairball


def build_digraph(result: DiscoveryResult) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(ROOT_ID, label=result.project_name, name=result.project_name, version=None,
               version_status="resolved", ecosystem="application", dependency_type="root")
    for c in result.components:
        g.add_node(c.id, label=f"{c.name} {c.version}" if c.version else f"{c.name} (unresolved)", name=c.name,
                   version=c.version, version_status=c.version_status, ecosystem=c.ecosystem,
                   dependency_type=c.dependency_type)
    for r in result.relationships:
        if r.source in g and r.target in g:
            g.add_edge(r.source, r.target, requirement=r.requirement, inferred=r.inferred)
    return g


def graph_response(result: DiscoveryResult) -> GraphResponse:
    g = build_digraph(result)
    depth = nx.single_source_shortest_path_length(g, ROOT_ID)
    cyc_nodes: set[str] = set()
    cycles = 0
    for scc in nx.strongly_connected_components(g):
        if len(scc) > 1:
            cycles += 1
            cyc_nodes |= scc
    for n in g.nodes:
        if g.has_edge(n, n):
            cycles += 1
            cyc_nodes.add(n)
    nodes = [
        GraphNode(id=n, label=d["label"], name=d["name"], version=d["version"], version_status=d["version_status"],
                  ecosystem=d["ecosystem"], dependency_type=d["dependency_type"], depth=depth.get(n),
                  in_cycle=n in cyc_nodes)
        for n, d in g.nodes(data=True)
    ]
    edges = [GraphEdge(source=u, target=v, requirement=d.get("requirement"), inferred=bool(d.get("inferred")))
             for u, v, d in g.edges(data=True)]
    shared = sum(1 for n in g.nodes if n != ROOT_ID and g.in_degree(n) > 1)
    stats = GraphStats(
        nodes=g.number_of_nodes(), edges=g.number_of_edges(), max_depth=max(depth.values()) if depth else 0,
        cycles=cycles, shared_components=shared, unreachable=g.number_of_nodes() - len(depth),
    )
    return GraphResponse(analysis_id=result.analysis_id, nodes=nodes, edges=edges, stats=stats)


# --------------------------------------------------------------- dict helpers
def dependents_of(graph: dict[str, Any], node_id: str) -> list[str]:
    return sorted({e["source"] for e in graph["edges"] if e["target"] == node_id})


def dependencies_of(graph: dict[str, Any], node_id: str) -> list[str]:
    return sorted({e["target"] for e in graph["edges"] if e["source"] == node_id})


def paths_from_root(graph: dict[str, Any], node_id: str, limit: int = 5, max_len: int = 12) -> list[list[str]]:
    """Up to ``limit`` simple paths root -> node (shows multiple dependency paths)."""
    dg = nx.DiGraph()
    dg.add_edges_from((e["source"], e["target"]) for e in graph["edges"])
    if ROOT_ID not in dg or node_id not in dg:
        return []
    out = []
    for p in nx.all_simple_paths(dg, ROOT_ID, node_id, cutoff=max_len):
        out.append(p)
        if len(out) >= limit:
            break
    return out


def subgraph_around(graph: dict[str, Any], node_id: str, depth: int = 3) -> dict[str, Any]:
    """Nodes within ``depth`` steps below ``node_id`` plus the path context up to the root."""
    children: dict[str, list[str]] = {}
    for e in graph["edges"]:
        children.setdefault(e["source"], []).append(e["target"])
    keep = {node_id}
    dq = deque([(node_id, 0)])
    while dq:
        n, d = dq.popleft()
        if d >= depth:
            continue
        for k in children.get(n, []):
            if k not in keep:
                keep.add(k)
                dq.append((k, d + 1))
    for p in paths_from_root(graph, node_id, limit=3):
        keep.update(p)
    return {
        **graph,
        "nodes": [n for n in graph["nodes"] if n["id"] in keep],
        "edges": [e for e in graph["edges"] if e["source"] in keep and e["target"] in keep],
    }


def _layout(graph: dict[str, Any]) -> dict[str, tuple[float, float]]:
    ids = [n["id"] for n in graph["nodes"]]
    adj: dict[str, list[str]] = {i: [] for i in ids}
    for e in graph["edges"]:
        adj.setdefault(e["source"], []).append(e["target"])
    depth = {ROOT_ID: 0} if ROOT_ID in adj else {}
    dq = deque(depth)
    while dq:
        n = dq.popleft()
        for k in adj.get(n, []):
            if k not in depth:
                depth[k] = depth[n] + 1
                dq.append(k)
    layers: dict[int, list[str]] = {}
    for i in ids:
        layers.setdefault(depth.get(i, max(depth.values(), default=0) + 1), []).append(i)
    pos: dict[str, tuple[float, float]] = {}
    parents: dict[str, list[str]] = {}
    for e in graph["edges"]:
        parents.setdefault(e["target"], []).append(e["source"])
    for d in sorted(layers):
        layer = layers[d]
        if d == 0:
            layer.sort()
        else:  # barycentre ordering reduces crossing lines
            layer.sort(key=lambda n: (sum(pos[p][0] for p in parents.get(n, []) if p in pos) / max(1, sum(1 for p in parents.get(n, []) if p in pos)), n))
        width = max(len(layer) - 1, 1)
        for idx, n in enumerate(layer):
            pos[n] = ((idx - width / 2) if len(layer) > 1 else 0.0, -float(d))
    return pos


_COLORS = {"root": "#111827", "direct": "#2563eb", "transitive": "#0d9488", "unknown": "#d97706"}


def build_figure(graph: dict[str, Any], highlight: Optional[str] = None):
    """Return a Plotly figure for a graph JSON dict (as returned by the API)."""
    import plotly.graph_objects as go

    pos = _layout(graph)
    xs: list[Optional[float]] = []
    ys: list[Optional[float]] = []
    for e in graph["edges"]:
        if e["source"] in pos and e["target"] in pos:
            xs += [pos[e["source"]][0], pos[e["target"]][0], None]
            ys += [pos[e["source"]][1], pos[e["target"]][1], None]
    edge_trace = go.Scatter(x=xs, y=ys, mode="lines", line=dict(width=1, color="#9ca3af"), hoverinfo="none", showlegend=False)

    fig = go.Figure(edge_trace)
    by_type: dict[str, list[dict]] = {}
    for n in graph["nodes"]:
        by_type.setdefault(n["dependency_type"], []).append(n)
    for dtype, nodes in by_type.items():
        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes], mode="markers+text",
            name=dtype.capitalize(), textposition="bottom center",
            text=[(n["name"].split("/")[-1][:18] + (f"<br>{n['version']}" if n["version"] and len(graph["nodes"]) <= 60 else ""))
                  for n in nodes],
            textfont=dict(size=9),
            marker=dict(
                size=[22 if n["id"] == highlight else 14 for n in nodes], color=_COLORS.get(dtype, "#6b7280"),
                line=dict(width=[3 if n["id"] == highlight else 1 for n in nodes], color="#ef4444" if highlight else "#ffffff"),
                symbol=["diamond" if n.get("in_cycle") else "circle" for n in nodes],
            ),
            customdata=[n["id"] for n in nodes],
            hovertext=[f"<b>{n['name']}</b><br>Version: {n['version'] or 'unresolved'} ({n['version_status']})<br>"
                       f"Type: {n['dependency_type']}<br>Ecosystem: {n['ecosystem']}<br>Depth: {n.get('depth')}" for n in nodes],
            hoverinfo="text",
        ))
    fig.update_layout(
        showlegend=True, hovermode="closest", margin=dict(l=10, r=10, t=10, b=10), height=560,
        xaxis=dict(visible=False), yaxis=dict(visible=False), plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.05),
    )
    return fig
