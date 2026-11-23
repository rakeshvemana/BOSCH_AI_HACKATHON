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
from typing import Any, Iterable, Optional

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


class PathFinder:
    """Shortest dependency paths root -> component, for many lookups on one graph.

    One BFS from the root gives every node's depth. A node's "shortest-path parents" are the
    parents exactly one level closer to the root; walking those back always ends at the root,
    so enumerating paths never explores a dead end: O(limit x depth) per lookup, after an
    O(nodes + edges) setup. (``nx.all_simple_paths`` can explore exponentially many branches
    in dense npm graphs before it finds a few paths.)
    """

    def __init__(self, edges: Iterable[tuple[str, str]], root: str = ROOT_ID) -> None:
        children: dict[str, list[str]] = {}
        parents: dict[str, list[str]] = {}
        for s, t in edges:
            children.setdefault(s, []).append(t)
            parents.setdefault(t, []).append(s)
        self.root = root
        self.depth: dict[str, int] = {root: 0}
        dq = deque([root])
        while dq:
            n = dq.popleft()
            for k in children.get(n, []):
                if k not in self.depth:
                    self.depth[k] = self.depth[n] + 1
                    dq.append(k)
        self._up = {n: sorted({p for p in ps if self.depth.get(p, -2) == self.depth.get(n, -1) - 1})
                    for n, ps in parents.items()}

    def paths(self, target: str, limit: int = 3) -> list[list[str]]:
        if target not in self.depth:
            return []
        out: list[list[str]] = []
        stack = [(target, [target])]
        while stack and len(out) < limit:
            node, acc = stack.pop()
            if node == self.root:
                out.append(acc[::-1])
                continue
            for p in reversed(self._up.get(node, [])):
                stack.append((p, acc + [p]))
        return out


def paths_from_root(graph: dict[str, Any], node_id: str, limit: int = 5, max_len: int = 12) -> list[list[str]]:
    """Up to ``limit`` SHORTEST paths root -> node (several when it is reached through several parents)."""
    paths = PathFinder((e["source"], e["target"]) for e in graph["edges"]).paths(node_id, limit)
    return [p for p in paths if len(p) - 1 <= max_len]


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


def _layers(graph: dict[str, Any]) -> dict[int, list[str]]:
    """Group node ids by BFS depth from the root (unreachable nodes go in one extra layer)."""
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
    return layers


def _layout(graph: dict[str, Any]) -> dict[str, tuple[float, float]]:
    """Left-to-right layered layout: x = depth column, nodes stacked vertically in each column.

    Stacking vertically (instead of one long row per depth) gives every label its own line,
    so wide layers (e.g. 50+ transitive packages) stay readable.
    """
    layers = _layers(graph)
    parents: dict[str, list[str]] = {}
    for e in graph["edges"]:
        parents.setdefault(e["target"], []).append(e["source"])
    pos: dict[str, tuple[float, float]] = {}
    for d in sorted(layers):
        layer = layers[d]
        if d == 0:
            layer.sort()
        else:  # barycentre ordering (mean parent row) reduces crossing lines
            def key(n: str) -> tuple[float, str]:
                ys = [pos[p][1] for p in parents.get(n, []) if p in pos]
                return (-(sum(ys) / len(ys)) if ys else 0.0, n)
            layer.sort(key=key)
        half = (len(layer) - 1) / 2
        for idx, n in enumerate(layer):
            pos[n] = (float(d), half - idx)
    return pos


_COLORS = {"root": "#111827", "direct": "#2563eb", "transitive": "#0d9488", "unknown": "#d97706"}
_ROW_PX = 22  # vertical pixels per node in the tallest column


def _short(name: str, n: int = 26) -> str:
    name = name.split("/")[-1]
    return name if len(name) <= n else name[: n - 1] + "…"


_RISK_RING = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#f97316", "low": "#eab308"}


def build_figure(graph: dict[str, Any], highlight: Optional[str] = None, flags: Optional[dict[str, str]] = None):
    """Return a Plotly figure for a graph JSON dict (as returned by the API).

    ``flags`` maps node id -> highest risk level of its findings; those nodes get a coloured ring.
    """
    flags = {k: v for k, v in (flags or {}).items() if v in _RISK_RING}
    import plotly.graph_objects as go

    pos = _layout(graph)
    layers = _layers(graph)
    tallest = max((len(v) for v in layers.values()), default=1)
    columns = max(layers, default=0)

    def edge_trace(edges: list[dict], color: str, width: float):
        xs: list[Optional[float]] = []
        ys: list[Optional[float]] = []
        for e in edges:
            if e["source"] in pos and e["target"] in pos:
                (x0, y0), (x1, y1) = pos[e["source"]], pos[e["target"]]
                # cubic Bezier S-curve (horizontal tangents at both ends): lines fan out instead of
                # merging into a block, and never overshoot the way a Plotly spline does
                xm = (x0 + x1) / 2
                for i in range(13):
                    t = i / 12
                    a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3
                    xs.append(a * x0 + b * xm + c * xm + d * x1)
                    ys.append(a * y0 + b * y0 + c * y1 + d * y1)
                xs.append(None)
                ys.append(None)
        return go.Scatter(x=xs, y=ys, mode="lines", line=dict(width=width, color=color),
                          hoverinfo="none", showlegend=False)

    touching = [e for e in graph["edges"] if highlight in (e["source"], e["target"])] if highlight else []
    other = [e for e in graph["edges"] if not highlight or highlight not in (e["source"], e["target"])]
    fig = go.Figure(edge_trace(other, "rgba(156,163,175,0.3)" if highlight else "rgba(156,163,175,0.55)", 0.8))
    if touching:
        fig.add_trace(edge_trace(touching, "#ef4444", 2))

    near = ({highlight} | {e["source"] for e in touching} | {e["target"] for e in touching}) if highlight else set()
    lit = lambda n: not highlight or n["id"] in near  # noqa: E731
    by_type: dict[str, list[dict]] = {}
    for n in graph["nodes"]:
        by_type.setdefault(n["dependency_type"], []).append(n)
    for dtype, nodes in by_type.items():
        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes], mode="markers+text",
            name=dtype.capitalize(), textposition="middle right",
            text=[f" {'⚠ ' if n['id'] in flags else ''}{_short(n['name'])}"
                  # commit SHAs / digests are 40+ chars and would run into the next column
                  + (f" <span style='color:#9ca3af'>{_short(n['version'], 14)}</span>" if n["version"] else "")
                  for n in nodes],
            textfont=dict(size=11, color=[("#b91c1c" if n["id"] in flags else "#111827") if lit(n) else "#d1d5db"
                                          for n in nodes]),
            marker=dict(
                size=[16 if n["id"] == highlight else (13 if n["id"] in flags else 10) for n in nodes],
                color=_COLORS.get(dtype, "#6b7280"),
                opacity=[1.0 if lit(n) else 0.3 for n in nodes],
                line=dict(width=[3 if n["id"] == highlight or n["id"] in flags else 1 for n in nodes],
                          color=["#ef4444" if n["id"] == highlight else _RISK_RING.get(flags.get(n["id"], ""), "#ffffff")
                                 for n in nodes]),
                symbol=["diamond" if n.get("in_cycle") else "circle" for n in nodes],
            ),
            customdata=[n["id"] for n in nodes],
            hovertext=[f"<b>{n['name']}</b><br>Version: {n['version'] or 'unresolved'} ({n['version_status']})<br>"
                       f"Type: {n['dependency_type']}<br>Ecosystem: {n['ecosystem']}<br>Depth: {n.get('depth')}"
                       + (f"<br><b>Highest risk: {flags[n['id']]}</b>" if n["id"] in flags else "") for n in nodes],
            hoverinfo="text",
        ))
    half = (tallest - 1) / 2
    titles = ["Application", "Direct"] + [f"Transitive (depth {i})" for i in range(2, columns + 1)]
    fig.update_layout(
        showlegend=True, hovermode="closest", margin=dict(l=10, r=10, t=40, b=10),
        height=max(420, 100 + _ROW_PX * tallest),
        xaxis=dict(visible=False, range=[-0.1, columns + 0.9]),
        yaxis=dict(visible=False, range=[-half - 1, half + 1.5]),
        plot_bgcolor="rgba(0,0,0,0)", legend=dict(orientation="h", y=1.0, yanchor="bottom", x=0, xanchor="left"),
        annotations=[dict(x=d, y=half + 1.2, text=f"<b>{t}</b>", showarrow=False, font=dict(size=12, color="#6b7280"),
                          xanchor="left") for d, t in enumerate(titles[: columns + 1])],
    )
    return fig
