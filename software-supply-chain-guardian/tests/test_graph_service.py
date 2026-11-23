import json

from backend.models import ROOT_ID
from backend.services.discovery_service import discover_uploads
from backend.services.graph_service import (
    TABLE_FALLBACK_NODES, build_digraph, build_figure, graph_response, paths_from_root, subgraph_around,
)


def _lock(packages):
    return json.dumps({"lockfileVersion": 3, "packages": packages}).encode()


DIAMOND = {
    "": {"dependencies": {"a": "1", "b": "1"}},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "1"}},
    "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1"}},
    "node_modules/c": {"version": "1.0.0", "dependencies": {"d": "1"}},
    "node_modules/d": {"version": "1.0.0"},
}


def test_root_connects_to_direct_dependencies_only(samples):
    res, _ = discover_uploads(samples("python-uv-sample", "pyproject.toml", "uv.lock"))
    g = build_digraph(res)
    direct = {c.id for c in res.components if c.dependency_type == "direct"}
    assert set(g.successors(ROOT_ID)) == direct
    transitive = [c.id for c in res.components if c.dependency_type == "transitive"]
    assert all(not g.has_edge(ROOT_ID, t) for t in transitive)


def test_shared_dependency_not_duplicated_and_paths_preserved():
    res, _ = discover_uploads({"package-lock.json": _lock(DIAMOND)})
    graph = graph_response(res)
    assert graph.stats.nodes == 5 and graph.stats.shared_components == 1  # c has two parents
    g = json.loads(graph.model_dump_json())
    c_id = next(n["id"] for n in g["nodes"] if n["name"] == "c")
    d_id = next(n["id"] for n in g["nodes"] if n["name"] == "d")
    paths = paths_from_root(g, d_id)
    assert len(paths) == 2 and all(p[0] == ROOT_ID and p[-1] == d_id and c_id in p for p in paths)
    assert graph.stats.max_depth == 3 and graph.stats.unreachable == 0


def test_cycles_are_detected_and_do_not_hang():
    packages = {"": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}}}
    res, _ = discover_uploads({"package-lock.json": _lock(packages)})
    graph = graph_response(res)
    assert graph.stats.cycles == 1 and sum(n.in_cycle for n in graph.nodes) == 2
    build_figure(json.loads(graph.model_dump_json()))  # layout must terminate


def test_node_labels_show_version_only_when_known():
    res, _ = discover_uploads({"requirements.txt": b"Flask==2.2.2\nrequests\n"})
    labels = {n.name: n.label for n in graph_response(res).nodes}
    assert labels["Flask"] == "Flask 2.2.2" and labels["requests"] == "requests (unresolved)"


def test_graph_json_export_roundtrip_and_stable_ids(samples):
    res1, _ = discover_uploads(samples("python-sample", "requirements.txt"))
    res2, _ = discover_uploads(samples("python-sample", "requirements.txt"))
    g1, g2 = graph_response(res1), graph_response(res2)
    assert {n.id for n in g1.nodes} == {n.id for n in g2.nodes}   # ids are stable across runs
    data = json.loads(g1.model_dump_json())
    assert set(data) >= {"nodes", "edges", "stats", "root"}
    assert "pkg:pypi/flask@2.2.2" in {n["id"] for n in data["nodes"]}


def test_subgraph_and_figure(samples):
    res, _ = discover_uploads({"package-lock.json": _lock(DIAMOND)})
    g = json.loads(graph_response(res).model_dump_json())
    c_id = next(n["id"] for n in g["nodes"] if n["name"] == "c")
    sub = subgraph_around(g, c_id, depth=1)
    assert {n["name"] for n in sub["nodes"]} >= {"c", "d", "a", "b"}
    fig = build_figure(g, highlight=c_id)
    assert len(fig.data) >= 2


def test_table_fallback_threshold_is_defined():
    assert TABLE_FALLBACK_NODES >= 100
