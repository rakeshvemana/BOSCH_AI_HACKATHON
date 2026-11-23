import json

import pytest

from backend.services.discovery_service import discover_uploads
from backend.utils.file_utils import FileValidationError


def _lock_v3(packages):
    return json.dumps({"name": "demo", "lockfileVersion": 3, "packages": packages}).encode()


def test_package_json_only_gives_direct_deps_with_unresolved_ranges():
    pj = json.dumps({"name": "demo", "dependencies": {"express": "4.18.2", "lodash": "^4.17.21"}, "devDependencies": {"mocha": "~10.0.0"}}).encode()
    res, _ = discover_uploads({"package.json": pj})
    by = {c.name: c for c in res.components}
    assert by["express"].version == "4.18.2" and by["express"].version_status == "pinned"
    assert by["lodash"].version is None and by["lodash"].declared_constraint == "^4.17.21"
    assert by["mocha"].scope == "dev"
    assert all(c.dependency_type == "direct" for c in res.components)
    assert res.summary.transitive_dependencies == 0 and res.summary.transitive_resolution == "none"
    assert any("package-lock.json" in l for l in res.limitations)


def test_real_lockfile_separates_direct_from_transitive(samples):
    res, _ = discover_uploads(samples("javascript-sample", "package.json", "package-lock.json"))
    by = {c.name: c for c in res.components}
    assert {n for n, c in by.items() if c.dependency_type == "direct"} == {"express", "lodash", "mocha"}
    assert res.summary.transitive_dependencies > 100  # lockfile has the full tree
    assert by["express"].version == "4.18.2" and by["express"].version_status == "resolved"
    assert by["lodash"].declared_constraint == "^4.17.21" and by["lodash"].version.startswith("4.")  # declared vs resolved
    assert by["body-parser"].dependency_type == "transitive"
    assert any(r.source == by["express"].id and r.target == by["body-parser"].id for r in res.relationships)
    assert res.summary.unresolved_dependencies == 0


def test_lockfile_alone_uses_root_entry_for_direct_deps(samples):
    res, _ = discover_uploads(samples("javascript-sample", "package-lock.json"))
    assert {c.name for c in res.components if c.dependency_type == "direct"} == {"express", "lodash", "mocha"}


def test_nested_node_modules_resolution_and_shared_dependency():
    packages = {
        "": {"name": "demo", "dependencies": {"a": "^1", "b": "^1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^2"}},
        "node_modules/c": {"version": "1.5.0"},
        "node_modules/b/node_modules/c": {"version": "2.1.0"},  # b needs its own copy of c
    }
    res, _ = discover_uploads({"package-lock.json": _lock_v3(packages)})
    ids = {(c.name, c.version): c.id for c in res.components}
    edges = {(r.source, r.target) for r in res.relationships}
    assert (ids["a", "1.0.0"], ids["c", "1.5.0"]) in edges
    assert (ids["b", "1.0.0"], ids["c", "2.1.0"]) in edges          # nearest node_modules wins
    assert (ids["b", "1.0.0"], ids["c", "1.5.0"]) not in edges
    assert len(res.components) == 4
    assert {c.version for c in res.components if c.name == "c"} == {"1.5.0", "2.1.0"}


def test_same_package_via_two_paths_is_one_node():
    packages = {
        "": {"dependencies": {"a": "1", "b": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1"}},
        "node_modules/c": {"version": "1.0.0"},
    }
    res, _ = discover_uploads({"package-lock.json": _lock_v3(packages)})
    assert len([c for c in res.components if c.name == "c"]) == 1
    c_id = next(c.id for c in res.components if c.name == "c")
    assert len([r for r in res.relationships if r.target == c_id]) == 2


def test_dependency_cycle_is_handled():
    packages = {
        "": {"dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
    }
    res, _ = discover_uploads({"package-lock.json": _lock_v3(packages)})
    assert len(res.components) == 2 and len(res.relationships) == 3  # root->a, a->b, b->a


def test_lockfile_v1_relationships():
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "^1"}},
        "b": {"version": "1.2.0"},
    }}
    pj = {"name": "demo", "dependencies": {"a": "^1"}}
    res, _ = discover_uploads({"package-lock.json": json.dumps(lock).encode(), "package.json": json.dumps(pj).encode()})
    by = {c.name: c for c in res.components}
    assert by["a"].dependency_type == "direct" and by["b"].dependency_type == "transitive"
    assert any(r.source == by["a"].id and r.target == by["b"].id for r in res.relationships)


def test_declared_but_missing_from_lock_is_unresolved():
    packages = {"": {"dependencies": {"a": "1"}}, "node_modules/a": {"version": "1.0.0"}}
    pj = json.dumps({"name": "x", "dependencies": {"a": "1", "ghost": "^3"}}).encode()
    res, _ = discover_uploads({"package-lock.json": _lock_v3(packages), "package.json": pj})
    ghost = next(c for c in res.components if c.name == "ghost")
    assert ghost.version is None and any("ghost" in w for w in res.warnings)


def test_scoped_package_purl():
    pj = json.dumps({"dependencies": {"@types/node": "20.1.0"}}).encode()
    res, _ = discover_uploads({"package.json": pj})
    assert res.components[0].purl == "pkg:npm/%40types/node@20.1.0"


def test_invalid_json_rejected():
    with pytest.raises(FileValidationError) as e:
        discover_uploads({"package.json": b"{not json"})
    assert e.value.status_code == 422


@pytest.mark.parametrize("name", ["yarn.lock", "pnpm-lock.yaml"])
def test_unsupported_lockfiles_are_reported_not_silently_skipped(name):
    with pytest.raises(FileValidationError) as e:
        discover_uploads({name: b"# lock"})
    assert e.value.status_code == 415 and "not yet supported" in str(e.value).lower()
