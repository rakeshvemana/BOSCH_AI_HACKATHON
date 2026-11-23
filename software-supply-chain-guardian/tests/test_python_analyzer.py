import pytest

from backend.analyzers.python_analyzer import PythonAnalyzer, parse_pyproject, parse_requirements_text
from backend.services.discovery_service import discover_uploads
from backend.utils.file_utils import FileValidationError

POETRY_LOCK = '''
[[package]]
name = "app-lib-a"
version = "1.0.0"

[package.dependencies]
shared = ">=2.0"

[[package]]
name = "app-lib-b"
version = "3.1.0"

[package.dependencies]
shared = "*"
cyc = "*"

[[package]]
name = "shared"
version = "2.5.0"

[[package]]
name = "cyc"
version = "0.1.0"

[package.dependencies]
app-lib-b = "*"

[metadata]
lock-version = "2.0"
'''
PYPROJECT_POETRY = '''
[tool.poetry]
name = "demo"
[tool.poetry.dependencies]
python = "^3.10"
app-lib-a = "^1.0"
app-lib-b = "3.1.0"
[tool.poetry.group.dev.dependencies]
missing-pkg = "^9.0"
'''


def test_valid_requirements_parsing():
    reqs, warns = parse_requirements_text("Flask==2.2.2\nrequests[security]>=2.0; python_version>'3.8'\n# c\n\nnumpy == 1.24.0  # inline\n")
    assert warns == []
    by = {r.name: r for r in reqs}
    assert by["Flask"].pinned_version == "2.2.2"
    assert by["numpy"].pinned_version == "1.24.0"
    assert by["requests"].pinned_version is None
    assert by["requests"].extras == ["security"] and "python_version" in by["requests"].markers


def test_invalid_requirements_do_not_crash_and_are_reported():
    reqs, warns = parse_requirements_text("Flask==2.2.2\n!!!bad line!!!\n==1.0\ngit+https://example.com/x.git\n")
    assert [r.name for r in reqs] == ["Flask"]
    assert len(warns) == 3 and all("requirements.txt:" in w for w in warns)


def test_version_constraint_parsing_and_missing_version():
    reqs, _ = parse_requirements_text("a>=1.0,<2\nb\nc==1.*\nd~=1.4\ne===1.0\n")
    by = {r.name: r for r in reqs}
    assert set(by["a"].constraint.split(",")) == {">=1.0", "<2"}
    assert by["a"].pinned_version is None
    assert by["b"].constraint is None and by["b"].pinned_version is None
    assert by["c"].pinned_version is None  # wildcard is NOT a pin
    assert by["d"].pinned_version is None
    assert by["e"].pinned_version == "1.0"


def test_missing_version_is_unresolved_never_invented():
    res, _ = discover_uploads({"requirements.txt": b"requests\nflask>=2\n"})
    assert all(c.version is None and c.version_status == "unresolved" for c in res.components)
    assert res.summary.unresolved_dependencies == 2


def test_options_hashes_and_continuations():
    text = ("-r other.txt\n-e ./local\n--index-url https://example.org/simple\n"
            "pkg==1.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n")
    reqs, warns = parse_requirements_text(text)
    assert [r.name for r in reqs] == ["pkg"] and reqs[0].pinned_version == "1.0"
    assert any("not followed" in w for w in warns)
    assert any("editable" in w for w in warns)
    assert any("custom package index" in w for w in warns)


def test_duplicate_dependencies_are_merged():
    res, _ = discover_uploads({"requirements.txt": b"requests==2.28.0\nrequests==2.28.0\nFlask==2.2.2\n"})
    assert len(res.components) == 2


def test_direct_dependency_detection_requirements_only(samples):
    res, _ = discover_uploads(samples("python-sample", "requirements.txt"))
    assert {c.name for c in res.components} == {"Flask", "requests", "numpy", "PyYAML"}
    assert all(c.dependency_type == "direct" and c.version_status == "pinned" for c in res.components)
    assert res.summary.transitive_resolution == "none"
    assert any("transitive" in l.lower() for l in res.limitations)  # honest about the limitation


def test_pyproject_pep621_and_poetry():
    reqs, name, _ = parse_pyproject('[project]\nname="x"\ndependencies=["a>=1","b==2.0"]\n[project.optional-dependencies]\nweb=["c"]\n', "pyproject.toml")
    assert name == "x" and {r.name: r.scope for r in reqs} == {"a": "runtime", "b": "runtime", "c": "optional:web"}
    with pytest.raises(ValueError):
        parse_pyproject("not = [valid", "pyproject.toml")


def test_uv_lock_transitive_discovery(samples):
    res, _ = discover_uploads(samples("python-uv-sample", "pyproject.toml", "uv.lock"))
    by = {c.name: c for c in res.components}
    assert by["flask"].dependency_type == "direct" and by["flask"].version == "2.2.2"
    assert by["flask"].declared_constraint == "==2.2.2" and by["flask"].version_status == "resolved"
    assert by["werkzeug"].dependency_type == "transitive"
    flask_id, werk_id = by["flask"].id, by["werkzeug"].id
    assert any(r.source == flask_id and r.target == werk_id for r in res.relationships)
    assert res.summary.transitive_resolution == "full-from-lockfile"
    assert res.summary.unresolved_dependencies == 0


def test_poetry_lock_with_pyproject_multiple_paths_and_cycle():
    res, _ = discover_uploads({"pyproject.toml": PYPROJECT_POETRY.encode(), "poetry.lock": POETRY_LOCK.encode()})
    by = {c.name: c for c in res.components}
    assert by["app-lib-a"].dependency_type == "direct" and by["app-lib-b"].dependency_type == "direct"
    assert by["shared"].dependency_type == "transitive"
    parents = {r.source for r in res.relationships if r.target == by["shared"].id}
    assert parents == {by["app-lib-a"].id, by["app-lib-b"].id}  # one node, two dependency paths
    assert sum(1 for c in res.components if c.name == "shared") == 1
    # declared in pyproject but absent from lock => unresolved, flagged, never invented
    assert by["missing-pkg"].version is None and any("missing from the lockfile" in w for w in res.warnings)


def test_poetry_lock_alone_does_not_guess_direct():
    res, _ = discover_uploads({"poetry.lock": POETRY_LOCK.encode()})
    by = {c.name: c for c in res.components}
    assert by["shared"].dependency_type == "transitive"
    assert by["app-lib-a"].dependency_type == "unknown"  # nothing depends on it; NOT guessed as direct
    assert any("does not record which packages" in l for l in res.limitations)


def test_invalid_toml_is_rejected_with_safe_message():
    with pytest.raises(FileValidationError) as e:
        discover_uploads({"uv.lock": b"[[package\nbroken"})
    assert e.value.status_code == 422


def test_monorepo_with_one_unlocked_project_is_reported_as_partial(samples):
    """Honesty check: a manifest-only sub-project must stop the headline claiming full resolution."""
    from backend.services.discovery_service import discover
    files = {f"app/{n}": b for n, b in samples("python-uv-sample", "pyproject.toml", "uv.lock").items()}
    files["tools/requirements.txt"] = b"click==8.1.7\n"
    res, _ = discover(files, "repository", "https://github.com/o/r", "o/r")
    assert res.summary.transitive_resolution == "partial"
    assert any("tools" in l and "no lockfile" in l for l in res.limitations)
    only_locked, _ = discover({k: v for k, v in files.items() if k.startswith("app/")}, "repository", "x", "x")
    assert only_locked.summary.transitive_resolution == "full-from-lockfile"
