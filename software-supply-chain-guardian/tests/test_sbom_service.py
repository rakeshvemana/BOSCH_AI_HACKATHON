import json

import pytest

from backend.services import sbom_service
from backend.services.discovery_service import discover_uploads
from backend.utils.file_utils import FileValidationError

SPDX = {
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "demo",
    "packages": [
        {"SPDXID": "SPDXRef-app", "name": "demo-app", "versionInfo": "1.0"},
        {"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1.0.0",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/a@1.0.0"}]},
        {"SPDXID": "SPDXRef-b", "name": "b", "versionInfo": "NOASSERTION"},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
        {"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a"},
        {"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-b"},
    ],
}


def test_generated_sbom_is_valid_cyclonedx_1_6(samples):
    res, sbom = discover_uploads(samples("python-uv-sample", "pyproject.toml", "uv.lock"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.6"
    assert sbom_service.validate_cyclonedx(sbom) == []
    assert len(sbom["components"]) == len(res.components)
    flask = next(c for c in sbom["components"] if c["name"] == "flask")
    assert flask["purl"] == "pkg:pypi/flask@2.2.2" and flask["version"] == "2.2.2"
    dep_refs = {d["ref"]: d.get("dependsOn", []) for d in sbom["dependencies"]}
    assert "pkg:pypi/flask@2.2.2" in dep_refs["root-application"]
    assert any("werkzeug" in r for r in dep_refs["pkg:pypi/flask@2.2.2"])
    assert res.sbom_status.endswith("(complete from lockfile)")


def test_unresolved_versions_are_never_invented_and_sbom_is_labelled_partial():
    res, sbom = discover_uploads({"requirements.txt": b"requests\nFlask==2.2.2\n"})
    req = next(c for c in sbom["components"] if c["name"] == "requests")
    assert "version" not in req and req["purl"] == "pkg:pypi/requests"
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    assert props["ssc-guardian:completeness"] == "partial" and "PARTIAL" in res.sbom_status
    assert sbom_service.validate_cyclonedx(sbom) == []


def test_validator_rejects_invalid_documents():
    assert sbom_service.validate_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "x"}]})
    assert sbom_service.validate_cyclonedx({"bomFormat": "nope"})


def test_maven_and_docker_purls_in_sbom(samples):
    _, sbom = discover_uploads(samples("java-sample", "pom.xml"))
    assert sbom_service.validate_cyclonedx(sbom) == []
    jack = next(c for c in sbom["components"] if c["name"] == "jackson-databind")
    assert jack["group"] == "com.fasterxml.jackson.core" and jack["purl"].startswith("pkg:maven/com.fasterxml.jackson.core/jackson-databind@")
    _, dsbom = discover_uploads(samples("docker-sample", "Dockerfile"))
    assert sbom_service.validate_cyclonedx(dsbom) == []
    assert any(c["type"] == "container" for c in dsbom["components"])


def test_cyclonedx_roundtrip_import(samples):
    res, sbom = discover_uploads(samples("python-uv-sample", "pyproject.toml", "uv.lock"))
    imp, _ = discover_uploads({"bom.json": json.dumps(sbom).encode()})
    assert {c.id for c in imp.components} == {c.id for c in res.components}
    assert {(r.source, r.target) for r in imp.relationships if r.source != "root"} == \
           {(r.source, r.target) for r in res.relationships if r.source != "root"}
    assert imp.project_name == "python-uv-sample"
    assert {c.id for c in imp.components if c.dependency_type == "direct"} == {c.id for c in res.components if c.dependency_type == "direct"}
    assert imp.files[0].format == "cyclonedx"


def test_cyclonedx_without_dependencies_section_is_honest():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "components": [{"type": "library", "name": "x", "version": "1.0", "purl": "pkg:npm/x@1.0"}]}
    res, _ = discover_uploads({"sbom.json": json.dumps(doc).encode()})
    assert res.components[0].dependency_type == "unknown" and res.components[0].ecosystem == "npm"
    assert any("no 'dependencies' section" in l for l in res.limitations)


def test_spdx_import():
    res, _ = discover_uploads({"app.spdx.json": json.dumps(SPDX).encode()})
    by = {c.name: c for c in res.components}
    assert res.project_name == "demo-app" and by["a"].dependency_type == "direct" and by["b"].dependency_type == "transitive"
    assert by["b"].version is None            # NOASSERTION is not a version
    assert any(r.source == by["a"].id and r.target == by["b"].id for r in res.relationships)
    assert by["a"].ecosystem == "pypi"


@pytest.mark.parametrize("payload", [b"{broken", b"[1,2]", b'{"hello": "world", "bomFormat": "CycloneDXX"}'])
def test_invalid_sbom_inputs(payload):
    with pytest.raises(FileValidationError):
        discover_uploads({"bom.json": payload})


def test_syft_is_disabled_by_default_and_needs_installation(monkeypatch):
    with pytest.raises(sbom_service.SbomError, match="disabled"):
        sbom_service.run_syft("alpine:3.19")
    monkeypatch.setenv("SSC_ENABLE_SYFT", "true")
    monkeypatch.setattr(sbom_service.shutil, "which", lambda _n: None)
    with pytest.raises(sbom_service.SbomError, match="not installed"):
        sbom_service.run_syft("alpine:3.19")
    monkeypatch.setattr(sbom_service.shutil, "which", lambda _n: "/usr/bin/syft")
    for bad in ("--help", "/etc/passwd", "dir:/", "a b; rm -rf /"):
        with pytest.raises(sbom_service.SbomError, match="Invalid"):
            sbom_service.run_syft(bad)
