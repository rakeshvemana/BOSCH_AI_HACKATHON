import json

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.models import DiscoveryResult, GraphResponse
from backend.services import sbom_service
from backend.services.repository_service import RepositoryService
from backend.services.storage_service import AnalysisStore


@pytest.fixture
def client(tmp_path):
    app = create_app(store=AnalysisStore(tmp_path / "t.db"), repo_service=RepositoryService())
    return TestClient(app, raise_server_exceptions=False)


def upload(client, **files):
    return client.post("/api/discover/file", files=[("files", (n, c, "application/octet-stream")) for n, c in files.items()])


def test_root_and_health(client):
    r = client.get("/")
    assert r.status_code == 200 and r.json()["name"] == "Software Supply Chain Guardian"
    levels = {f["format"]: f["support_level"] for f in r.json()["supported_formats"]}
    assert levels["uv.lock"] == "Fully supported" and levels["yarn.lock"] == "Not yet supported"
    assert levels["requirements.txt"] == "Partially supported"
    assert client.get("/health").json()["status"] == "ok"


def test_upload_flow_result_graph_sbom(client, samples):
    r = upload(client, **{"requirements.txt": samples("python-sample", "requirements.txt")["requirements.txt"]})
    assert r.status_code == 200
    result = DiscoveryResult.model_validate(r.json())          # response matches the schema
    assert result.summary.direct_dependencies == 4 and result.input_type == "file"

    again = client.get(f"/api/discovery/{result.analysis_id}")
    assert again.status_code == 200 and again.json()["analysis_id"] == result.analysis_id

    g = client.get(f"/api/discovery/{result.analysis_id}/graph")
    graph = GraphResponse.model_validate(g.json())
    assert graph.stats.nodes == 5 and graph.stats.edges == 4

    s = client.get(f"/api/discovery/{result.analysis_id}/sbom")
    assert s.status_code == 200 and s.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert sbom_service.validate_cyclonedx(s.json()) == []


def test_multi_file_upload_pairs_manifest_and_lock(client, samples):
    files = samples("javascript-sample", "package.json", "package-lock.json")
    r = upload(client, **files)
    assert r.status_code == 200 and r.json()["summary"]["transitive_resolution"] == "full-from-lockfile"
    assert r.json()["summary"]["transitive_dependencies"] > 100


def test_unknown_analysis_id_404(client):
    for path in ("", "/graph", "/sbom"):
        assert client.get(f"/api/discovery/deadbeef{path}").status_code == 404
    assert client.get("/api/discovery/..%2F..%2Fetc/graph").status_code == 404


def test_unsupported_file_type_415(client):
    assert upload(client, **{"malware.exe": b"MZ\x90\x00"}).status_code == 415          # binary
    r = upload(client, **{"setup.py": b"print('would execute if we were careless')"})
    assert r.status_code == 415 and "Unsupported file type" in r.json()["detail"]
    assert upload(client, **{"notes.txt": b"hello"}).status_code == 415
    assert upload(client, **{"yarn.lock": b"# yarn"}).status_code == 415


def test_binary_content_rejected(client):
    assert upload(client, **{"requirements.txt": b"\x00\x01\x02binary"}).status_code == 415


def test_upload_size_limit_413(client, monkeypatch):
    monkeypatch.setenv("SSC_MAX_UPLOAD_BYTES", "1000")
    r = upload(client, **{"requirements.txt": b"a==1\n" * 500})
    assert r.status_code == 413 and "too large" in r.json()["detail"].lower()
    assert upload(client, **{"requirements.txt": b"a==1\n"}).status_code == 200


def test_too_many_files_413(client, monkeypatch):
    monkeypatch.setenv("SSC_MAX_UPLOAD_FILES", "1")
    r = upload(client, **{"requirements.txt": b"a==1\n", "package.json": b"{}"})
    assert r.status_code == 413


def test_invalid_requirements_file_422(client):
    r = upload(client, **{"requirements.txt": b"!!! nothing valid !!!\n"})
    assert r.status_code == 422 and "No dependencies could be extracted" in r.json()["detail"]


def test_malformed_json_422_and_no_internal_details(client):
    r = upload(client, **{"package.json": b"{oops"})
    assert r.status_code == 422 and "/" not in r.json()["detail"].replace("package.json", "")


def test_path_traversal_filename_is_neutralised(client):
    r = upload(client, **{"../../etc/requirements.txt": b"Flask==2.2.2\n"})
    assert r.status_code == 200
    assert all(f["path"] == "requirements.txt" for f in r.json()["files"])


def test_no_file_uploaded_422(client):
    assert client.post("/api/discover/file").status_code == 422


@pytest.mark.parametrize("url", ["http://localhost/a/b", "https://169.254.169.254/x/y", "https://evil.com/a/b", "nonsense", ""])
def test_repository_rejects_unsafe_urls_400(client, url):
    r = client.post("/api/discover/repository", json={"url": url})
    assert r.status_code in (400, 422)


def test_repository_failure_surfaces_cleanly(tmp_path):
    svc = RepositoryService(remote_override=lambda r: f"file://{tmp_path}/missing", extra_git_config=["protocol.file.allow=always"])
    c = TestClient(create_app(store=AnalysisStore(tmp_path / "d.db"), repo_service=svc), raise_server_exceptions=False)
    r = c.post("/api/discover/repository", json={"url": "https://github.com/o/r"})
    assert r.status_code in (404, 502) and str(tmp_path) not in r.text


def test_repository_analysis_end_to_end_with_local_git(tmp_path, local_repo_service):
    svc = local_repo_service({"requirements.txt": "Flask==2.2.2\nrequests==2.28.0\n", "Dockerfile": "FROM python:3.12-slim\n"})
    c = TestClient(create_app(store=AnalysisStore(tmp_path / "e.db"), repo_service=svc))
    r = c.post("/api/discover/repository", json={"url": "https://github.com/octo/demo"})
    assert r.status_code == 200
    body = r.json()
    assert body["project_name"] == "octo/demo" and body["input_type"] == "repository" and body["summary"]["total_components"] == 3
    assert c.get(f"/api/discovery/{body['analysis_id']}/graph").status_code == 200
    assert c.get(f"/api/discovery/{body['analysis_id']}/sbom").status_code == 200


def test_unexpected_errors_do_not_leak_internals(tmp_path, monkeypatch):
    from backend.services import discovery_service
    monkeypatch.setattr(discovery_service, "discover_uploads", lambda u: (_ for _ in ()).throw(RuntimeError("secret /Users/x/path")))
    c = TestClient(create_app(store=AnalysisStore(tmp_path / "f.db")), raise_server_exceptions=False)
    r = upload(c, **{"requirements.txt": b"a==1"})
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error."}


def test_image_scan_requires_approval_and_is_disabled_by_default(client):
    assert client.post("/api/discover/image", json={"image": "alpine:3.19"}).status_code == 400
    r = client.post("/api/discover/image", json={"image": "alpine:3.19", "approve": True})
    assert r.status_code == 422 and "disabled" in r.json()["detail"]


def test_storage_is_bounded(tmp_path):
    store = AnalysisStore(tmp_path / "b.db", max_items=3)
    c = TestClient(create_app(store=store))
    ids = [upload(c, **{"requirements.txt": b"a==1\n"}).json()["analysis_id"] for _ in range(6)]
    assert store.count() == 3
    assert c.get(f"/api/discovery/{ids[-1]}").status_code == 200 and c.get(f"/api/discovery/{ids[0]}").status_code == 404
