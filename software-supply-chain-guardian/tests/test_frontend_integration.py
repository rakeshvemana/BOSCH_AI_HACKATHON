"""Frontend <-> backend integration without a network: the API client talks to the FastAPI app in-process."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.services.storage_service import AnalysisStore
from frontend.api_client import ApiError, GuardianClient

APP = str(Path(__file__).resolve().parent.parent / "frontend" / "app.py")


@pytest.fixture
def api(tmp_path, local_repo_service):
    svc = local_repo_service({"requirements.txt": "Flask==2.2.2\nrequests==2.28.0\n", "package.json": '{"dependencies":{"left-pad":"1.3.0"}}'})
    return create_app(store=AnalysisStore(tmp_path / "fe.db"), repo_service=svc)


def test_client_full_flow(api, samples):
    c = GuardianClient(client=TestClient(api))
    assert c.health()["status"] == "ok" and c.info()["name"] == "Software Supply Chain Guardian"
    files = samples("python-uv-sample", "pyproject.toml", "uv.lock")
    result = c.discover_files(list(files.items()))
    graph, sbom = c.get_graph(result["analysis_id"]), c.get_sbom(result["analysis_id"])
    assert graph["stats"]["nodes"] == result["summary"]["total_components"] + 1
    assert sbom["bomFormat"] == "CycloneDX"


def test_client_surfaces_backend_errors_as_readable_messages(api):
    c = GuardianClient(client=TestClient(api))
    with pytest.raises(ApiError, match="Unsupported file type"):
        c.discover_files([("setup.py", b"print(1)")])
    with pytest.raises(ApiError, match="github.com"):
        c.discover_repository("https://evil.example/a/b")
    with pytest.raises(ApiError, match="not found"):
        c.get_graph("deadbeef")
    assert c.get_sbom("deadbeef") is None


def test_client_reports_unreachable_backend():
    c = GuardianClient("http://127.0.0.1:9", timeout=1)
    with pytest.raises(ApiError, match="Cannot reach the backend"):
        c.health()


def test_streamlit_app_renders_results_end_to_end(api, monkeypatch):
    """Runs the real dashboard script headlessly against the in-process API."""
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    monkeypatch.setattr("frontend.api_client.httpx.Client", lambda **kw: TestClient(api))
    st.cache_resource.clear()

    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    at.text_input[0].set_value("https://github.com/octo/demo")
    at.button[0].click().run()
    assert not at.exception, [e.value for e in at.exception]
    headers = [h.value for h in at.header]
    assert any(h.startswith("A") for h in headers) and any(h.startswith("F") for h in headers)
    assert {"C · What appears risky", "D · What changed", "H · Export"} <= set(headers)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Total components"] == "3" and metrics["Direct"] == "3"
    assert metrics["What changed"] == "first scan"
    assert not at.error
    # second scan of the same repo: 'what changed' now compares against the first
    at.button[0].click().run()
    assert not at.exception
    assert {m.label: m.value for m in at.metric}["What changed"] == "0 change(s)"


def test_streamlit_app_shows_friendly_error_for_bad_url(api, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    monkeypatch.setattr("frontend.api_client.httpx.Client", lambda **kw: TestClient(api))
    st.cache_resource.clear()
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_input[0].set_value("https://evil.example/a/b")
    at.button[0].click().run()
    assert not at.exception and any("github.com" in e.value for e in at.error)
