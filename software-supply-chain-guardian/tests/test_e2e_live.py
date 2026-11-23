"""OPTIONAL live end-to-end test. Needs internet access to github.com.

Run explicitly with:   pytest tests/test_e2e_live.py --run-e2e
"""
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.services import sbom_service
from backend.services.storage_service import AnalysisStore

pytestmark = pytest.mark.e2e


def test_public_repository_analysis(tmp_path):
    client = TestClient(create_app(store=AnalysisStore(tmp_path / "live.db")))
    r = client.post("/api/discover/repository", json={"url": "https://github.com/pallets/click"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["project_name"] == "pallets/click" and body["summary"]["total_components"] > 0
    assert any(f["format"] == "pyproject.toml" for f in body["files"])
    sbom = client.get(f"/api/discovery/{body['analysis_id']}/sbom").json()
    assert sbom_service.validate_cyclonedx(sbom) == []
    assert client.get(f"/api/discovery/{body['analysis_id']}/graph").status_code == 200
