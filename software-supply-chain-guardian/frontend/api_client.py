"""Thin HTTP client used by the dashboard. Kept separate so it can be tested without Streamlit."""
from __future__ import annotations

from typing import Any, Optional

import httpx


class ApiError(Exception):
    """Raised with a message that is safe to show to the user."""


class GuardianClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 150.0,
                 client: Optional[httpx.Client] = None) -> None:
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def _request(self, method: str, url: str, **kwargs) -> Any:
        try:
            resp = self._client.request(method, url, **kwargs)
        except httpx.ConnectError:
            raise ApiError("Cannot reach the backend. Start it with: uvicorn backend.main:app --port 8000")
        except httpx.TimeoutException:
            raise ApiError("The backend took too long to respond.")
        except httpx.HTTPError:
            raise ApiError("Network error while contacting the backend.")
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = None
            if isinstance(detail, list):  # FastAPI validation errors
                detail = "; ".join(str(d.get("msg", d)) for d in detail)
            raise ApiError(str(detail or f"Backend returned HTTP {resp.status_code}."))
        return resp.json()

    def health(self) -> dict:
        return self._request("GET", "/health")

    def info(self) -> dict:
        return self._request("GET", "/")

    def discover_files(self, files: list[tuple[str, bytes]]) -> dict:
        payload = [("files", (name, data, "application/octet-stream")) for name, data in files]
        return self._request("POST", "/api/discover/file", files=payload)

    def discover_repository(self, url: str) -> dict:
        return self._request("POST", "/api/discover/repository", json={"url": url})

    def get_graph(self, analysis_id: str) -> dict:
        return self._request("GET", f"/api/discovery/{analysis_id}/graph")

    def get_sbom(self, analysis_id: str) -> Optional[dict]:
        try:
            return self._request("GET", f"/api/discovery/{analysis_id}/sbom")
        except ApiError:
            return None
