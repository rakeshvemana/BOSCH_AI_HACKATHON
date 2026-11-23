"""FastAPI backend for Software Supply Chain Guardian (Stage 1: discovery).

Run:  uvicorn backend.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.models import (
    AppInfo, DiscoveryResult, Finding, GraphResponse, HealthResponse, ImageRequest, RepositoryRequest,
    TriageReport,
)
from backend.services import agent_service, discovery_service, risk_service, sbom_service
from backend.services.graph_service import graph_response
from backend.services.repository_service import RepositoryService
from backend.services.storage_service import AnalysisStore
from backend.utils.file_utils import FileValidationError

log = logging.getLogger("ssc-guardian")


def create_app(store: Optional[AnalysisStore] = None, repo_service: Optional[RepositoryService] = None,
               llm: Optional[agent_service.LLM] = None) -> FastAPI:
    app = FastAPI(title=settings.app_name, version=settings.app_version,
                  description="Day 1: discover the software supply chain (dependencies, graph, SBOM), detect known "
                              "vulnerabilities and suspicious changes, and present the evidence.")
    app.state.store = store or AnalysisStore()
    app.state.repo_service = repo_service or RepositoryService()
    app.state.llm = llm  # tests inject a fake; otherwise a DeepSeek client is built per request from the environment

    # ------------------------------------------------------------ error handling
    @app.exception_handler(FileValidationError)
    async def _validation_handler(_req: Request, exc: FileValidationError):
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.exception_handler(sbom_service.SbomError)
    async def _sbom_handler(_req: Request, exc: sbom_service.SbomError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def _unexpected(_req: Request, exc: Exception):
        # Log details server-side only; never leak paths or internals to the client.
        log.exception("Unhandled error")
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    def _store() -> AnalysisStore:
        return app.state.store

    def _load(analysis_id: str) -> DiscoveryResult:
        if not analysis_id.isalnum() or len(analysis_id) > 64:
            raise HTTPException(404, "Analysis not found.")
        res = _store().get(analysis_id)
        if res is None:
            raise HTTPException(404, "Analysis not found.")
        return res

    # ------------------------------------------------------------------ routes
    @app.get("/", response_model=AppInfo)
    def root() -> AppInfo:
        return AppInfo(name=settings.app_name, version=settings.app_version, stage=settings.stage,
                       supported_formats=discovery_service.supported_formats())

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(version=settings.app_version)

    @app.post("/api/discover/file", response_model=DiscoveryResult)
    async def discover_file(files: list[UploadFile] = File(..., description="One or more dependency files / SBOMs")):
        if not files:
            raise FileValidationError("No file uploaded.")
        if len(files) > settings.max_upload_files:
            raise FileValidationError(f"Too many files (max {settings.max_upload_files}).", 413)
        limit = settings.max_upload_bytes
        uploads: dict[str, bytes] = {}
        for f in files:
            data = await f.read(limit + 1)  # never read more than limit+1 bytes
            if len(data) > limit:
                raise FileValidationError(f"File too large (limit {limit // (1024 * 1024)} MB).", 413)
            uploads[f.filename or ""] = data
        result, sbom = await run_in_threadpool(discovery_service.discover_uploads, uploads)
        await run_in_threadpool(_save, result, sbom)
        return result

    def _save(result: DiscoveryResult, sbom) -> None:
        """Compare with the previous analysis of the same source ('what changed'), then store."""
        previous = _store().previous(result)
        if previous is not None:
            result.changes, change_findings = risk_service.compare(previous, result)
            risk_service.finalize(result, [*result.findings, *change_findings])
        _store().save(result, sbom)

    @app.post("/api/discover/repository", response_model=DiscoveryResult)
    def discover_repository(req: RepositoryRequest):
        repo_files = app.state.repo_service.fetch_files(req.url)
        result, sbom = discovery_service.discover_repository(repo_files)
        _save(result, sbom)
        return result

    @app.post("/api/discover/image", response_model=DiscoveryResult)
    def discover_image(req: ImageRequest):
        """Optional deep container scan with Syft. Disabled by default; needs explicit approval."""
        if not req.approve:
            raise FileValidationError("Image scanning needs explicit approval (approve=true).", 400)
        doc = sbom_service.run_syft(req.image)
        result, sbom = discovery_service.discover_image(doc, req.image)
        _save(result, sbom)
        return result

    @app.get("/api/discovery/{analysis_id}", response_model=DiscoveryResult)
    def get_discovery(analysis_id: str):
        return _load(analysis_id)

    @app.get("/api/discovery/{analysis_id}/findings", response_model=list[Finding])
    def get_findings(analysis_id: str):
        """Vulnerabilities and suspicious signals, highest initial risk first, each with its evidence."""
        return _load(analysis_id).findings

    @app.post("/api/discovery/{analysis_id}/triage", response_model=TriageReport)
    async def triage(analysis_id: str):
        """AI triage: an agent investigates the findings with read-only tools and gives a verdict on each.

        Sends package names/versions, finding titles and file paths to the configured LLM (DeepSeek).
        """
        result = _load(analysis_id)
        llm_fn, model = app.state.llm, "injected"
        if llm_fn is None:
            if not settings.deepseek_api_key:
                raise HTTPException(503, "AI triage is not configured: set DEEPSEEK_API_KEY in the backend's environment.")
            llm_fn = agent_service.DeepSeekClient()
            model = llm_fn.model
        try:
            return await run_in_threadpool(agent_service.run_triage, result, llm_fn, model)
        except agent_service.LLMError as exc:
            raise HTTPException(502, str(exc))

    @app.get("/api/discovery/{analysis_id}/graph", response_model=GraphResponse)
    def get_graph(analysis_id: str):
        return graph_response(_load(analysis_id))

    @app.get("/api/discovery/{analysis_id}/sbom", response_model=dict[str, Any])
    def get_sbom(analysis_id: str):
        _load(analysis_id)
        doc = _store().get_sbom(analysis_id)
        if doc is None:
            raise HTTPException(404, "No SBOM was generated for this analysis (no components discovered).")
        return JSONResponse(content=doc, media_type="application/vnd.cyclonedx+json")

    return app


app = create_app()
