"""Central configuration. All limits can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Settings:
    app_name = "Software Supply Chain Guardian"
    app_version = "0.1.0"
    stage = "Day 1 - Discovery, detection and evidence"

    @property
    def max_upload_bytes(self) -> int:
        return _int("SSC_MAX_UPLOAD_BYTES", 5 * 1024 * 1024)

    @property
    def max_upload_files(self) -> int:
        return _int("SSC_MAX_UPLOAD_FILES", 10)

    @property
    def git_timeout_seconds(self) -> int:
        return _int("SSC_GIT_TIMEOUT_SECONDS", 90)

    @property
    def max_repo_files(self) -> int:
        return _int("SSC_MAX_REPO_FILES", 60)

    @property
    def max_repo_file_bytes(self) -> int:
        return _int("SSC_MAX_REPO_FILE_BYTES", 5 * 1024 * 1024)

    @property
    def db_path(self) -> Path:
        p = Path(os.environ.get("SSC_DB_PATH", "data/analyses.db"))
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def max_stored_analyses(self) -> int:
        return _int("SSC_MAX_STORED_ANALYSES", 200)

    @property
    def vuln_scan_enabled(self) -> bool:
        """Known-vulnerability lookup against OSV.dev (sends package names + versions, nothing else)."""
        return os.environ.get("SSC_VULN_SCAN", "true").lower() in {"1", "true", "yes"}

    @property
    def osv_url(self) -> str:
        return os.environ.get("SSC_OSV_URL", "https://api.osv.dev")

    @property
    def vuln_timeout_seconds(self) -> int:
        return _int("SSC_VULN_TIMEOUT_SECONDS", 45)

    @property
    def syft_enabled(self) -> bool:
        return os.environ.get("SSC_ENABLE_SYFT", "false").lower() in {"1", "true", "yes"}


settings = Settings()
