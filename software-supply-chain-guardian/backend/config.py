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
    stage = "Stage 1 - Software Supply Chain Discovery"

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
    def syft_enabled(self) -> bool:
        return os.environ.get("SSC_ENABLE_SYFT", "false").lower() in {"1", "true", "yes"}


settings = Settings()
