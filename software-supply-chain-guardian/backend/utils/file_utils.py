"""Small, security-focused file helpers.

We never write uploaded content to disk: files are decoded in memory and parsed
as DATA. That alone removes most path traversal and code-execution risks. The
helpers below add defence in depth.
"""
from __future__ import annotations

import posixpath
import re
from typing import Optional

from backend.models import SupportLevel


class FileValidationError(ValueError):
    """Raised for input that is unsafe or unsupported. Message is safe to show users."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


# format id -> (support level, human description)
FORMAT_REGISTRY: dict[str, tuple[SupportLevel, str]] = {
    "requirements.txt": (SupportLevel.PARTIAL, "Direct dependencies only; exact '==' pins are shown as pinned versions. No transitive resolution."),
    "pyproject.toml": (SupportLevel.PARTIAL, "Direct dependencies (PEP 621 and Poetry). Constraints only; versions unresolved unless a lockfile is supplied."),
    "poetry.lock": (SupportLevel.FULL, "Resolved versions and dependency relationships. Direct/transitive split needs pyproject.toml alongside; otherwise top-level packages are 'unknown'."),
    "uv.lock": (SupportLevel.FULL, "Resolved versions, relationships and direct dependencies of the project."),
    "package.json": (SupportLevel.PARTIAL, "Direct dependencies only. Ranges are unresolved without a lockfile."),
    "package-lock.json": (SupportLevel.FULL, "lockfileVersion 2/3 fully; v1 supported for relationships (direct deps need package.json)."),
    "yarn.lock": (SupportLevel.NONE, "Not yet supported: recognised but not parsed. Use package-lock.json instead."),
    "pnpm-lock.yaml": (SupportLevel.NONE, "Not yet supported: recognised but not parsed. Use package-lock.json instead."),
    "pom.xml": (SupportLevel.PARTIAL, "Declared dependencies only (no transitive tree). Versions from parent POMs/BOMs are unresolved."),
    "cyclonedx": (SupportLevel.FULL, "CycloneDX JSON import: components and dependency graph as provided."),
    "spdx": (SupportLevel.PARTIAL, "SPDX 2.x JSON import: packages and DEPENDS_ON relationships."),
    "Dockerfile": (SupportLevel.PARTIAL, "Static metadata only: base images, installs, copied files. Not a list of installed OS packages."),
}

ECOSYSTEM_OF_FORMAT = {
    "requirements.txt": "pypi", "pyproject.toml": "pypi", "poetry.lock": "pypi", "uv.lock": "pypi",
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "pom.xml": "maven", "Dockerfile": "docker",
}

_SKIP_DIRS = {
    "node_modules", "vendor", "third_party", "venv", ".venv", "env", "site-packages",
    ".git", "dist", "build", "__pycache__", ".tox", "target",
}


def safe_basename(name: str) -> str:
    """Return only the final path component of a user-supplied file name."""
    name = (name or "").replace("\\", "/")
    base = posixpath.basename(name)
    base = re.sub(r"[\x00-\x1f]", "", base).strip()
    return base[:200]


def safe_relative_path(path: str) -> str:
    """Normalise a repo-relative path and reject traversal / absolute paths."""
    p = (path or "").replace("\\", "/")
    if "\x00" in p or p.startswith("/"):
        raise FileValidationError("Unsafe file path rejected.")
    norm = posixpath.normpath(p)
    if norm.startswith("..") or norm == "." or "/../" in f"/{norm}/":
        raise FileValidationError("Unsafe file path rejected.")
    return norm


def classify_file(path: str, content_head: Optional[str] = None) -> Optional[str]:
    """Return a FORMAT_REGISTRY key for a file, or None if unrecognised.

    ``content_head`` (the first chunk of the file) is used to tell SBOM JSON
    documents apart from arbitrary JSON.
    """
    base = posixpath.basename(path)
    low = base.lower()
    if low in {"requirements.txt"} or (low.startswith("requirements") and low.endswith(".txt")):
        return "requirements.txt"
    if posixpath.basename(posixpath.dirname(path)).lower() in {"requirements", "reqs"} and low.endswith(".txt"):
        return "requirements.txt"
    exact = {
        "pyproject.toml": "pyproject.toml", "poetry.lock": "poetry.lock", "uv.lock": "uv.lock",
        "package.json": "package.json", "package-lock.json": "package-lock.json",
        "npm-shrinkwrap.json": "package-lock.json",
        "yarn.lock": "yarn.lock", "pnpm-lock.yaml": "pnpm-lock.yaml", "pom.xml": "pom.xml",
    }
    if low in exact:
        return exact[low]
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return "Dockerfile"
    if low.endswith(".json"):
        head = content_head or ""
        if '"bomFormat"' in head and "CycloneDX" in head:
            return "cyclonedx"
        if '"spdxVersion"' in head:
            return "spdx"
        if low in {"bom.json", "sbom.json"} or low.endswith((".cdx.json", ".spdx.json")):
            return "cyclonedx" if not low.endswith(".spdx.json") else "spdx"
    return None


def is_skipped_repo_path(path: str) -> bool:
    return any(part in _SKIP_DIRS for part in path.split("/")[:-1])


def decode_text(data: bytes, filename: str = "file") -> str:
    """Decode bytes as UTF-8 (BOM tolerated); reject binary content."""
    if b"\x00" in data[:8192]:
        raise FileValidationError(f"'{filename}' looks like a binary file, not a text dependency file.", 415)
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise FileValidationError(f"'{filename}' is not valid UTF-8 text.", 415)
