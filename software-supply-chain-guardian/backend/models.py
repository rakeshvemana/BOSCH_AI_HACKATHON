"""Pydantic data models shared by analyzers, services, the API and the dashboard.

Key idea for beginners
----------------------
A dependency has TWO different kinds of version information:

* ``declared_constraint`` - what a human wrote, e.g. ``requests>=2.0``.
* ``version`` - a concrete version, together with ``version_status`` which says
  HOW we know it:

  - ``resolved``   : taken from a lockfile / SBOM (the real answer).
  - ``pinned``     : an exact pin written in a manifest (``Flask==2.2.2``).
  - ``declared``   : a version written in a manifest that is not guaranteed to be
                     final (Maven soft version, mutable Docker tag).
  - ``unresolved`` : we do not know. ``version`` is then ``None``. We never guess.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

ROOT_ID = "root"

ECOSYSTEM_LABELS = {
    "pypi": "Python (PyPI)",
    "npm": "JavaScript (npm)",
    "maven": "Java (Maven)",
    "docker": "Container image",
    "os-package": "OS package",
    "other": "Other",
}

VersionStatus = Literal["resolved", "pinned", "declared", "unresolved"]
DependencyType = Literal["direct", "transitive", "unknown"]


class SupportLevel(str, Enum):
    FULL = "Fully supported"
    PARTIAL = "Partially supported"
    NONE = "Not yet supported"


class Component(BaseModel):
    id: str
    name: str
    ecosystem: str
    version: Optional[str] = None
    version_status: VersionStatus = "unresolved"
    declared_constraint: Optional[str] = None
    dependency_type: DependencyType = "unknown"
    purl: Optional[str] = None
    namespace: Optional[str] = None
    scope: Optional[str] = None  # runtime / dev / optional / peer / test ...
    extras: list[str] = Field(default_factory=list)
    markers: Optional[str] = None
    source_files: list[str] = Field(default_factory=list)
    component_type: str = "library"  # library | container | application
    notes: list[str] = Field(default_factory=list)


class Relationship(BaseModel):
    source: str
    target: str
    requirement: Optional[str] = None
    # True when we attached a component to the root only because no package
    # depends on it (we could not prove it is a direct dependency).
    inferred: bool = False


class SourceFileInfo(BaseModel):
    path: str
    format: str
    support_level: SupportLevel
    ecosystem: Optional[str] = None
    component_count: int = 0
    provides_transitive: bool = False
    notes: list[str] = Field(default_factory=list)


class DockerImageRef(BaseModel):
    raw: str
    image: str
    tag: Optional[str] = None
    digest: Optional[str] = None
    stage_name: Optional[str] = None
    stage_index: int
    is_final_stage: bool = False
    line: int
    pinned_by_digest: bool = False
    notes: list[str] = Field(default_factory=list)


class DockerInstall(BaseModel):
    manager: str
    packages: list[str]
    line: int
    stage_index: int


class DockerMetadata(BaseModel):
    source_file: str
    images: list[DockerImageRef] = Field(default_factory=list)
    installs: list[DockerInstall] = Field(default_factory=list)
    copied_files: list[str] = Field(default_factory=list)
    exposed_ports: list[str] = Field(default_factory=list)
    user: Optional[str] = None
    stage_count: int = 0
    analysis_kind: str = "Dockerfile metadata analysis (static text; no image was built or scanned)"


class DiscoverySummary(BaseModel):
    project_name: str
    primary_ecosystem: Optional[str] = None
    ecosystems: list[str] = Field(default_factory=list)
    total_components: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    unknown_classification: int = 0
    unresolved_dependencies: int = 0
    sbom_status: str = "not generated"
    transitive_resolution: str = "none"  # none | partial | full-from-lockfile


class DiscoveryResult(BaseModel):
    analysis_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_type: Literal["file", "repository", "image"]
    source: str  # repo URL or comma-separated uploaded file names
    project_name: str
    summary: DiscoverySummary
    files: list[SourceFileInfo] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    docker: list[DockerMetadata] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    sbom_status: str = "not generated"


# ---------------------------------------------------------------- API models
class RepositoryRequest(BaseModel):
    url: str = Field(min_length=1, max_length=300, examples=["https://github.com/pallets/click"])


class ImageRequest(BaseModel):
    image: str = Field(min_length=1, max_length=300)
    approve: bool = False


class AppInfo(BaseModel):
    name: str
    version: str
    stage: str
    docs_url: str = "/docs"
    supported_formats: list[dict[str, Any]]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


class GraphNode(BaseModel):
    id: str
    label: str
    name: str
    version: Optional[str] = None
    version_status: str
    ecosystem: str
    dependency_type: str
    depth: Optional[int] = None
    in_cycle: bool = False


class GraphEdge(BaseModel):
    source: str
    target: str
    requirement: Optional[str] = None
    inferred: bool = False


class GraphStats(BaseModel):
    nodes: int
    edges: int
    max_depth: int
    cycles: int
    shared_components: int  # components with more than one parent
    unreachable: int


class GraphResponse(BaseModel):
    analysis_id: str
    root: str = ROOT_ID
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: GraphStats


class ErrorResponse(BaseModel):
    detail: str
