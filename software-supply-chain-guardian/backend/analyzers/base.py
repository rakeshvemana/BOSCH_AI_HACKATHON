"""Shared building blocks for all analyzers.

* ``make_component`` creates a Component with a stable ID derived from its
  Package URL (purl), e.g. ``pkg:pypi/flask@2.2.2``. Stable IDs let the same
  package found in two files collapse into ONE node in the graph.
* ``PartBuilder`` collects components / edges and merges duplicates safely.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from packageurl import PackageURL
from packaging.utils import canonicalize_name

from backend.models import (
    Component, DockerMetadata, Relationship, SourceFileInfo, VersionStatus,
)


class AnalysisError(ValueError):
    """Raised when a file is present but cannot be parsed at all."""


@dataclass
class AnalysisPart:
    """Output of one analyzer run (possibly covering many files)."""
    components: list[Component] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    files: list[SourceFileInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    docker: list[DockerMetadata] = field(default_factory=list)
    project_name: Optional[str] = None


_RANK = {"unresolved": 0, "declared": 1, "pinned": 2, "resolved": 3}
_DEP_RANK = {"unknown": 0, "transitive": 1, "direct": 2}


def build_purl(ecosystem: str, name: str, version: Optional[str] = None,
               namespace: Optional[str] = None, qualifiers: Optional[dict] = None) -> Optional[str]:
    try:
        if ecosystem == "pypi":
            return str(PackageURL(type="pypi", name=canonicalize_name(name), version=version))
        if ecosystem == "npm":
            if name.startswith("@") and "/" in name:
                ns, n = name.split("/", 1)
                return str(PackageURL(type="npm", namespace=ns, name=n, version=version))
            return str(PackageURL(type="npm", name=name, version=version))
        if ecosystem == "maven":
            group, _, artifact = name.partition(":")
            return str(PackageURL(type="maven", namespace=group or None, name=artifact or group, version=version))
        if ecosystem == "github-actions":
            owner, _, repo = name.partition("/")
            return str(PackageURL(type="github", namespace=owner or None, name=repo or owner, version=version))
        if ecosystem == "docker":
            return str(PackageURL(type="docker", namespace=namespace, name=name, version=version,
                                  qualifiers=qualifiers or None))
    except (ValueError, TypeError):
        return None
    return None


def make_component(
    ecosystem: str,
    name: str,
    version: Optional[str] = None,
    version_status: VersionStatus = "unresolved",
    declared_constraint: Optional[str] = None,
    dependency_type: str = "unknown",
    source_file: Optional[str] = None,
    scope: Optional[str] = None,
    extras: Optional[list[str]] = None,
    markers: Optional[str] = None,
    purl_namespace: Optional[str] = None,
    purl_name: Optional[str] = None,
    qualifiers: Optional[dict] = None,
    component_type: str = "library",
    notes: Optional[list[str]] = None,
) -> Component:
    if version is None:
        version_status = "unresolved"
    purl = build_purl(ecosystem, purl_name or name, version, purl_namespace, qualifiers)
    cid = purl or f"{ecosystem}:{name}@{version or 'unresolved'}"
    return Component(
        id=cid, name=name, ecosystem=ecosystem, version=version, version_status=version_status,
        declared_constraint=declared_constraint, dependency_type=dependency_type,  # type: ignore[arg-type]
        purl=purl, namespace=purl_namespace, scope=scope, extras=sorted(set(extras or [])),
        markers=markers, source_files=[source_file] if source_file else [],
        component_type=component_type, notes=list(notes or []),
    )


def _join(a: Optional[str], b: Optional[str], sep: str) -> Optional[str]:
    parts = [p for p in (a, b) if p]
    seen: list[str] = []
    for p in parts:
        for piece in p.split(sep):
            piece = piece.strip()
            if piece and piece not in seen:
                seen.append(piece)
    return sep.join(seen) if seen else None


def merge_components(old: Component, new: Component) -> Component:
    """Combine two descriptions of the SAME component (same id)."""
    if _RANK[new.version_status] > _RANK[old.version_status]:
        old.version, old.version_status = new.version, new.version_status
    if _DEP_RANK[new.dependency_type] > _DEP_RANK[old.dependency_type]:
        old.dependency_type = new.dependency_type
    old.declared_constraint = _join(old.declared_constraint, new.declared_constraint, " | ")
    old.scope = _join(old.scope, new.scope, ",")
    old.markers = _join(old.markers, new.markers, " | ")
    old.extras = sorted(set(old.extras) | set(new.extras))
    for f in new.source_files:
        if f not in old.source_files:
            old.source_files.append(f)
    for n in new.notes:
        if n not in old.notes:
            old.notes.append(n)
    return old


class PartBuilder:
    """Accumulates components and relationships; duplicates are merged."""

    def __init__(self) -> None:
        self.components: dict[str, Component] = {}
        self._edges: dict[tuple[str, str], Relationship] = {}
        self.warnings: list[str] = []
        self.limitations: list[str] = []

    def add(self, comp: Component) -> Component:
        existing = self.components.get(comp.id)
        if existing is None:
            self.components[comp.id] = comp
            return comp
        return merge_components(existing, comp)

    def edge(self, source: str, target: str, requirement: Optional[str] = None) -> None:
        if source == target:
            return
        key = (source, target)
        if key in self._edges:
            if requirement and not self._edges[key].requirement:
                self._edges[key].requirement = requirement
            return
        self._edges[key] = Relationship(source=source, target=target, requirement=requirement)

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def limit(self, msg: str) -> None:
        if msg not in self.limitations:
            self.limitations.append(msg)

    def to_part(self, files: list[SourceFileInfo], project_name: Optional[str] = None) -> AnalysisPart:
        return AnalysisPart(
            components=list(self.components.values()), relationships=list(self._edges.values()),
            files=files, warnings=self.warnings, limitations=self.limitations, project_name=project_name,
        )


EXACT_VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}([-+.][0-9A-Za-z.\-+]+)?$")


def dirname(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]
