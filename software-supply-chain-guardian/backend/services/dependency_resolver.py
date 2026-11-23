"""Combine analyzer outputs into one consistent component list + relationship list.

This module does NOT resolve versions itself (we deliberately do not write a
package resolver). It only:
  1. merges duplicate components found in several files,
  2. connects direct dependencies to the application root,
  3. makes sure every component is reachable from the root, flagging anything
     we had to attach without proof (``inferred=True``),
  4. describes how complete transitive resolution is.
"""
from __future__ import annotations

from collections import deque

from backend.analyzers.base import AnalysisPart, merge_components
from backend.models import Component, Relationship, SourceFileInfo, ROOT_ID


def merge_parts(parts: list[AnalysisPart]) -> tuple[list[Component], list[Relationship]]:
    comps: dict[str, Component] = {}
    edges: dict[tuple[str, str], Relationship] = {}
    for part in parts:
        for c in part.components:
            if c.id in comps:
                merge_components(comps[c.id], c)
            else:
                comps[c.id] = c.model_copy(deep=True)
        for r in part.relationships:
            edges.setdefault((r.source, r.target), r.model_copy())
    valid = {k: r for k, r in edges.items() if r.source in comps and r.target in comps}
    return list(comps.values()), list(valid.values())


def attach_root(components: list[Component], relationships: list[Relationship]) -> tuple[list[Relationship], list[str]]:
    """Add root edges. Returns (all relationships, warnings)."""
    warnings: list[str] = []
    rels = list(relationships)
    existing = {(r.source, r.target) for r in rels}
    for c in components:
        if c.dependency_type == "direct" and (ROOT_ID, c.id) not in existing:
            rels.append(Relationship(source=ROOT_ID, target=c.id))
            existing.add((ROOT_ID, c.id))
    # reachability check
    children: dict[str, list[str]] = {}
    for r in rels:
        children.setdefault(r.source, []).append(r.target)
    seen = {ROOT_ID}
    dq = deque([ROOT_ID])
    while dq:
        for k in children.get(dq.popleft(), []):
            if k not in seen:
                seen.add(k)
                dq.append(k)
    orphans = [c for c in components if c.id not in seen]
    # Attach orphans in a stable order; a cycle-only orphan group gets one entry point, not all members.
    for c in sorted(orphans, key=lambda x: x.id):
        if c.id in seen:
            continue
        rels.append(Relationship(source=ROOT_ID, target=c.id, inferred=True))
        seen.add(c.id)
        dq.append(c.id)
        while dq:
            for k in children.get(dq.popleft(), []):
                if k not in seen:
                    seen.add(k)
                    dq.append(k)
    inferred = [c for c in orphans]
    if inferred:
        n_unknown = sum(1 for c in inferred if c.dependency_type == "unknown")
        warnings.append(
            f"{len(inferred)} component(s) were not provably connected to the application; they are linked to the root "
            f"with an 'inferred' edge ({n_unknown} have unknown direct/transitive classification)."
        )
    return rels, warnings


def transitive_resolution_level(components: list[Component], files: list[SourceFileInfo]) -> str:
    """How trustworthy is the transitive picture?  none | partial | full-from-lockfile

    "full" only when EVERY library component was derived from a file that carries
    resolved relationship data (lockfile / SBOM). A single manifest-only project
    in a monorepo downgrades the result to "partial".
    """
    # CI actions have no lockfile-style tree; they must not downgrade a project's resolution level.
    libs = [c for c in components if c.ecosystem not in {"docker", "github-actions"} and c.component_type == "library"]
    if not libs:
        return "none"
    resolving = {f.path for f in files if f.provides_transitive}
    covered = [c for c in libs if set(c.source_files) & resolving]
    if not covered:
        return "none"
    return "full-from-lockfile" if len(covered) == len(libs) else "partial"
