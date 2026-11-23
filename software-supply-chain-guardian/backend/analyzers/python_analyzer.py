"""Python dependency discovery.

Supported inputs
----------------
* requirements*.txt  - direct dependencies; exact ``==`` pins reported as "pinned".
* pyproject.toml     - PEP 621 / PEP 735 / Poetry declared dependencies.
* uv.lock            - fully resolved graph (versions + relationships + direct deps).
* poetry.lock        - fully resolved graph; direct deps need pyproject.toml.

We never run pip/poetry/uv and never import the analysed project. Everything is
parsed as text/TOML data.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from typing import Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from backend.analyzers.base import (
    AnalysisPart, EXACT_VERSION_RE, PartBuilder, basename, dirname, make_component,
)
from backend.models import SourceFileInfo, SupportLevel
from backend.utils.file_utils import FORMAT_REGISTRY, classify_file

ECO = "pypi"


@dataclass
class DeclaredReq:
    name: str
    constraint: Optional[str] = None
    pinned_version: Optional[str] = None
    extras: list[str] = field(default_factory=list)
    markers: Optional[str] = None
    scope: str = "runtime"
    source: str = ""
    note: Optional[str] = None


# ----------------------------------------------------------- requirements.txt
_COMMENT_RE = re.compile(r"(^|\s)#.*$")
_HASH_RE = re.compile(r"\s+--hash[= ]\S+")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        out.append((start, buf + raw))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def requirement_to_declared(req: Requirement, source: str, scope: str = "runtime") -> DeclaredReq:
    pinned = None
    constraint: Optional[str] = str(req.specifier) or None
    specs = list(req.specifier)
    if not req.url and len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        pinned = specs[0].version
    if req.url:
        constraint = f"@ {req.url}"
    return DeclaredReq(
        name=req.name, constraint=constraint, pinned_version=pinned, extras=sorted(req.extras),
        markers=str(req.marker) if req.marker else None, scope=scope, source=source,
    )


def parse_requirements_text(text: str, source: str = "requirements.txt") -> tuple[list[DeclaredReq], list[str]]:
    """Parse a requirements file. Returns (requirements, warnings). Never raises."""
    reqs: list[DeclaredReq] = []
    warnings: list[str] = []
    for lineno, raw in _logical_lines(text):
        line = _COMMENT_RE.sub("", raw).strip()
        if not line:
            continue
        line = _HASH_RE.sub("", line).strip()
        where = f"{source}:{lineno}"
        if line.startswith("-"):
            opt = line.split(None, 1)[0].split("=", 1)[0]
            if opt in {"-r", "--requirement", "-c", "--constraint"}:
                warnings.append(f"{where}: '{opt}' include/constraint file is not followed; analyse that file separately.")
            elif opt in {"-e", "--editable"}:
                warnings.append(f"{where}: editable requirement skipped (local path / VCS, cannot be resolved statically).")
            elif opt in {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}:
                warnings.append(f"{where}: custom package index / link option '{opt}' found - packages may come from a non-default source.")
            continue
        try:
            reqs.append(requirement_to_declared(Requirement(line), source))
        except InvalidRequirement as exc:
            snippet = line if len(line) <= 60 else line[:57] + "..."
            warnings.append(f"{where}: could not parse requirement '{snippet}' ({str(exc).splitlines()[0][:80]}).")
    return reqs, warnings


# --------------------------------------------------------------- pyproject.toml
def _poetry_constraint(spec) -> tuple[Optional[str], list[str], Optional[str], Optional[str]]:
    """Return (constraint, extras, markers, note) for one Poetry dependency value."""
    if isinstance(spec, str):
        return spec, [], None, None
    if isinstance(spec, list):  # multiple-constraint dependencies
        parts = [_poetry_constraint(s)[0] for s in spec]
        return " | ".join(p for p in parts if p) or None, [], None, "multiple constraints"
    if isinstance(spec, dict):
        extras = list(spec.get("extras", []) or [])
        markers = spec.get("markers") or (f"python {spec['python']}" if spec.get("python") else None)
        for key in ("git", "path", "url"):
            if key in spec:
                return f"{key}: {spec[key]}", extras, markers, f"{key} dependency (version cannot be determined statically)"
        return spec.get("version"), extras, markers, None
    return None, [], None, None


def parse_pyproject(text: str, source: str) -> tuple[list[DeclaredReq], Optional[str], list[str]]:
    warnings: list[str] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{source}: invalid TOML ({str(exc)[:100]})")
    reqs: list[DeclaredReq] = []

    def add_pep508(items, scope):
        for item in items or []:
            if not isinstance(item, str):
                continue  # e.g. {include-group = "..."} (PEP 735)
            try:
                reqs.append(requirement_to_declared(Requirement(item), source, scope))
            except InvalidRequirement:
                warnings.append(f"{source}: could not parse requirement '{item[:60]}'.")

    project = data.get("project", {}) or {}
    name = project.get("name")
    add_pep508(project.get("dependencies"), "runtime")
    for group, items in (project.get("optional-dependencies") or {}).items():
        add_pep508(items, f"optional:{group}")
    for group, items in (data.get("dependency-groups") or {}).items():
        add_pep508(items, f"dev:{group}")
    add_pep508((data.get("build-system") or {}).get("requires"), "build")

    poetry = (data.get("tool") or {}).get("poetry") or {}
    if poetry:
        name = name or poetry.get("name")

        def add_poetry(table, scope):
            for dep, spec in (table or {}).items():
                if canonicalize_name(dep) == "python":
                    continue
                constraint, extras, markers, note = _poetry_constraint(spec)
                pinned = constraint if constraint and EXACT_VERSION_RE.match(constraint) else None
                if constraint and constraint.startswith("=="):
                    pinned = constraint[2:].strip() or None
                reqs.append(DeclaredReq(dep, constraint, pinned, extras, markers, scope, source, note))

        add_poetry(poetry.get("dependencies"), "runtime")
        add_poetry(poetry.get("dev-dependencies"), "dev")
        for group, body in (poetry.get("group") or {}).items():
            add_poetry((body or {}).get("dependencies"), f"dev:{group}" if group != "main" else "runtime")
    return reqs, name, warnings


# ------------------------------------------------------------------ lock files
@dataclass
class LockedPackage:
    name: str
    version: Optional[str]
    deps: list[tuple[str, Optional[str], Optional[str]]]  # (name, pinned version or None, requirement text)
    scope: Optional[str] = None


def _parse_poetry_lock(text: str, source: str) -> tuple[list[LockedPackage], list[str]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{source}: invalid TOML ({str(exc)[:100]})")
    pkgs: list[LockedPackage] = []
    for p in data.get("package", []) or []:
        if "name" not in p:
            continue
        deps = []
        for dname, spec in (p.get("dependencies") or {}).items():
            constraint = _poetry_constraint(spec)[0]
            deps.append((dname, None, constraint))
        scope = p.get("category")  # present in older lock formats ("main"/"dev")
        pkgs.append(LockedPackage(p["name"], p.get("version"), deps, scope))
    return pkgs, []


def _parse_uv_lock(text: str, source: str):
    """Return (packages, root_direct list, project name, warnings)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{source}: invalid TOML ({str(exc)[:100]})")
    pkgs: list[LockedPackage] = []
    root_direct: list[DeclaredReq] = []
    root_name: Optional[str] = None
    warnings: list[str] = []

    def uvdeps(items):
        out = []
        for d in items or []:
            if isinstance(d, dict) and "name" in d:
                out.append((d["name"], d.get("version"), d.get("marker")))
        return out

    for p in data.get("package", []) or []:
        if "name" not in p:
            continue
        src = p.get("source") or {}
        is_root = src.get("virtual") == "." or src.get("editable") == "."
        deps = uvdeps(p.get("dependencies"))
        if is_root:
            root_name = p["name"]
            for dn, _v, marker in deps:
                root_direct.append(DeclaredReq(dn, None, None, [], marker, "runtime", source))
            for group, items in (p.get("optional-dependencies") or {}).items():
                for dn, _v, marker in uvdeps(items):
                    root_direct.append(DeclaredReq(dn, None, None, [], marker, f"optional:{group}", source))
            for group, items in (p.get("dev-dependencies") or {}).items():
                for dn, _v, marker in uvdeps(items):
                    root_direct.append(DeclaredReq(dn, None, None, [], marker, f"dev:{group}", source))
            continue
        # non-root: optional-dependencies of locked packages are not installed by default; keep base deps only
        pkgs.append(LockedPackage(p["name"], p.get("version"), deps))
    return pkgs, root_direct, root_name, warnings


# ---------------------------------------------------------------- the analyzer
class PythonAnalyzer:
    def analyze(self, files: dict[str, str]) -> AnalysisPart:
        b = PartBuilder()
        infos: list[SourceFileInfo] = []
        project_name: Optional[str] = None

        by_dir: dict[str, dict[str, list[str]]] = {}
        for path in sorted(files):
            fmt = classify_file(path)
            if fmt in {"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"}:
                by_dir.setdefault(dirname(path), {}).setdefault(fmt, []).append(path)

        for directory, groups in sorted(by_dir.items()):
            declared: list[DeclaredReq] = []
            file_counts: dict[str, int] = {}
            for path in groups.get("requirements.txt", []):
                reqs, warns = parse_requirements_text(files[path], path)
                declared += reqs
                for w in warns:
                    b.warn(w)
                file_counts[path] = len(reqs)
                if not reqs and not warns and files[path].strip() == "":
                    b.warn(f"{path}: file is empty.")
            for path in groups.get("pyproject.toml", []):
                reqs, name, warns = parse_pyproject(files[path], path)
                declared += reqs
                project_name = project_name or name
                for w in warns:
                    b.warn(w)
                file_counts[path] = len(reqs)

            lock_paths = groups.get("uv.lock", []) + groups.get("poetry.lock", [])
            have_manifest = bool(groups.get("pyproject.toml") or groups.get("requirements.txt"))
            if lock_paths:
                for path in groups.get("uv.lock", []):
                    pkgs, root_direct, root_name, ws = _parse_uv_lock(files[path], path)
                    project_name = project_name or root_name
                    self._apply_lock(b, path, pkgs, root_direct + declared, True, have_manifest or bool(root_direct), file_counts)
                for path in groups.get("poetry.lock", []):
                    pkgs, ws = _parse_poetry_lock(files[path], path)
                    self._apply_lock(b, path, pkgs, declared, False, have_manifest, file_counts)
            else:
                self._apply_declared_only(b, declared)
                if declared:
                    b.limit(
                        f"Python ({directory or '.'}): no lockfile found, so transitive dependencies were NOT discovered "
                        "and only exact '==' pins have versions."
                    )

            for path in sorted(p for g in groups.values() for p in g):
                fmt = classify_file(path)
                level, desc = FORMAT_REGISTRY[fmt]
                n = sum(1 for c in b.components.values() if path in c.source_files)
                notes = [desc]
                infos.append(SourceFileInfo(
                    path=path, format=fmt, support_level=level, ecosystem=ECO, component_count=n,
                    provides_transitive=fmt in {"poetry.lock", "uv.lock"}, notes=notes,
                ))
        return b.to_part(infos, project_name)

    # -- declared only (no lock): components are the direct deps
    @staticmethod
    def _apply_declared_only(b: PartBuilder, declared: list[DeclaredReq]) -> None:
        for d in declared:
            b.add(make_component(
                ECO, d.name, d.pinned_version, "pinned" if d.pinned_version else "unresolved",
                d.constraint, "direct", d.source, d.scope, d.extras, d.markers,
                notes=([d.note] if d.note else []) + ([] if d.pinned_version else ["Version not pinned: resolved version unknown."]),
            ))

    # -- with lock: components are every locked package
    @staticmethod
    def _apply_lock(b: PartBuilder, path: str, pkgs: list[LockedPackage], declared: list[DeclaredReq],
                    is_uv: bool, direct_known: bool, file_counts: dict[str, int]) -> None:
        by_name: dict[str, list[LockedPackage]] = {}
        for p in pkgs:
            by_name.setdefault(canonicalize_name(p.name), []).append(p)

        def locate(name: str, version: Optional[str]) -> Optional[LockedPackage]:
            cands = by_name.get(canonicalize_name(name), [])
            if version:
                cands = [c for c in cands if c.version == version]
            if len(cands) == 1:
                return cands[0]
            if len(cands) > 1:
                b.warn(f"{path}: '{name}' has multiple locked versions and no way to choose; relationship skipped.")
            return None

        direct_names = {canonicalize_name(d.name): d for d in declared} if direct_known else {}
        comp_id: dict[tuple[str, Optional[str]], str] = {}
        for p in pkgs:
            d = direct_names.get(canonicalize_name(p.name))
            if d is not None:
                dtype = "direct"
            elif direct_known:
                dtype = "transitive"
            else:
                dtype = "unknown"  # fixed up below once edges are known
            c = b.add(make_component(
                ECO, p.name, p.version, "resolved" if p.version else "unresolved",
                d.constraint if d else None, dtype, path, d.scope if d else p.scope,
                d.extras if d else None, d.markers if d else None,
            ))
            comp_id[(canonicalize_name(p.name), p.version)] = c.id

        has_incoming: set[str] = set()
        for p in pkgs:
            src = comp_id[(canonicalize_name(p.name), p.version)]
            for dname, dver, req in p.deps:
                target = locate(dname, dver)
                if target is None:
                    if not by_name.get(canonicalize_name(dname)):
                        b.warn(f"{path}: '{p.name}' depends on '{dname}' which is not in the lockfile (e.g. excluded by markers).")
                    continue
                tid = comp_id[(canonicalize_name(target.name), target.version)]
                b.edge(src, tid, req)
                has_incoming.add(tid)

        if not direct_known:
            for cid in has_incoming:
                if b.components[cid].dependency_type == "unknown":
                    b.components[cid].dependency_type = "transitive"
            b.limit(
                f"{path}: this lockfile does not record which packages the project declares directly. Packages that nothing "
                "else depends on are labelled 'unknown' (not guessed as direct). Provide pyproject.toml to classify them."
            )

        # declared deps not present in the lock -> keep as unresolved, never invent a version
        locked_names = set(by_name)
        for d in declared:
            if canonicalize_name(d.name) not in locked_names:
                b.add(make_component(ECO, d.name, d.pinned_version, "pinned" if d.pinned_version else "unresolved",
                                     d.constraint, "direct", d.source, d.scope, d.extras, d.markers,
                                     notes=["Declared but missing from the lockfile (lock may be stale)."]))
                b.warn(f"{path}: declared dependency '{d.name}' is missing from the lockfile.")
