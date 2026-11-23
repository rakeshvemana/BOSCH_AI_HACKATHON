"""JavaScript / Node.js dependency discovery.

* package.json       - DIRECT dependencies only (version ranges stay unresolved).
* package-lock.json  - resolved versions + the real dependency tree.
* yarn.lock / pnpm-lock.yaml - recognised, reported as "Not yet supported".

How lockfile v2/v3 relationships work (beginner explanation)
------------------------------------------------------------
The lockfile has a flat map ``"node_modules/a/node_modules/b": {...}``. When
package ``a`` needs ``b``, Node first looks in ``a``'s own node_modules folder
and then walks UP the folder tree. ``_resolve`` implements exactly that rule,
so edges come from real lockfile data, not from guesswork.
"""
from __future__ import annotations

import json
from typing import Optional

from backend.analyzers.base import (
    AnalysisPart, EXACT_VERSION_RE, PartBuilder, dirname, make_component,
)
from backend.models import SourceFileInfo, SupportLevel
from backend.utils.file_utils import FORMAT_REGISTRY, classify_file

ECO = "npm"
DEP_SECTIONS = (
    ("dependencies", "runtime"), ("devDependencies", "dev"),
    ("optionalDependencies", "optional"), ("peerDependencies", "peer"),
)


def _load_json(text: str, path: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON ({str(exc)[:80]})")
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at top level.")
    return data


def _declared_from_package_json(data: dict) -> list[tuple[str, str, str]]:
    out = []
    for section, scope in DEP_SECTIONS:
        table = data.get(section) or {}
        if isinstance(table, dict):
            for name, rng in table.items():
                out.append((name, str(rng), scope))
    return out


def _name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


class JavaScriptAnalyzer:
    def analyze(self, files: dict[str, str]) -> AnalysisPart:
        b = PartBuilder()
        infos: list[SourceFileInfo] = []
        project_name: Optional[str] = None
        by_dir: dict[str, dict[str, str]] = {}
        for path in sorted(files):
            fmt = classify_file(path)
            if fmt in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                by_dir.setdefault(dirname(path), {})[fmt] = path

        for directory, group in sorted(by_dir.items()):
            pj_path, lock_path = group.get("package.json"), group.get("package-lock.json")
            pj = _load_json(files[pj_path], pj_path) if pj_path else None
            if pj and not project_name:
                project_name = pj.get("name")

            if lock_path:
                self._apply_lock(b, lock_path, _load_json(files[lock_path], lock_path), pj_path, pj)
                if not project_name:
                    project_name = _load_json(files[lock_path], lock_path).get("name")
            elif pj:
                declared = _declared_from_package_json(pj)
                for name, rng, scope in declared:
                    pinned = rng if EXACT_VERSION_RE.match(rng) else None
                    note = None if pinned else "Version range only: resolved version unknown without a lockfile."
                    b.add(make_component(ECO, name, pinned, "pinned" if pinned else "unresolved", rng,
                                         "direct", pj_path, scope, notes=[note] if note else None))
                if declared:
                    b.limit(f"JavaScript ({directory or '.'}): no package-lock.json found, so transitive dependencies "
                            "were NOT discovered and version ranges are unresolved.")

            for fmt, path in group.items():
                level, desc = FORMAT_REGISTRY[fmt]
                n = sum(1 for c in b.components.values() if path in c.source_files)
                if level == SupportLevel.NONE:
                    b.limit(f"{path}: {fmt} is recognised but NOT parsed yet. Transitive dependencies from it are not discovered.")
                infos.append(SourceFileInfo(
                    path=path, format=fmt, support_level=level, ecosystem=ECO, component_count=n,
                    provides_transitive=(fmt == "package-lock.json"), notes=[desc],
                ))
        return b.to_part(infos, project_name)

    # ------------------------------------------------------------------ lockfile
    def _apply_lock(self, b: PartBuilder, path: str, lock: dict, pj_path: Optional[str], pj: Optional[dict]) -> None:
        version = lock.get("lockfileVersion")
        if isinstance(lock.get("packages"), dict):
            self._apply_v2(b, path, lock["packages"], pj_path, pj)
        elif isinstance(lock.get("dependencies"), dict):
            self._apply_v1(b, path, lock["dependencies"], pj_path, pj)
        else:
            b.warn(f"{path}: lockfile (lockfileVersion={version}) contains no packages.")
            return

    def _apply_v2(self, b: PartBuilder, path: str, packages: dict, pj_path, pj) -> None:
        root = packages.get("", {}) or {}
        declared = {n: (r, s) for n, r, s in _declared_from_package_json(root)}
        if pj:  # package.json is authoritative for what the project declares
            declared.update({n: (r, s) for n, r, s in _declared_from_package_json(pj)})

        def resolve(frm: str, name: str) -> Optional[str]:
            base = frm
            while True:
                cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
                if cand in packages:
                    target = packages[cand]
                    if isinstance(target, dict) and target.get("link") and target.get("resolved") in packages:
                        return target["resolved"]  # npm workspace symlink
                    return cand
                if not base:
                    return None
                idx = base.rfind("node_modules/")
                base = base[:idx].rstrip("/") if idx > 0 else ""

        key_to_id: dict[str, str] = {}
        for key, entry in packages.items():
            if key == "" or not isinstance(entry, dict) or entry.get("link"):
                continue
            name = entry.get("name") or _name_from_key(key)
            ver = entry.get("version")
            scope = "dev" if entry.get("dev") else "optional" if entry.get("optional") else "peer" if entry.get("peer") else "runtime"
            rng_scope = declared.get(name)
            is_direct = key == f"node_modules/{name}" and name in declared
            notes = []
            if "resolved" not in entry and not key.startswith("node_modules/"):
                notes.append("Local workspace package.")
            c = b.add(make_component(
                ECO, name, ver, "resolved" if ver else "unresolved",
                rng_scope[0] if is_direct else None, "direct" if is_direct else "transitive",
                path, rng_scope[1] if is_direct else scope, notes=notes,
            ))
            key_to_id[key] = c.id

        missing = 0
        for key, entry in packages.items():
            if key not in key_to_id:
                continue
            for section, _scope in DEP_SECTIONS:
                for dname, rng in (entry.get(section) or {}).items():
                    tkey = resolve(key, dname)
                    if tkey and tkey in key_to_id:
                        b.edge(key_to_id[key], key_to_id[tkey], str(rng))
                    elif section == "dependencies":
                        missing += 1
        if missing:
            b.warn(f"{path}: {missing} required dependency reference(s) were not present in the lockfile (lock may be incomplete).")

        for name, (rng, scope) in declared.items():
            if f"node_modules/{name}" not in key_to_id:
                # Declared but not locked (e.g. optional / peer not installed). Never invent a version.
                if scope in {"optional", "peer"}:
                    continue
                b.add(make_component(ECO, name, None, "unresolved", rng, "direct", pj_path or path, scope,
                                     notes=["Declared in package.json but missing from the lockfile."]))
                b.warn(f"{path}: declared dependency '{name}' is missing from the lockfile.")

    def _apply_v1(self, b: PartBuilder, path: str, deps: dict, pj_path, pj) -> None:
        """lockfileVersion 1: nested 'dependencies' trees with 'requires' maps."""
        declared = {n: (r, s) for n, r, s in _declared_from_package_json(pj)} if pj else {}
        id_by_entry: dict[int, str] = {}
        parent_of: dict[int, Optional[dict]] = {}

        def walk(table: dict, parent: Optional[dict], top: bool) -> None:
            for name, entry in table.items():
                if not isinstance(entry, dict):
                    continue
                parent_of[id(entry)] = parent
                ver = entry.get("version")
                is_direct = top and name in declared
                scope = "dev" if entry.get("dev") else "optional" if entry.get("optional") else "runtime"
                dtype = "direct" if is_direct else ("transitive" if (declared or not top) else "unknown")
                c = b.add(make_component(
                    ECO, name, ver if ver and EXACT_VERSION_RE.match(ver) else None,
                    "resolved" if ver and EXACT_VERSION_RE.match(ver) else "unresolved",
                    declared[name][0] if is_direct else None, dtype, path,
                    declared[name][1] if is_direct else scope,
                ))
                id_by_entry[id(entry)] = c.id
                walk(entry.get("dependencies") or {}, entry, False)

        walk(deps, None, True)

        def find(entry: Optional[dict], name: str) -> Optional[dict]:
            scope_entry = entry
            while True:
                table = deps if scope_entry is None else (scope_entry.get("dependencies") or {})
                if name in table and isinstance(table[name], dict):
                    return table[name]
                if scope_entry is None:
                    return None
                scope_entry = parent_of.get(id(scope_entry))

        def edges(table: dict) -> None:
            for name, entry in table.items():
                if not isinstance(entry, dict):
                    continue
                for rname, rng in (entry.get("requires") or {}).items():
                    target = find(entry, rname)
                    if target is not None and id(target) in id_by_entry:
                        b.edge(id_by_entry[id(entry)], id_by_entry[id(target)], str(rng))
                edges(entry.get("dependencies") or {})

        edges(deps)
        targets = {t for (_s, t) in b._edges}
        for cid in targets:
            if b.components[cid].dependency_type == "unknown":
                b.components[cid].dependency_type = "transitive"
        if not pj:
            b.limit(f"{path}: lockfileVersion 1 does not list the project's own dependencies; "
                    "provide package.json to tell direct from transitive (top-level entries are 'unknown').")
