"""Java / Maven dependency discovery from pom.xml.

IMPORTANT LIMITATION (reported in every result)
-----------------------------------------------
A pom.xml only DECLARES dependencies. Maven computes the real tree by reading
parent POMs, BOMs and every dependency's own pom from a repository, applying
"nearest wins" mediation. We do NOT run Maven (that could execute build
plugins from an untrusted project), so transitive dependencies are not
discovered and are never invented.

We resolve only what is certain from the single file:
* literal versions, ``${property}`` references defined in the same pom,
* ``<dependencyManagement>`` versions defined in the same pom.
Anything else (parent/BOM-managed, version ranges) is left unresolved.
"""
from __future__ import annotations

import re
from typing import Optional

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import Element, ParseError

from backend.analyzers.base import AnalysisPart, PartBuilder, make_component
from backend.models import SourceFileInfo
from backend.utils.file_utils import FORMAT_REGISTRY, classify_file

ECO = "maven"
_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _strip_ns(root: Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: Optional[Element], tag: str) -> Optional[str]:
    if el is None:
        return None
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text and child.text.strip() else None


class JavaAnalyzer:
    def analyze(self, files: dict[str, str]) -> AnalysisPart:
        b = PartBuilder()
        infos: list[SourceFileInfo] = []
        project_name: Optional[str] = None
        for path in sorted(files):
            if classify_file(path) != "pom.xml":
                continue
            name = self._analyze_pom(b, path, files[path])
            project_name = project_name or name
            n = sum(1 for c in b.components.values() if path in c.source_files)
            infos.append(SourceFileInfo(
                path=path, format="pom.xml", support_level=FORMAT_REGISTRY["pom.xml"][0], ecosystem=ECO,
                component_count=n, provides_transitive=False, notes=[FORMAT_REGISTRY["pom.xml"][1]],
            ))
        if infos:
            b.limit("Maven: pom.xml declares direct dependencies only. Transitive dependencies are NOT discovered "
                    "(Maven was not run; build plugins are never executed). Versions managed by parent POMs/BOMs are unresolved.")
        return b.to_part(infos, project_name)

    def _analyze_pom(self, b: PartBuilder, path: str, text: str) -> Optional[str]:
        try:
            root = SafeET.fromstring(text)
        except (ParseError, DefusedXmlException) as exc:
            raise ValueError(f"{path}: invalid or unsafe XML ({type(exc).__name__}).")
        _strip_ns(root)
        if root.tag != "project":
            raise ValueError(f"{path}: not a Maven POM (root element is '{root.tag}', expected 'project').")

        parent = root.find("parent")
        props: dict[str, str] = {}
        group = _text(root, "groupId") or _text(parent, "groupId")
        version = _text(root, "version") or _text(parent, "version")
        artifact = _text(root, "artifactId")
        for key, val in (("project.groupId", group), ("project.version", version), ("project.artifactId", artifact),
                         ("pom.groupId", group), ("pom.version", version)):
            if val:
                props[key] = val
        if parent is not None:
            for key, tag in (("project.parent.version", "version"), ("project.parent.groupId", "groupId")):
                v = _text(parent, tag)
                if v:
                    props[key] = v
        pnode = root.find("properties")
        if pnode is not None:
            for el in pnode:
                if isinstance(el.tag, str) and el.text:
                    props[el.tag] = el.text.strip()

        def interpolate(value: Optional[str]) -> tuple[Optional[str], bool]:
            """Return (value, fully_resolved)."""
            if value is None:
                return None, False
            for _ in range(5):
                new = _PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)
                if new == value:
                    break
                value = new
            return value, not _PROP_RE.search(value)

        managed: dict[str, str] = {}
        dm = root.find("dependencyManagement/dependencies")
        if dm is not None:
            for dep in dm.findall("dependency"):
                g, a, v = (interpolate(_text(dep, t))[0] for t in ("groupId", "artifactId", "version"))
                if g and a and v and not _PROP_RE.search(v):
                    managed[f"{g}:{a}"] = v

        if parent is not None:
            b.warn(f"{path}: has a <parent> POM; versions inherited from it (and BOM imports) cannot be resolved here.")
        if root.find("modules") is not None:
            b.warn(f"{path}: multi-module project; module poms were not followed. Upload/analyse each module's pom.xml.")
        if root.find("profiles") is not None:
            b.warn(f"{path}: <profiles> dependencies are not analysed.")

        deps = root.find("dependencies")
        for dep in (deps.findall("dependency") if deps is not None else []):
            g = interpolate(_text(dep, "groupId"))[0]
            a = interpolate(_text(dep, "artifactId"))[0]
            if not g or not a:
                b.warn(f"{path}: dependency without groupId/artifactId skipped.")
                continue
            raw_version = _text(dep, "version")
            version_val, ok = interpolate(raw_version)
            constraint = raw_version
            notes: list[str] = []
            ver: Optional[str] = None
            if raw_version is None:
                if f"{g}:{a}" in managed:
                    ver = managed[f"{g}:{a}"]
                    notes.append("Version from <dependencyManagement> in the same pom.")
                else:
                    notes.append("No version in this pom (inherited from parent/BOM): unresolved.")
            elif not ok:
                notes.append(f"Version references undefined property {raw_version}: unresolved.")
            elif re.match(r"^[\[(]", version_val or ""):
                notes.append("Version range: Maven picks the final version at build time; unresolved.")
            else:
                ver = version_val
            scope = _text(dep, "scope") or "compile"
            if _text(dep, "type") not in (None, "jar"):
                notes.append(f"Dependency type '{_text(dep, 'type')}'.")
            if _text(dep, "optional") == "true":
                notes.append("Marked optional.")
            b.add(make_component(
                ECO, f"{g}:{a}", ver, "declared" if ver else "unresolved", constraint, "direct", path, scope,
                notes=notes,
            ))
        return f"{group}:{artifact}" if group and artifact else artifact
