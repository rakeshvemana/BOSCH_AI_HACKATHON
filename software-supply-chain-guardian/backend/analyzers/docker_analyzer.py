"""Static Dockerfile metadata analysis.

This reads the Dockerfile as TEXT. It never builds, pulls or runs anything.
What it can tell you: which base images are referenced, which packages the
Dockerfile asks the package manager to install, and which local files are
copied in. What it CANNOT tell you: the full list of OS packages inside the
final image (that needs a real image scan, e.g. Syft).
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

from backend.analyzers.base import AnalysisPart, PartBuilder, make_component
from backend.models import (
    DockerImageRef, DockerInstall, DockerMetadata, SourceFileInfo,
)
from backend.utils.file_utils import FORMAT_REGISTRY, classify_file

ECO = "docker"
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

_INSTALL_PATTERNS = [
    ("apt", re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\s+(.*)")),
    ("apk", re.compile(r"\bapk\s+(?:-\S+\s+)*add\s+(.*)")),
    ("yum/dnf", re.compile(r"\b(?:yum|dnf|microdnf)\s+(?:-\S+\s+)*install\s+(.*)")),
    ("pip", re.compile(r"\bpip3?\s+(?:--?\S+\s+)*install\s+(.*)")),
    ("npm", re.compile(r"\bnpm\s+(?:i|install|add)\s+(.*)")),
    ("gem", re.compile(r"\bgem\s+install\s+(.*)")),
]


def _logical_instructions(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buf:
            if not stripped or stripped.startswith("#"):
                continue
            start = i
        elif stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        out.append((start, (buf + stripped).strip()))
        buf = ""
    if buf:
        out.append((start, buf.strip()))
    return out


def _subst(value: str, args: dict[str, Optional[str]]) -> tuple[str, bool]:
    resolved = True

    def repl(m: re.Match) -> str:
        nonlocal resolved
        name = m.group(1) or m.group(3)
        default = m.group(2)
        val = args.get(name)
        if val is None:
            val = default
        if val is None:
            resolved = False
            return m.group(0)
        return val

    return _VAR_RE.sub(repl, value), resolved


def split_image(ref: str) -> tuple[str, Optional[str], Optional[str]]:
    """'registry:5000/a/b:1.0@sha256:...' -> (image, tag, digest)."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    return ref, tag, digest


def _clean_packages(arg_str: str) -> list[str]:
    arg_str = re.split(r"\s*(?:&&|\|\||;|\|)\s*", arg_str)[0]
    try:
        tokens = shlex.split(arg_str, posix=True)
    except ValueError:
        tokens = arg_str.split()
    return [t for t in tokens if t and not t.startswith("-") and "$(" not in t and t not in {"\\"}]


class DockerAnalyzer:
    def analyze(self, files: dict[str, str]) -> AnalysisPart:
        b = PartBuilder()
        infos: list[SourceFileInfo] = []
        docker: list[DockerMetadata] = []
        for path in sorted(files):
            if classify_file(path) != "Dockerfile":
                continue
            meta = self.parse(files[path], path, b)
            docker.append(meta)
            n = sum(1 for c in b.components.values() if path in c.source_files)
            infos.append(SourceFileInfo(
                path=path, format="Dockerfile", support_level=FORMAT_REGISTRY["Dockerfile"][0], ecosystem=ECO,
                component_count=n, provides_transitive=False, notes=[FORMAT_REGISTRY["Dockerfile"][1]],
            ))
        if docker:
            b.limit("Docker: Dockerfile analysis is static metadata only. It does NOT list the OS packages installed in the "
                    "final image; run an image scan (e.g. Syft) for that. Nothing was built, pulled or executed.")
        part = b.to_part(infos)
        part.docker = docker
        return part

    def parse(self, text: str, path: str, b: Optional[PartBuilder] = None) -> DockerMetadata:
        b = b or PartBuilder()
        meta = DockerMetadata(source_file=path)
        args: dict[str, Optional[str]] = {}
        stage_names: dict[str, int] = {}
        stage_index = -1

        for lineno, ins in _logical_instructions(text):
            keyword, _, rest = ins.partition(" ")
            kw = keyword.upper()
            rest = rest.strip()
            if kw == "ARG":
                for item in rest.split():
                    k, eq, v = item.partition("=")
                    args.setdefault(k, v if eq else None)
            elif kw == "FROM":
                stage_index += 1
                toks = [t for t in rest.split() if not t.startswith("--")]
                if not toks:
                    b.warn(f"{path}:{lineno}: FROM without an image.")
                    continue
                raw = toks[0]
                stage_name = toks[2] if len(toks) >= 3 and toks[1].upper() == "AS" else None
                if stage_name:
                    stage_names[stage_name.lower()] = stage_index
                ref, resolved = _subst(raw, args)
                notes: list[str] = []
                if ref.lower() in stage_names and ref.lower() != (stage_name or "").lower() and stage_names[ref.lower()] < stage_index:
                    meta.images.append(DockerImageRef(
                        raw=raw, image=ref, stage_name=stage_name, stage_index=stage_index, line=lineno,
                        notes=["References an earlier build stage (not an external image)."]))
                    continue
                if ref.lower() == "scratch":
                    meta.images.append(DockerImageRef(raw=raw, image="scratch", stage_name=stage_name,
                                                      stage_index=stage_index, line=lineno,
                                                      notes=["Empty base image."]))
                    continue
                if not resolved:
                    notes.append("Image reference uses a build ARG with no default; actual image unknown.")
                image, tag, digest = split_image(ref)
                if not resolved:
                    image, tag, digest = ref, None, None
                if resolved and not tag and not digest:
                    notes.append("No tag: implicit ':latest' (mutable, not reproducible).")
                elif tag == "latest":
                    notes.append("':latest' is a mutable tag.")
                if resolved and not digest:
                    notes.append("Not pinned by digest.")
                meta.images.append(DockerImageRef(
                    raw=raw, image=image, tag=tag, digest=digest, stage_name=stage_name, stage_index=stage_index,
                    line=lineno, pinned_by_digest=bool(digest), notes=notes))
                if resolved:
                    version = digest or tag
                    status = "pinned" if digest else ("declared" if tag else "unresolved")
                    first = image.split("/")[0]
                    qualifiers = {"repository_url": image} if ("." in first or ":" in first or first == "localhost") and "/" in image else None
                    b.add(make_component(
                        ECO, image, version, status, tag or digest, "direct", path, "base-image",
                        purl_name=image.rsplit("/", 1)[-1], qualifiers=qualifiers, component_type="container",
                        notes=notes))
            elif kw == "RUN":
                for manager, pat in _INSTALL_PATTERNS:
                    m = pat.search(rest)
                    if m:
                        pkgs = _clean_packages(m.group(1))
                        if pkgs:
                            meta.installs.append(DockerInstall(manager=manager, packages=pkgs, line=lineno, stage_index=max(stage_index, 0)))
            elif kw in {"COPY", "ADD"}:
                toks = [t for t in rest.split() if not t.startswith("--")]
                if rest.startswith("["):
                    try:
                        import json
                        toks = json.loads(rest)
                    except ValueError:
                        pass
                if len(toks) >= 2 and not any(t.startswith("--from") for t in rest.split()):
                    for src in toks[:-1]:
                        if not src.startswith(("http://", "https://")) and src not in meta.copied_files:
                            meta.copied_files.append(src)
                elif any(t.startswith("--from") for t in rest.split()):
                    pass  # copying from another stage, not a local file
            elif kw == "EXPOSE":
                meta.exposed_ports += [p for p in rest.split() if p not in meta.exposed_ports]
            elif kw == "USER":
                meta.user = rest.split(":")[0] if rest else None

        meta.stage_count = stage_index + 1
        if meta.images:
            last = max(i.stage_index for i in meta.images)
            for i in meta.images:
                i.is_final_stage = i.stage_index == last
        if meta.stage_count == 0:
            b.warn(f"{path}: no FROM instruction found; not a valid Dockerfile.")
        return meta
