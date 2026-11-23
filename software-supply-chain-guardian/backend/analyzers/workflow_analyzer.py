"""Static GitHub Actions workflow analysis (CI/CD supply chain).

A workflow's `uses:` lines pull third-party code into your build: actions
(`actions/checkout@v4`), reusable workflows and container images. Each becomes a
component. The YAML is parsed as DATA with ``yaml.safe_load``; nothing is run.

What a reference can tell us:
* ``owner/repo@<40-hex sha>``  -> pinned (immutable)
* ``owner/repo@v4`` or ``@main`` -> declared (a tag or branch the owner can move)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional

import yaml

from backend.analyzers.base import AnalysisPart, PartBuilder, make_component
from backend.analyzers.docker_analyzer import split_image
from backend.models import SourceFileInfo
from backend.utils.file_utils import FORMAT_REGISTRY

ECO = "github-actions"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class UsesRef:
    """One external thing a workflow pulls in."""
    kind: str             # action | reusable-workflow | docker | local
    raw: str
    name: str             # owner/repo for actions, image for docker
    ref: Optional[str]    # tag / branch / sha (actions) or tag / digest (docker)
    job: str
    step: Optional[int]
    line: Optional[int]


def load_workflow(text: str, path: str) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: not valid YAML ({str(exc).splitlines()[0]}).")
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise ValueError(f"{path}: not a GitHub Actions workflow (no 'jobs' section).")
    # YAML 1.1 reads the bare key `on` as boolean True.
    if "on" not in doc and True in doc:
        doc["on"] = doc.pop(True)
    return doc


def triggers(doc: dict[str, Any]) -> set[str]:
    on = doc.get("on")
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


class LineFinder:
    """Map YAML values back to line numbers (safe_load drops them) by scanning the text in order."""

    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        self._used: set[int] = set()

    def find(self, needle: str) -> Optional[int]:
        fallback = None
        for i, line in enumerate(self.lines, 1):
            if needle in line:
                if i not in self._used:
                    self._used.add(i)
                    return i
                fallback = fallback or i
        return fallback


def parse_uses(raw: str) -> tuple[str, str, Optional[str]]:
    """'owner/repo/path@ref' -> (kind, name, ref)."""
    raw = raw.strip()
    if raw.startswith("./") or raw.startswith("../"):
        return "local", raw, None
    if raw.startswith("docker://"):
        image, tag, digest = split_image(raw[len("docker://"):])
        return "docker", image, digest or tag
    target, _, ref = raw.partition("@")
    parts = target.split("/")
    name = "/".join(parts[:2])
    kind = "reusable-workflow" if "/.github/workflows/" in f"/{target}" else "action"
    return kind, name, ref or None


def iter_uses(doc: dict[str, Any], text: str) -> Iterator[UsesRef]:
    lf = LineFinder(text)
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            kind, name, ref = parse_uses(job["uses"])
            yield UsesRef(kind, job["uses"], name, ref, str(job_id), None, lf.find(job["uses"]))
        images: list[str] = []
        container = job.get("container")
        if isinstance(container, str):
            images.append(container)
        elif isinstance(container, dict) and isinstance(container.get("image"), str):
            images.append(container["image"])
        for svc in (job.get("services") or {}).values() if isinstance(job.get("services"), dict) else []:
            if isinstance(svc, dict) and isinstance(svc.get("image"), str):
                images.append(svc["image"])
            elif isinstance(svc, str):
                images.append(svc)
        for img in images:
            if "${{" in img:
                continue
            image, tag, digest = split_image(img)
            yield UsesRef("docker", img, image, digest or tag, str(job_id), None, lf.find(img))
        for idx, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                kind, name, ref = parse_uses(step["uses"])
                yield UsesRef(kind, step["uses"], name, ref, str(job_id), idx, lf.find(step["uses"]))


def iter_run_steps(doc: dict[str, Any], text: str) -> Iterator[tuple[str, int, str, Optional[int]]]:
    """(job, step index, script, line of the step's `run:`)."""
    lf = LineFinder(text)
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for idx, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                first = step["run"].strip().splitlines()[0] if step["run"].strip() else ""
                yield str(job_id), idx, step["run"], (lf.find(first) if first else None)


class WorkflowAnalyzer:
    def analyze(self, files: dict[str, str]) -> AnalysisPart:
        b = PartBuilder()
        infos: list[SourceFileInfo] = []
        for path in sorted(files):
            try:
                doc = load_workflow(files[path], path)
            except ValueError as exc:  # one broken workflow must not fail a whole repository scan
                b.warn(str(exc))
                continue
            local = 0
            for u in iter_uses(doc, files[path]):
                if u.kind == "local":
                    local += 1
                    continue
                if u.kind == "docker":
                    image, tag, digest = split_image(u.raw[len("docker://"):] if u.raw.startswith("docker://") else u.raw)
                    status = "pinned" if digest else ("declared" if tag else "unresolved")
                    b.add(make_component(
                        "docker", image, digest or tag, status, u.raw, "direct", path, "ci",
                        purl_name=image.rsplit("/", 1)[-1], component_type="container",
                        notes=[f"Container used by CI job '{u.job}'."]))
                    continue
                pinned = bool(u.ref and SHA_RE.match(u.ref))
                what = "reusable workflow" if u.kind == "reusable-workflow" else "action"
                b.add(make_component(
                    ECO, u.name, u.ref, "pinned" if pinned else ("declared" if u.ref else "unresolved"),
                    u.raw, "direct", path, "ci",
                    notes=[f"GitHub Actions {what} used by job '{u.job}'"
                           + ("" if pinned else " (referenced by a movable tag/branch, not a commit SHA)") + "."]))
            if local:
                b.warn(f"{path}: {local} local action(s) (./...) live in this repository and were not analysed as dependencies.")
            infos.append(SourceFileInfo(
                path=path, format="github-workflow", support_level=FORMAT_REGISTRY["github-workflow"][0], ecosystem=ECO,
                component_count=sum(1 for c in b.components.values() if path in c.source_files),
                provides_transitive=False, notes=[FORMAT_REGISTRY["github-workflow"][1]],
            ))
        if infos:
            b.limit("CI/CD: actions are listed as used; what each action itself downloads at run time is not visible statically.")
        return b.to_part(infos)
