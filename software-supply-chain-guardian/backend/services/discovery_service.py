"""Orchestrates discovery: classify files -> run analyzers -> merge -> SBOM -> result."""
from __future__ import annotations

import uuid
from collections import Counter
from typing import Any, Optional, Union

from backend.analyzers.base import AnalysisPart
from backend.analyzers.docker_analyzer import DockerAnalyzer
from backend.analyzers.java_analyzer import JavaAnalyzer
from backend.analyzers.javascript_analyzer import JavaScriptAnalyzer
from backend.analyzers.python_analyzer import PythonAnalyzer
from backend.analyzers.workflow_analyzer import WorkflowAnalyzer
from backend.config import settings
from backend.models import (
    DiscoveryResult, DiscoverySummary, SourceFileInfo, SupportLevel,
)
from backend.services import risk_service, sbom_service, vulnerability_service
from backend.services.dependency_resolver import attach_root, merge_parts, transitive_resolution_level
from backend.utils.file_utils import (
    FORMAT_REGISTRY, FileValidationError, classify_file, decode_text, safe_basename,
)

PY_FORMATS = {"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"}
JS_FORMATS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}


def supported_formats() -> list[dict[str, Any]]:
    return [{"format": k, "support_level": v[0].value, "notes": v[1]} for k, v in FORMAT_REGISTRY.items()]


def _run(analyzer, files: dict[str, str]) -> AnalysisPart:
    try:
        return analyzer.analyze(files)
    except FileValidationError:
        raise
    except ValueError as exc:  # analyzers raise ValueError with a safe message
        raise FileValidationError(str(exc), 422)


def discover(
    raw_files: dict[str, Union[bytes, str]],
    input_type: str,
    source: str,
    project_hint: Optional[str] = None,
    extra_warnings: Optional[list[str]] = None,
) -> tuple[DiscoveryResult, Optional[dict[str, Any]]]:
    """Analyse already-validated files. Returns (result, cyclonedx_sbom_or_None)."""
    texts: dict[str, str] = {}
    for path, data in raw_files.items():
        texts[path] = decode_text(data, path) if isinstance(data, bytes) else data

    groups: dict[str, dict[str, str]] = {"py": {}, "js": {}, "java": {}, "docker": {}, "ci": {}}
    sboms: dict[str, tuple[str, str]] = {}
    unsupported: list[str] = []
    formats: dict[str, str] = {}
    for path, text in texts.items():
        fmt = classify_file(path, text[:2000])
        if fmt:
            formats[path] = fmt
        if fmt == "github-workflow":
            groups["ci"][path] = text
        elif fmt in PY_FORMATS:
            groups["py"][path] = text
        elif fmt in JS_FORMATS:
            groups["js"][path] = text
        elif fmt == "pom.xml":
            groups["java"][path] = text
        elif fmt == "Dockerfile":
            groups["docker"][path] = text
        elif fmt in {"cyclonedx", "spdx"}:
            sboms[path] = (fmt, text)
        else:
            unsupported.append(path)

    if unsupported and input_type == "file":
        names = ", ".join(f"'{p}'" for p in unsupported[:5])
        raise FileValidationError(
            f"Unsupported file type: {names}. Supported: requirements.txt, pyproject.toml, poetry.lock, uv.lock, package.json, "
            "package-lock.json, pom.xml, Dockerfile, GitHub Actions workflow (.yml), CycloneDX JSON, SPDX JSON "
            "(yarn.lock and pnpm-lock.yaml are recognised but "
            "not yet supported).", 415)

    parts: list[AnalysisPart] = []
    if groups["py"]:
        parts.append(_run(PythonAnalyzer(), groups["py"]))
    if groups["js"]:
        parts.append(_run(JavaScriptAnalyzer(), groups["js"]))
    if groups["java"]:
        parts.append(_run(JavaAnalyzer(), groups["java"]))
    if groups["docker"]:
        parts.append(_run(DockerAnalyzer(), groups["docker"]))
    if groups["ci"]:
        parts.append(_run(WorkflowAnalyzer(), groups["ci"]))
    for path, (fmt, text) in sboms.items():
        try:
            _fmt, part = sbom_service.parse_sbom_json(text, path)
        except sbom_service.SbomError as exc:
            raise FileValidationError(str(exc), 422)
        level = FORMAT_REGISTRY[fmt][0]
        part.files.append(SourceFileInfo(
            path=path, format=fmt, support_level=level, ecosystem=None, component_count=len(part.components),
            provides_transitive=bool(part.relationships), notes=[FORMAT_REGISTRY[fmt][1]]))
        parts.append(part)

    all_infos = [i for p in parts for i in p.files]
    if input_type == "file" and all_infos and all(i.support_level == SupportLevel.NONE for i in all_infos):
        raise FileValidationError(
            "; ".join(f"{i.path}: {i.notes[0]}" for i in all_infos) or "Format not yet supported.", 415)

    components, relationships = merge_parts(parts)
    warnings = list(extra_warnings or []) + [w for p in parts for w in p.warnings]
    limitations: list[str] = []
    for p in parts:
        limitations += [l for l in p.limitations if l not in limitations]

    if input_type == "file" and not components and not any(p.docker for p in parts):
        detail = warnings[0] if warnings else "the file contains no dependencies"
        if warnings or not all_infos:
            raise FileValidationError(f"No dependencies could be extracted: {detail}", 422)

    relationships, w = attach_root(components, relationships)
    warnings += w

    project_name = project_hint or next((p.project_name for p in parts if p.project_name), None)
    if not project_name:
        project_name = (safe_basename(next(iter(texts))) or "application") if texts else "application"

    unsupported_in_repo = [i for i in all_infos if i.support_level == SupportLevel.NONE]
    for i in unsupported_in_repo:
        limitations.append(f"{i.path}: {i.format} is not yet supported and was not parsed.")
    if not components and not any(p.docker for p in parts):
        limitations.append("No dependency information could be extracted from the supplied inputs.")

    eco_counts = (Counter(c.ecosystem for c in components if c.ecosystem not in {"docker", "github-actions"})
                  or Counter(c.ecosystem for c in components))
    summary = DiscoverySummary(
        project_name=project_name,
        primary_ecosystem=eco_counts.most_common(1)[0][0] if eco_counts else None,
        ecosystems=sorted({c.ecosystem for c in components}),
        total_components=len(components),
        direct_dependencies=sum(1 for c in components if c.dependency_type == "direct"),
        transitive_dependencies=sum(1 for c in components if c.dependency_type == "transitive"),
        unknown_classification=sum(1 for c in components if c.dependency_type == "unknown"),
        unresolved_dependencies=sum(1 for c in components if c.version is None),
        transitive_resolution=transitive_resolution_level(components, all_infos),
    )

    result = DiscoveryResult(
        analysis_id=uuid.uuid4().hex, input_type=input_type, source=source,  # type: ignore[arg-type]
        project_name=project_name, summary=summary, files=all_infos, components=components,
        relationships=relationships, docker=[d for p in parts for d in p.docker],
        limitations=limitations, warnings=warnings,
    )
    detect_risks(result, texts, formats)
    sbom_doc, status, notes = sbom_service.build_sbom(result)
    result.sbom_status = status
    result.summary.sbom_status = status
    result.warnings += notes
    return result, sbom_doc


def detect_risks(result: DiscoveryResult, texts: dict[str, str], formats: dict[str, str]) -> None:
    """Day-1 detection: suspicious supply-chain signals + known vulnerabilities (OSV.dev), in place."""
    findings = risk_service.detect_suspicious(result, texts, formats)
    if not result.components:
        risk_service.finalize(result, findings, "not run (no components)", 0, 0)
        return
    if not settings.vuln_scan_enabled:
        risk_service.finalize(result, findings, "disabled (SSC_VULN_SCAN=false)", 0, len(result.components))
        return
    outcome = vulnerability_service.scan(result.components)
    result.warnings += outcome.warnings
    if outcome.not_checked:
        result.limitations.append(
            f"Vulnerabilities: {outcome.not_checked} component(s) were not checked because their version is unresolved "
            "or their ecosystem (e.g. Docker images) has no package advisory database here.")
    risk_service.finalize(result, findings + outcome.findings, outcome.status, outcome.checked, outcome.not_checked)


def discover_uploads(uploads: dict[str, bytes]) -> tuple[DiscoveryResult, Optional[dict[str, Any]]]:
    """Entry point for uploaded files. Names are reduced to a safe base name."""
    clean: dict[str, bytes] = {}
    for name, data in uploads.items():
        base = safe_basename(name)
        if not base:
            raise FileValidationError("Uploaded file has no usable name.")
        if base in clean:
            raise FileValidationError(f"Duplicate upload name '{base}'. Upload each file once.")
        clean[base] = data
    # A pasted pair like requirements.txt + package.json is analysed together, in a single directory.
    return discover(clean, "file", ", ".join(clean))


def discover_repository(repo_files) -> tuple[DiscoveryResult, Optional[dict[str, Any]]]:
    """Analyse the files returned by RepositoryService.fetch_files."""
    if not repo_files.files:
        raise FileValidationError(
            "No supported dependency files (requirements.txt, pyproject.toml, lockfiles, package.json, pom.xml, "
            "Dockerfile, SBOM JSON) were found in this repository.", 422)
    notes = list(repo_files.warnings)
    if repo_files.commit:
        notes.append(f"Analysed commit {repo_files.commit} of the default branch.")
    return discover(repo_files.files, "repository", repo_files.repo.web_url,
                    project_hint=repo_files.repo.name, extra_warnings=notes)


def discover_image(cyclonedx_doc: dict[str, Any], image: str) -> tuple[DiscoveryResult, Optional[dict[str, Any]]]:
    """Wrap a Syft-produced CycloneDX document as a discovery result (image scan, not Dockerfile analysis)."""
    import json
    return discover({f"{safe_basename(image) or 'image'}.cdx.json": json.dumps(cyclonedx_doc)}, "image", f"image:{image}",
                    project_hint=image)
