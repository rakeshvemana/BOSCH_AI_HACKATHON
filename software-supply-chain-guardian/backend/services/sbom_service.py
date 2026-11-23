"""SBOM (Software Bill of Materials) generation, validation and import.

What is an SBOM? A machine-readable inventory of the components in your
software. We output CycloneDX 1.6 JSON using the maintained
``cyclonedx-python-lib`` and validate it against the official JSON schema.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any, Optional

from decimal import Decimal

from cyclonedx.model import Property, XsUri
from cyclonedx.model.vulnerability import (
    BomTarget, Vulnerability, VulnerabilityRating, VulnerabilityScoreSource, VulnerabilitySeverity, VulnerabilitySource,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component as CdxComponent, ComponentType
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packageurl import PackageURL

from backend.config import settings
from backend.models import Component, DiscoveryResult, Relationship, ROOT_ID
from backend.analyzers.base import AnalysisPart, make_component

SPEC_VERSION = SchemaVersion.V1_6
ROOT_REF = "root-application"
PROP = "ssc-guardian:"


class SbomError(ValueError):
    pass


# ---------------------------------------------------------------- generation
def _ref(component_id: str) -> str:
    return ROOT_REF if component_id == ROOT_ID else component_id


def generate_cyclonedx(result: DiscoveryResult) -> tuple[dict[str, Any], list[str]]:
    """Build a CycloneDX 1.6 document. Returns (document, notes)."""
    notes: list[str] = []
    bom = Bom()
    root = CdxComponent(name=result.project_name, type=ComponentType.APPLICATION, bom_ref=BomRef(ROOT_REF))
    bom.metadata.component = root

    unresolved = [c for c in result.components if c.version is None]
    partial = bool(unresolved) or result.summary.transitive_resolution != "full-from-lockfile"
    bom.metadata.properties.add(Property(name=PROP + "completeness", value="partial" if partial else "complete-from-lockfile"))
    bom.metadata.properties.add(Property(name=PROP + "stage", value="discovery"))
    if partial:
        notes.append("Partial SBOM: some components have unresolved versions or transitive dependencies could not be resolved.")

    refs: dict[str, CdxComponent] = {}
    for c in result.components:
        ctype = ComponentType.CONTAINER if c.component_type == "container" else ComponentType.LIBRARY
        purl = None
        if c.purl:
            try:
                purl = PackageURL.from_string(c.purl)
            except ValueError:
                purl = None
        cc = CdxComponent(
            name=c.name.split(":", 1)[-1] if c.ecosystem == "maven" else c.name,
            group=c.name.split(":", 1)[0] if c.ecosystem == "maven" and ":" in c.name else None,
            version=c.version, type=ctype, bom_ref=BomRef(c.id), purl=purl,
        )
        cc.properties.add(Property(name=PROP + "version-status", value=c.version_status))
        cc.properties.add(Property(name=PROP + "dependency-type", value=c.dependency_type))
        if c.declared_constraint:
            cc.properties.add(Property(name=PROP + "declared-constraint", value=c.declared_constraint))
        if c.scope:
            cc.properties.add(Property(name=PROP + "scope", value=c.scope))
        bom.components.add(cc)
        refs[c.id] = cc
    refs[ROOT_ID] = root

    children: dict[str, list[str]] = {}
    for r in result.relationships:
        if r.source in refs and r.target in refs:
            children.setdefault(r.source, []).append(r.target)
    for cid, comp in refs.items():
        kids = [refs[k] for k in dict.fromkeys(children.get(cid, []))]
        bom.register_dependency(comp, kids)

    for n, f in enumerate(f for f in result.findings if f.category == "vulnerability" and f.component_id in refs):
        vid = next((i for i in f.vulnerability_ids if i.startswith("CVE-")), None) or (f.vulnerability_ids or [f.id])[0]
        method = None
        if f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1"):
            method = VulnerabilityScoreSource.CVSS_V3_1
        elif f.cvss_vector and f.cvss_vector.startswith("CVSS:3"):
            method = VulnerabilityScoreSource.CVSS_V3
        elif f.cvss_vector and f.cvss_vector.startswith("CVSS:4"):
            method = VulnerabilityScoreSource.CVSS_V4
        bom.vulnerabilities.add(Vulnerability(
            bom_ref=f"vuln-{n + 1}", id=vid, source=VulnerabilitySource(name="OSV", url=XsUri("https://osv.dev")),
            description=f.title[:500],
            ratings=[VulnerabilityRating(
                severity=VulnerabilitySeverity(f.severity),
                score=Decimal(str(f.cvss_score)) if f.cvss_score is not None else None,
                method=method, vector=f.cvss_vector)],
            recommendation=f"Upgrade {f.component_name} to {f.fixed_versions[0]} or later." if f.fixed_versions else None,
            affects=[BomTarget(ref=f.component_id)],
        ))

    doc = json.loads(JsonV1Dot6(bom).output_as_string())
    return doc, notes


def validate_cyclonedx(doc: dict[str, Any] | str, version: SchemaVersion = SPEC_VERSION) -> list[str]:
    """Validate against the official CycloneDX JSON schema. Returns a list of errors (empty = valid)."""
    text = doc if isinstance(doc, str) else json.dumps(doc)
    err = JsonStrictValidator(version).validate_str(text)
    return [] if err is None else [str(err.data)[:500]]


def build_sbom(result: DiscoveryResult) -> tuple[Optional[dict[str, Any]], str, list[str]]:
    """Generate + validate. Returns (sbom or None, status, notes)."""
    if not result.components:
        return None, "not generated (no components discovered)", []
    doc, notes = generate_cyclonedx(result)
    errors = validate_cyclonedx(doc)
    if errors:
        raise SbomError(f"Generated SBOM failed schema validation: {errors[0]}")
    partial = any("completeness" in p["name"] and p["value"] == "partial" for p in doc["metadata"].get("properties", []))
    status = f"CycloneDX {SPEC_VERSION.to_version()} - valid ({'PARTIAL' if partial else 'complete from lockfile'})"
    return doc, status, notes


# -------------------------------------------------------------------- import
_PURL_ECO = {"pypi": "pypi", "npm": "npm", "maven": "maven", "docker": "docker",
             "deb": "os-package", "apk": "os-package", "rpm": "os-package"}


def _component_from_purl(name: str, version: Optional[str], purl: Optional[str], group: Optional[str],
                         source: str, ctype: str = "library", ref: Optional[str] = None) -> Component:
    eco = "other"
    cname = f"{group}:{name}" if group and not name.startswith(group + ":") else name
    if purl:
        try:
            p = PackageURL.from_string(purl)
            eco = _PURL_ECO.get(p.type, "other")
            if eco == "npm" and p.namespace:
                cname = f"{p.namespace}/{p.name}"
            elif eco == "maven" and p.namespace:
                cname = f"{p.namespace}:{p.name}"
            elif eco in ("pypi", "docker", "os-package"):
                cname = name or p.name
            version = version or p.version
        except ValueError:
            purl = None
    cid = purl or ref or f"{eco}:{cname}@{version or 'unresolved'}"
    return Component(
        id=cid, name=cname, ecosystem=eco, version=version, version_status="resolved" if version else "unresolved",
        purl=purl, source_files=[source], component_type="container" if ctype == "container" else "library",
    )


def parse_cyclonedx(doc: dict[str, Any], source: str) -> AnalysisPart:
    spec = str(doc.get("specVersion", ""))
    part = AnalysisPart()
    errors: list[str] = []
    try:
        errors = validate_cyclonedx(doc, SchemaVersion.from_version(spec))
    except (ValueError, KeyError):
        part.warnings.append(f"{source}: unknown or missing CycloneDX specVersion '{spec}'; schema validation skipped.")
    if errors:
        part.warnings.append(f"{source}: SBOM does not fully conform to CycloneDX {spec} schema (imported best-effort): {errors[0][:200]}")

    by_ref: dict[str, str] = {}
    comps: dict[str, Component] = {}

    def walk(items: list[dict]) -> None:
        for it in items or []:
            if not isinstance(it, dict) or "name" not in it:
                continue
            c = _component_from_purl(str(it["name"]), it.get("version"), it.get("purl"), it.get("group"), source,
                                     "container" if it.get("type") == "container" else "library", it.get("bom-ref"))
            comps.setdefault(c.id, c)
            if it.get("bom-ref"):
                by_ref[it["bom-ref"]] = c.id
            walk(it.get("components") or [])

    walk(doc.get("components") or [])
    meta_comp = (doc.get("metadata") or {}).get("component") or {}
    root_ref = meta_comp.get("bom-ref")
    part.project_name = meta_comp.get("name")

    deps = doc.get("dependencies")
    edges: list[Relationship] = []
    root_children: set[str] = set()
    if isinstance(deps, list):
        for d in deps:
            ref = d.get("ref")
            kids = [by_ref[k] for k in d.get("dependsOn", []) if k in by_ref]
            if ref == root_ref or (root_ref is None and ref not in by_ref):
                root_children.update(kids)
            elif ref in by_ref:
                edges += [Relationship(source=by_ref[ref], target=k) for k in kids]
        has_incoming = {e.target for e in edges}
        for cid, c in comps.items():
            if cid in root_children:
                c.dependency_type = "direct"
            elif cid in has_incoming:
                c.dependency_type = "transitive"
            else:
                c.dependency_type = "unknown"
        if not root_children:
            part.limitations.append(f"{source}: SBOM does not identify the application's direct dependencies; "
                                    "components not depended on by others are 'unknown'.")
    else:
        part.limitations.append(f"{source}: SBOM contains no 'dependencies' section, so relationships and direct/transitive "
                                "classification are unavailable (all components are 'unknown').")
    part.components = list(comps.values())
    part.relationships = edges
    unversioned = sum(1 for c in part.components if not c.version)
    if unversioned:
        part.warnings.append(f"{source}: {unversioned} component(s) have no version in the SBOM.")
    return part


def parse_spdx(doc: dict[str, Any], source: str) -> AnalysisPart:
    part = AnalysisPart()
    packages = doc.get("packages") or []
    rels = doc.get("relationships") or []
    by_id: dict[str, Component] = {}
    root_ids: set[str] = set()
    for rel in rels:
        if rel.get("relationshipType") == "DESCRIBES" and rel.get("spdxElementId") == "SPDXRef-DOCUMENT":
            root_ids.add(rel.get("relatedSpdxElement"))
    for rel in rels:
        if rel.get("relationshipType") == "DESCRIBED_BY" and rel.get("relatedSpdxElement") == "SPDXRef-DOCUMENT":
            root_ids.add(rel.get("spdxElementId"))
    root_ids.update(doc.get("documentDescribes") or [])
    for p in packages:
        sid = p.get("SPDXID")
        if not sid or not p.get("name"):
            continue
        if sid in root_ids:
            part.project_name = part.project_name or p["name"]
            continue
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"), None)
        ver = p.get("versionInfo")
        if ver in ("NOASSERTION", "NONE", ""):
            ver = None
        by_id[sid] = _component_from_purl(p["name"], ver, purl, None, source, ref=sid)
    edges: list[Relationship] = []
    direct: set[str] = set()
    for rel in rels:
        t, a, b_ = rel.get("relationshipType"), rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if t == "DEPENDENCY_OF":
            a, b_ = b_, a
            t = "DEPENDS_ON"
        if t != "DEPENDS_ON":
            continue
        if a in root_ids and b_ in by_id:
            direct.add(b_)
        elif a in by_id and b_ in by_id:
            edges.append(Relationship(source=by_id[a].id, target=by_id[b_].id))
    incoming = {e.target for e in edges}
    for sid, c in by_id.items():
        c.dependency_type = "direct" if sid in direct else "transitive" if c.id in incoming else "unknown"
    if not rels:
        part.limitations.append(f"{source}: SPDX document has no relationships; dependency structure is unavailable.")
    part.components = list(by_id.values())
    part.relationships = edges
    return part


def parse_sbom_json(text: str, source: str) -> tuple[str, AnalysisPart]:
    """Return (format_key, AnalysisPart) for a CycloneDX or SPDX JSON document."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{source}: invalid JSON ({str(exc)[:80]}).")
    if not isinstance(doc, dict):
        raise SbomError(f"{source}: SBOM must be a JSON object.")
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx", parse_cyclonedx(doc, source)
    if "spdxVersion" in doc:
        return "spdx", parse_spdx(doc, source)
    raise SbomError(f"{source}: JSON is neither a CycloneDX nor an SPDX document.")


# ----------------------------------------------------------------- Syft (opt)
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,250}$")


def run_syft(image: str, timeout: int = 180) -> dict[str, Any]:
    """Scan an image with Syft (optional, disabled by default, explicit approval required).

    Security: arguments are passed as a list (no shell), the image name is
    validated, and Syft only READS the image; it does not run it.
    """
    if not settings.syft_enabled:
        raise SbomError("Syft integration is disabled. Set SSC_ENABLE_SYFT=true to enable it.")
    exe = shutil.which("syft")
    if not exe:
        raise SbomError("Syft is not installed on the server (https://github.com/anchore/syft).")
    if not _IMAGE_RE.match(image) or image.startswith("-") or image.startswith(("dir:", "file:", "/")):
        raise SbomError("Invalid or unsupported image reference.")
    try:
        proc = subprocess.run([exe, image, "-o", "cyclonedx-json", "-q"], capture_output=True, text=True,
                              timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired:
        raise SbomError("Syft timed out.")
    if proc.returncode != 0:
        raise SbomError("Syft failed to scan the image (is it available locally or pullable?).")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise SbomError("Syft returned unreadable output.")
