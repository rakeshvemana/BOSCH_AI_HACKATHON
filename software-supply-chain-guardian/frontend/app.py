"""Software Supply Chain Guardian - Stage 1 dashboard (Streamlit).

Run from the project root:   streamlit run frontend/app.py
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so `backend` / `frontend` import

from backend.models import ECOSYSTEM_LABELS  # noqa: E402
from backend.services.graph_service import (  # noqa: E402
    TABLE_FALLBACK_NODES, build_figure, dependencies_of, dependents_of, paths_from_root, subgraph_around,
)
from frontend.api_client import ApiError, GuardianClient  # noqa: E402

BACKEND_URL = os.environ.get("SSC_BACKEND_URL", "http://127.0.0.1:8000")
TYPE_LABEL = {"direct": "Direct", "transitive": "Transitive", "unknown": "Unknown"}
STATUS_HELP = {
    "resolved": "From a lockfile / SBOM (actual resolved version)",
    "pinned": "Exact pin written in a manifest",
    "declared": "Declared in a manifest (not guaranteed final)",
    "unresolved": "Unknown - never guessed",
}
RISK_LEVELS = ["critical", "high", "medium", "low", "info"]
RISK_RANK = {r: i for i, r in enumerate(reversed(RISK_LEVELS))}
RISK_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
RULE_LABEL = {
    "known-vulnerability": "Known vulnerability", "typosquatting": "Typosquatting", "install-script": "Install script",
    "unsafe-install-script": "Unsafe install script", "non-registry-source": "Non-registry source",
    "insecure-source": "Insecure (http) source", "missing-integrity": "Missing integrity hash",
    "lockfile-mismatch": "Modified / stale lockfile", "unexpected-dependency": "Unexpected dependency",
    "untrusted-image": "Untrusted image", "remote-script": "Remote script execution",
    "unverified-download": "Unverified download", "unpinned-action": "Unpinned CI action",
    "untrusted-input-in-script": "CI script injection", "dangerous-trigger": "Dangerous CI trigger",
    "version-downgrade": "Suspicious update (downgrade)", "new-dependency": "New dependency",
}

st.set_page_config(page_title="Software Supply Chain Guardian", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 2rem;}
h1 {margin-bottom: 0;}
.subtitle {color:#4b5563; font-size:1.1rem; margin-bottom:1rem;}
div[data-testid="stMetric"] {background:#f3f4f6; border:1px solid #e5e7eb; border-radius:10px; padding:12px 16px;}
</style>""", unsafe_allow_html=True)


@st.cache_resource
def get_client() -> GuardianClient:
    return GuardianClient(BACKEND_URL)


def eco_label(eco: str | None) -> str:
    return ECOSYSTEM_LABELS.get(eco or "", eco or "-")


def worst_risk(result: dict) -> dict[str, tuple[str, int]]:
    """component id -> (highest risk, number of findings)."""
    out: dict[str, tuple[str, int]] = {}
    for f in result.get("findings", []):
        cid = f.get("component_id")
        if not cid:
            continue
        prev, n = out.get(cid, ("info", 0))
        out[cid] = (f["risk"] if RISK_RANK[f["risk"]] > RISK_RANK[prev] or n == 0 else prev, n + 1)
    return out


def inventory_df(result: dict) -> pd.DataFrame:
    risk = worst_risk(result)
    rows = [{
        "Risk": f"{RISK_ICON[risk[c['id']][0]]} {risk[c['id']][0]} ({risk[c['id']][1]})" if c["id"] in risk else "",
        "Package": c["name"],
        "Version": c["version"] or "unresolved",
        "Version source": c["version_status"],
        "Declared constraint": c["declared_constraint"] or "",
        "Ecosystem": eco_label(c["ecosystem"]),
        "Dependency type": TYPE_LABEL.get(c["dependency_type"], c["dependency_type"]),
        "Scope": c["scope"] or "",
        "Source file": ", ".join(c["source_files"]),
        "purl": c["purl"] or "",
    } for c in result["components"]]
    return pd.DataFrame(rows)


# ------------------------------------------------------------------- header
st.title("🛡️ Software Supply Chain Guardian")
st.markdown('<div class="subtitle">Day 1 — Discover the software supply chain, detect risks, and explain what was '
            'found with evidence</div>', unsafe_allow_html=True)

client = get_client()
try:
    client.health()
except ApiError as exc:
    st.error(str(exc))
    st.stop()

# ----------------------------------------------------------------- Section A
st.header("A · Input")
method = st.radio("Input method", ["GitHub repository URL", "Upload files"], horizontal=True, label_visibility="collapsed")
repo_url, uploads = "", []
if method == "GitHub repository URL":
    repo_url = st.text_input("Public GitHub repository", placeholder="https://github.com/owner/repository",
                             help="Only public github.com repositories. The repository is read, never executed.")
else:
    uploads = st.file_uploader(
        "Dependency files or SBOMs (max 5 MB each)", accept_multiple_files=True,
        help=(
            "requirements.txt, pyproject.toml, poetry.lock, uv.lock, package.json, package-lock.json, pom.xml, "
            "Dockerfile, GitHub Actions workflow (.yml), CycloneDX/SPDX JSON. Upload a manifest together with its "
            "lockfile to get transitive data and lockfile checks."))

if st.button("Analyze", type="primary"):
    try:
        with st.status("Analyzing software supply chain…", expanded=True) as status:
            if method == "GitHub repository URL":
                if not repo_url.strip():
                    raise ApiError("Enter a GitHub repository URL.")
                st.write("Retrieving repository metadata (shallow, read-only clone)…")
                result = client.discover_repository(repo_url.strip())
            else:
                if not uploads:
                    raise ApiError("Choose at least one file to upload.")
                st.write(f"Parsing {len(uploads)} file(s)…")
                result = client.discover_files([(f.name, f.getvalue()) for f in uploads])
            st.write("Building dependency graph and SBOM, checking vulnerabilities and suspicious changes…")
            graph = client.get_graph(result["analysis_id"])
            sbom = client.get_sbom(result["analysis_id"])
            st.session_state["analysis"] = {"result": result, "graph": graph, "sbom": sbom}
            status.update(label="Analysis complete", state="complete", expanded=False)
    except ApiError as exc:
        st.session_state.pop("analysis", None)
        st.error(f"❌ {exc}")

data = st.session_state.get("analysis")
if not data:
    st.info("Submit a repository URL or upload dependency files to begin. Sample inputs are in `sample-projects/`.")
    st.stop()

result, graph, sbom = data["result"], data["graph"], data["sbom"]
summary = result["summary"]
risk = result.get("risk") or {}
findings = result.get("findings") or []
changes = result.get("changes")

# ---------------------------------------------------------- Day 1 checkpoint
st.subheader("Day 1 checkpoint")
k1, k2, k3 = st.columns(3)
k1.metric("What is in the application", f"{summary['total_components']} components",
          help="Direct + transitive dependencies, base images and CI actions.")
k2.metric("What changed", (f"{len(changes['changes'])} change(s)" if changes else "first scan"),
          help="Compared with the previous analysis of the same repository / same uploaded file names.")
serious = sum(risk.get("by_risk", {}).get(k, 0) for k in ("critical", "high"))
k3.metric("What appears risky", f"{len(findings)} finding(s)", f"{serious} critical/high" if serious else None,
          delta_color="inverse", help="Known vulnerabilities and suspicious supply-chain signals, with evidence.")

# ----------------------------------------------------------------- Section B
st.header("B · Discovery summary")
st.caption(f"Analysis ID `{result['analysis_id']}` · source: {result['source']}")
c1, c2, c3 = st.columns(3)
c1.metric("Project", summary["project_name"])
c2.metric("Detected ecosystem", ", ".join(eco_label(e) for e in summary["ecosystems"]) or "—")
c3.metric("Total components", summary["total_components"])
c4, c5, c6, c7 = st.columns(4)
c4.metric("Direct", summary["direct_dependencies"])
c5.metric("Transitive", summary["transitive_dependencies"])
c6.metric("Unresolved versions", summary["unresolved_dependencies"],
          help="Components whose version is unknown. We never guess versions.")
c7.metric("Unknown classification", summary["unknown_classification"],
          help="Cannot tell direct from transitive from the supplied files.")
st.markdown(f"**SBOM status:** {summary['sbom_status']}")
level = summary["transitive_resolution"]
if level == "full-from-lockfile":
    st.success("Transitive dependencies were resolved from lockfile / SBOM data.")
elif level == "partial":
    st.warning("Transitive dependencies were resolved for SOME ecosystems only. See limitations.")
else:
    st.warning("Transitive dependencies were NOT resolved (no lockfile / reliable resolution data supplied).")
if result["limitations"]:
    with st.expander(f"Limitations of this result ({len(result['limitations'])})", expanded=True):
        for item in result["limitations"]:
            st.markdown(f"- {item}")
if result["warnings"]:
    with st.expander(f"Warnings ({len(result['warnings'])})"):
        for item in result["warnings"]:
            st.markdown(f"- {item}")
with st.expander("Analysed files and support level"):
    st.dataframe(pd.DataFrame([{
        "File": f["path"], "Format": f["format"], "Support": f["support_level"], "Components": f["component_count"],
        "Provides transitive data": "yes" if f["provides_transitive"] else "no", "Note": " ".join(f["notes"]),
    } for f in result["files"]]), width="stretch", hide_index=True)

# ----------------------------------------------------------------- Section C
st.header("C · What appears risky")
st.caption(f"Vulnerability check: {risk.get('vulnerability_scan', 'not run')}. "
           "Suspicious-change rules: typosquatting, install scripts, lockfile tampering/mismatch, non-registry sources, "
           "untrusted images, remote scripts, unpinned CI actions, CI script injection, version downgrades.")
r_cols = st.columns(5)
for col, lvl in zip(r_cols, RISK_LEVELS):
    col.metric(f"{RISK_ICON[lvl]} {lvl.capitalize()}", risk.get("by_risk", {}).get(lvl, 0))
v1, v2, v3 = st.columns(3)
v1.metric("Known vulnerabilities", risk.get("vulnerabilities", 0))
v2.metric("Vulnerable components", risk.get("vulnerable_components", 0))
v3.metric("Suspicious signals", risk.get("suspicious_signals", 0))

if not findings:
    st.success("No known vulnerabilities or suspicious supply-chain signals were found in what could be checked.")
else:
    g1, g2, g3 = st.columns([2, 2, 3])
    want_risk = g1.multiselect("Risk level", RISK_LEVELS, default=[r for r in RISK_LEVELS if r != "info"])
    rules = sorted({f["rule"] for f in findings})
    want_rule = g2.multiselect("Detected by", rules, format_func=lambda r: RULE_LABEL.get(r, r))
    fq = g3.text_input("Search findings", placeholder="CVE id, package, keyword…")
    shown_f = [f for f in findings
               if (not want_risk or f["risk"] in want_risk) and (not want_rule or f["rule"] in want_rule)
               and (not fq or fq.lower() in " ".join([f["title"], f.get("component_name") or "", *f["vulnerability_ids"]]).lower())]
    st.dataframe(pd.DataFrame([{
        "Risk": f"{RISK_ICON[f['risk']]} {f['risk']}",
        "Severity": f["severity"],
        "Detected by": RULE_LABEL.get(f["rule"], f["rule"]),
        "Finding": f["title"],
        "Component": f.get("component_name") or "—",
        "Version": f.get("component_version") or "",
        "Type": f.get("dependency_type") or "",
        "Fix": ", ".join(f["fixed_versions"]) or ("none published" if f["category"] == "vulnerability" else ""),
    } for f in shown_f]), width="stretch", hide_index=True, height=min(460, 60 + 35 * max(len(shown_f), 1)))
    st.caption(f"Showing {len(shown_f)} of {len(findings)} findings, highest initial risk first. "
               "Initial risk = severity adjusted for context (dev/test-only scope is lowered one level).")

    st.subheader("Evidence")
    limit = 40
    for f in shown_f[:limit]:
        label = f"{RISK_ICON[f['risk']]} {f['risk'].upper()} · {f['title']}"
        with st.expander(label[:180]):
            if f.get("description"):
                # advisory text is Markdown with its own headings; keep them from dwarfing the panel
                st.markdown(re.sub(r"(?m)^#{1,6}\s*(.+)$", r"**\1**", f["description"]))
            e1, e2 = st.columns(2)
            with e1:
                lines = [f"- **What was detected:** {RULE_LABEL.get(f['rule'], f['rule'])}"]
                if f.get("component_name"):
                    lines.append(f"- **Affected component:** `{f['component_name']}` {f.get('component_version') or ''} "
                                 f"({f.get('dependency_type') or 'n/a'}, {eco_label(f.get('ecosystem'))})")
                lines.append(f"- **Severity:** {f['severity']}" + (f" · CVSS {f['cvss_score']}" if f.get("cvss_score") is not None else ""))
                lines.append(f"- **Initial risk:** {f['risk']} — {f['risk_rationale']}")
                if f["vulnerability_ids"]:
                    lines.append("- **Advisories:** " + ", ".join(f["vulnerability_ids"]))
                if f["fixed_versions"]:
                    lines.append(f"- **Fixed in:** {', '.join(f['fixed_versions'])}")
                elif f["category"] == "vulnerability":
                    lines.append("- **Fixed in:** no fixed version published yet")
                st.markdown("\n".join(lines))
                if f.get("cvss_vector"):
                    st.caption(f"CVSS vector: `{f['cvss_vector']}`")
            with e2:
                if f["paths"]:
                    st.markdown("**Dependency path** (how it gets into the application):")
                    for p in f["paths"]:
                        st.code(" → ".join(p), language=None)
                st.markdown("**Supporting evidence:**")
                st.markdown("\n".join(
                    f"- `{e['source']}{':' + str(e['line']) if e.get('line') else ''}` — {e['detail']}" for e in f["evidence"]))
                if f["references"]:
                    st.markdown("**References:** " + " · ".join(f"[{i + 1}]({u})" for i, u in enumerate(f["references"][:5])))
    if len(shown_f) > limit:
        st.caption(f"Evidence shown for the first {limit}; narrow the filters or download the findings report (section H).")

# ----------------------------------------------------------------- Section D
st.header("D · What changed")
if not changes:
    st.info("This is the first analysis of this source, so there is nothing to compare yet. Analyse the same repository "
            "again later (or re-upload the same file names after a change) to see what changed.")
else:
    st.caption(f"Compared with analysis `{changes['previous_analysis_id']}` from "
               f"{str(changes['previous_created_at'])[:16].replace('T', ' ')} UTC.")
    w = st.columns(5)
    for col, k in zip(w, ["added", "removed", "upgraded", "downgraded", "changed"]):
        col.metric(k.capitalize(), changes[k])
    if changes["changes"]:
        order = {"downgraded": 0, "added": 1, "removed": 2, "changed": 3, "upgraded": 4}
        st.dataframe(pd.DataFrame([{
            "Change": c["change"], "Package": c["name"], "Ecosystem": eco_label(c["ecosystem"]),
            "Before": ", ".join(c["old_versions"]), "After": ", ".join(c["new_versions"]),
            "Type": c.get("dependency_type") or "",
        } for c in sorted(changes["changes"], key=lambda c: (order[c["change"]], c["name"]))]),
            width="stretch", hide_index=True, height=min(400, 60 + 35 * len(changes["changes"])))
        st.caption("Downgrades and new direct dependencies are also listed as findings in section C.")
    else:
        st.success("No dependency changes since the previous analysis.")

# ----------------------------------------------------------------- Section E
st.header("E · Dependency inventory")
df = inventory_df(result)
f1, f2, f3 = st.columns([3, 2, 2])
query = f1.text_input("Search packages", placeholder="e.g. flask")
types = f2.multiselect("Dependency type", sorted(df["Dependency type"].unique()) if len(df) else [], default=None)
ecos = f3.multiselect("Ecosystem", sorted(df["Ecosystem"].unique()) if len(df) else [], default=None)
view = df
if query:
    view = view[view["Package"].str.contains(query, case=False, regex=False) | view["purl"].str.contains(query, case=False, regex=False)]
if types:
    view = view[view["Dependency type"].isin(types)]
if ecos:
    view = view[view["Ecosystem"].isin(ecos)]
st.dataframe(view, width="stretch", hide_index=True, height=min(520, 60 + 35 * max(len(view), 1)))
st.caption(f"Showing {len(view)} of {len(df)} components. Version source — " + " · ".join(f"**{k}**: {v}" for k, v in STATUS_HELP.items()))

# Dockerfile metadata
if result["docker"]:
    st.subheader("Dockerfile metadata (static analysis — nothing was built or scanned)")
    for meta in result["docker"]:
        st.markdown(f"**{meta['source_file']}** — {meta['stage_count']} stage(s)")
        st.dataframe(pd.DataFrame([{
            "Stage": i["stage_index"], "Name": i["stage_name"] or "", "Image": i["image"], "Tag": i["tag"] or "",
            "Digest": (i["digest"] or "")[:19], "Final stage": i["is_final_stage"], "Notes": " ".join(i["notes"]),
        } for i in meta["images"]]), width="stretch", hide_index=True)
        if meta["installs"]:
            st.markdown("Packages requested by the Dockerfile (declared, not verified as installed):")
            st.dataframe(pd.DataFrame([{"Manager": i["manager"], "Packages": ", ".join(i["packages"]), "Line": i["line"]}
                                       for i in meta["installs"]]), width="stretch", hide_index=True)
        if meta["copied_files"]:
            st.markdown("Local files copied: " + ", ".join(f"`{p}`" for p in meta["copied_files"]))

# ----------------------------------------------------------------- Section F
st.header("F · Dependency graph")
gs = graph["stats"]
st.caption(f"{gs['nodes']} nodes · {gs['edges']} edges · depth {gs['max_depth']} · "
           f"{gs['shared_components']} shared components · {gs['cycles']} cycle(s)")
names = {n["id"]: n for n in graph["nodes"]}
options = [""] + sorted(names, key=lambda i: names[i]["label"].lower())
selected = st.selectbox("Inspect a component", options, format_func=lambda i: "— select —" if not i else names[i]["label"])
focus = st.checkbox("Focus on selected component (show only its dependency subtree and paths from the root)", value=False,
                    disabled=not selected)
shown = subgraph_around(graph, selected, depth=3) if (focus and selected) else graph

if len(shown["nodes"]) > TABLE_FALLBACK_NODES:
    st.warning(f"This graph has {len(shown['nodes'])} nodes — too many for a readable drawing. Showing a table of "
               "relationships instead. Select a component and tick 'Focus' to draw its subtree.")
    st.dataframe(pd.DataFrame([{
        "Parent": names[e["source"]]["label"] if e["source"] in names else e["source"],
        "Depends on": names[e["target"]]["label"] if e["target"] in names else e["target"],
        "Requirement": e["requirement"] or "", "Inferred": e["inferred"],
    } for e in graph["edges"]]), width="stretch", hide_index=True, height=420)
else:
    flags = {cid: r for cid, (r, _n) in worst_risk(result).items()}
    st.plotly_chart(build_figure(shown, highlight=selected or None, flags=flags), width="stretch")
    st.caption("Read left to right: your app → its direct dependencies → what those pull in. "
               "Blue = direct · teal = transitive · amber = unknown classification · diamond = part of a dependency cycle. "
               "⚠ with a coloured ring = has findings (dark red critical, red high, orange medium, yellow low). "
               "Pick a component above to highlight its links in red. Hover a node for details.")

if selected:
    n = names[selected]
    st.subheader(f"Details: {n['name']}")
    comp = next((c for c in result["components"] if c["id"] == selected), None)
    d1, d2 = st.columns(2)
    with d1:
        st.markdown(f"- **Version:** {n['version'] or 'unresolved'} ({n['version_status']})\n- **Type:** {n['dependency_type']}\n"
                    f"- **Ecosystem:** {eco_label(n['ecosystem'])}\n- **Depth from root:** {n['depth']}\n- **ID:** `{selected}`")
        if comp:
            st.markdown(f"- **Declared constraint:** {comp['declared_constraint'] or '—'}\n- **Scope:** {comp['scope'] or '—'}")
            for note in comp["notes"]:
                st.markdown(f"  - ℹ️ {note}")
    with d2:
        st.markdown("**Required by:** " + (", ".join(names[i]["label"] for i in dependents_of(graph, selected) if i in names) or "—"))
        st.markdown("**Depends on:** " + (", ".join(names[i]["label"] for i in dependencies_of(graph, selected) if i in names) or "—"))
    paths = paths_from_root(graph, selected)
    if paths:
        st.markdown(f"**Dependency path(s) from the application ({len(paths)} shown):**")
        for p in paths:
            st.code(" → ".join(names[i]["name"] for i in p), language=None)
    own = [f for f in findings if f.get("component_id") == selected]
    if own:
        st.markdown(f"**Findings for this component ({len(own)}):**")
        for f in own:
            st.markdown(f"- {RISK_ICON[f['risk']]} **{f['risk']}** · {f['title']}")

# ----------------------------------------------------------------- Section G
st.header("G · SBOM")
if sbom:
    props = {p["name"]: p["value"] for p in sbom.get("metadata", {}).get("properties", [])}
    e1, e2, e3 = st.columns(3)
    e1.metric("Format", f"CycloneDX {sbom['specVersion']}")
    e2.metric("Components", len(sbom.get("components", [])))
    e3.metric("Completeness", props.get("ssc-guardian:completeness", "—"))
    st.markdown(f"Validation: **{summary['sbom_status']}** · includes **{len(sbom.get('vulnerabilities', []))}** "
                "known vulnerabilit(ies) in its CycloneDX `vulnerabilities` section.")
    st.dataframe(pd.DataFrame([{
        "Name": c["name"], "Group": c.get("group", ""), "Version": c.get("version", "unresolved"), "Type": c["type"],
        "purl": c.get("purl", ""),
    } for c in sbom.get("components", [])]), width="stretch", hide_index=True, height=300)
    st.download_button("⬇ Download CycloneDX SBOM (JSON)", json.dumps(sbom, indent=2), file_name="sbom.cdx.json",
                       mime="application/vnd.cyclonedx+json")
else:
    st.info("No SBOM was generated (no components were discovered).")

# ----------------------------------------------------------------- Section H
st.header("H · Export")
x1, x2, x3 = st.columns(3)
x1.download_button("⬇ Full report (JSON)", json.dumps(result, indent=2), "guardian-report.json", "application/json")
x2.download_button("⬇ Dependency inventory (CSV)", df.to_csv(index=False), "dependency-inventory.csv", "text/csv")
x3.download_button("⬇ Dependency graph (JSON)", json.dumps(graph, indent=2), "dependency-graph.json", "application/json")
y1, y2, y3 = st.columns(3)
y1.download_button("⬇ Findings with evidence (JSON)", json.dumps(findings, indent=2), "findings.json", "application/json")
y2.download_button("⬇ Findings (CSV)", pd.DataFrame([{
    "risk": f["risk"], "severity": f["severity"], "rule": f["rule"], "title": f["title"],
    "component": f.get("component_name") or "", "version": f.get("component_version") or "",
    "dependency_type": f.get("dependency_type") or "", "advisories": " ".join(f["vulnerability_ids"]),
    "cvss": f.get("cvss_score") if f.get("cvss_score") is not None else "", "fixed_in": " ".join(f["fixed_versions"]),
    "path": " | ".join(" > ".join(p) for p in f["paths"]),
    "evidence": " | ".join(f"{e['source']}{':' + str(e['line']) if e.get('line') else ''}: {e['detail']}" for e in f["evidence"]),
    "risk_rationale": f["risk_rationale"],
} for f in findings]).to_csv(index=False), "findings.csv", "text/csv")
y3.download_button("⬇ CycloneDX SBOM + vulnerabilities (JSON)", json.dumps(sbom, indent=2) if sbom else "{}",
                   "sbom.cdx.json", "application/vnd.cyclonedx+json", disabled=not sbom)
