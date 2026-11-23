# 🛡️ Software Supply Chain Guardian — Day 1: Build the Guardian's Eyes

Discovers a project's software supply chain, detects risks, and explains what it found **with evidence**, from a public GitHub repository or uploaded files.

**Day 1 checkpoint: "Show us what is in the application, what changed, and what appears risky."**

| Day 1 step | What the Guardian does |
|---|---|
| 1 · Discover components | Parses manifests and lockfiles: direct **and** transitive dependencies with names and versions |
| 2 · Build the supply chain view | Dependency graph, CycloneDX 1.6 SBOM, the file each component comes from, Dockerfile base images **and GitHub Actions CI/CD workflows** |
| 3 · Detect vulnerabilities | Looks up every versioned component in [OSV.dev](https://osv.dev): CVE / GHSA ids, CVSS severity, fixed versions, and the dependency path that pulls a vulnerable transitive package in |
| 4 · Detect suspicious changes | Typosquatting, install scripts, modified/stale lockfiles, unexpected dependencies, non-registry or http sources, untrusted images, `curl \| sh`, unpinned CI actions, CI script injection, downgrades since the last scan |
| 5 · Present evidence | Every finding says what was detected, which component, its dependency path, file + line evidence, and an initial risk level with the reasoning |

> Day 1 is about visibility and detection. It does **not** change your code or apply fixes; remediation is Day 2.

## Quick start

Requires Python 3.11+ and `git` (Python 3.14 was used for development).

```bash
cd software-supply-chain-guardian
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Terminal 1 – backend (API docs at http://127.0.0.1:8000/docs)
.venv/bin/uvicorn backend.main:app --port 8000

# Terminal 2 – dashboard (http://localhost:8501)
.venv/bin/streamlit run frontend/app.py
```

If port 8000 is already used on your machine, pick another and tell the dashboard:

```bash
.venv/bin/uvicorn backend.main:app --port 8010
SSC_BACKEND_URL=http://127.0.0.1:8010 .venv/bin/streamlit run frontend/app.py
```

### Try the samples

In the dashboard choose **Upload files** and select (several files at once is fine — upload a manifest *together with* its lockfile):

| Sample | Upload | What you will see |
|---|---|---|
| `sample-projects/python-sample/` | `requirements.txt` | 4 direct, pinned versions; **no** transitive data (and a clear limitation notice). Known CVEs, e.g. a **critical** one in PyYAML 5.3.1 (fixed in 5.4) |
| `sample-projects/python-uv-sample/` | `pyproject.toml` + `uv.lock` | 5 direct + 23 transitive, all resolved, valid complete SBOM. Vulnerable *transitive* `urllib3`, traced as app → requests → urllib3. Note: the lock is a *universal* lock, so `requests`/`pytest` legitimately appear in two versions selected by Python-version markers |
| `sample-projects/javascript-sample/` | `package.json` + `package-lock.json` | 3 direct, ~135 transitive (real lockfile generated with `npm install --package-lock-only --ignore-scripts`). Vulnerabilities via express → path-to-regexp / body-parser; `fsevents` install script |
| `sample-projects/java-sample/` | `pom.xml` | 5 declared dependencies; the range-versioned `guava` stays **unresolved** (and so is not vulnerability-checked); no transitive claims |
| `sample-projects/docker-sample/` | `Dockerfile` | multi-stage base images, ARG substitution, digest pin, requested packages — static metadata only. Flags `nginx:latest` and the un-digested `python` image |
| `sample-projects/suspicious-sample/` | all three files | A deliberately tampered project: hand-edited lockfile, typosquat, `curl \| sh` install hook, http source, unpinned and injectable CI workflow |

**What changed:** analyse the same repository (or upload the same file names) twice. The second result compares against the first: added, removed, upgraded and **downgraded** packages.

For a repository choose **GitHub repository URL**, e.g. `https://github.com/pallets/click`.

Or use the API directly:

```bash
curl -s -F "files=@sample-projects/python-uv-sample/pyproject.toml" \
        -F "files=@sample-projects/python-uv-sample/uv.lock" http://127.0.0.1:8000/api/discover/file
curl -s -X POST http://127.0.0.1:8000/api/discover/repository \
     -H 'content-type: application/json' -d '{"url":"https://github.com/pallets/click"}'
```

### Tests

```bash
.venv/bin/python -m pytest                              # offline: no GitHub, registry or OSV access needed (OSV is faked)
.venv/bin/python -m pytest tests/test_e2e_live.py --run-e2e   # optional live test against public GitHub
```

## Detection (Day 1 steps 3–5)

### Known vulnerabilities
Every component with a concrete version in PyPI, npm, Maven or GitHub Actions goes to [OSV.dev](https://osv.dev) in **one batch request** (no API key; only package names and versions are sent). Each advisory is fetched once and cached. Duplicates of the same flaw (`GHSA-…` and `PYSEC-…` listing each other as aliases) are merged into one finding, titled by its CVE id.

* **Severity**: the CVSS v3 base score is computed from the advisory's vector (FIRST formula); if there is none, the advisory's own label (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`) is used.
* **Fix**: the lowest `fixed` version above yours, from the advisory's affected ranges.
* **Source**: the shortest dependency path(s) from your app to the vulnerable package, e.g. `app → express 4.18.2 → path-to-regexp 0.1.7`.
* **SBOM**: vulnerabilities are also written to the CycloneDX `vulnerabilities` section (schema-validated).
* Components with an **unresolved** version are **not** checked (we never guess); they are counted in the result. If OSV is unreachable the analysis still completes and says vulnerabilities were *not* checked.

### Suspicious supply-chain signals
| Rule | Fires when | Evidence |
|---|---|---|
| Typosquatting | a name is one edit from a popular PyPI/npm package (`reqeusts`), or the same name with different separators (`crossenv` vs `cross-env`) | declaring file + the popular name |
| Install script / unsafe install script | npm lockfile `hasInstallScript`; the project's own `preinstall`/`postinstall` downloads or evals code | lockfile entry / package.json line |
| Modified or stale lockfile | package.json ↔ package-lock.json, or pyproject.toml ↔ uv.lock disagree (missing, extra or different requirement) | both files |
| Unexpected dependency | lockfile declares a direct dependency the manifest doesn't; npm `extraneous`; a locked package nothing requires | lockfile entry |
| Non-registry / insecure source / missing integrity | lockfile entry from git, a URL, another index, plain `http://`, or without an integrity hash | `resolved` / `source` line |
| Untrusted image | `:latest` or no tag, no digest pin, a Docker Hub user image, an unrecognised registry (Dockerfile and CI containers) | FROM / `container:` line |
| Remote script / unverified download | `curl … \| sh` in a Dockerfile `RUN` or CI `run:`; `ADD https://…` without `--checksum` | the instruction |
| Unpinned CI action | `uses: owner/repo@tag-or-branch` instead of a commit SHA (branches and third-party owners rank higher) | workflow line |
| CI script injection / dangerous trigger | `${{ github.event.pull_request.title }}`-style input inside `run:`; `pull_request_target` that checks out PR code | workflow lines |
| Version downgrade / new dependency | compared with the previous analysis of the same source | previous analysis id + current file |

### Initial risk level
Each finding has a **severity** (the issue on its own) and an **initial risk** for this project, with the reasoning spelled out: dependencies only used in `dev`/`test`/`docs`/`lint`/`optional` scope are lowered one level (CI is **not** lowered — CI jobs hold secrets). Findings are sorted by initial risk.

## Key concept: declared vs resolved

Every component carries both a **declared constraint** (what a human wrote, e.g. `requests>=2.28`) and a **version** with a **version source**:

| Version source | Meaning |
|---|---|
| `resolved` | Taken from a lockfile or SBOM — the real answer |
| `pinned` | Exact pin in a manifest (`Flask==2.2.2`, exact npm version, Docker digest) |
| `declared` | Version written in a manifest that may not be final (Maven version, Docker tag) |
| `unresolved` | Unknown. `version` is empty. **Never guessed.** |

Dependency type is `direct`, `transitive`, or `unknown` (when the files cannot tell — e.g. a lone `poetry.lock`).

## Supported formats

| Format | Level | Notes |
|---|---|---|
| `uv.lock` | **Fully supported** | Versions, relationships, direct deps of the project |
| `package-lock.json` | **Fully supported** | v2/v3 (Node resolution rule applied to `node_modules` paths); v1 relationships supported (needs `package.json` for direct/transitive) |
| `poetry.lock` | **Fully supported** | Versions + relationships; direct/transitive needs `pyproject.toml` alongside, otherwise top-level packages are `unknown` |
| CycloneDX JSON | **Fully supported** (import) | Components and dependency graph exactly as provided; schema-validated |
| `requirements*.txt` | Partially supported | Direct only; exact `==` pins shown as `pinned`; no transitive resolution |
| `pyproject.toml` | Partially supported | PEP 621, PEP 735 groups, build requirements, Poetry. Constraints only without a lockfile |
| `package.json` | Partially supported | Direct only; ranges stay unresolved without a lockfile |
| `pom.xml` | Partially supported | Declared deps; `${properties}` and same-file `dependencyManagement` resolved; parent/BOM versions and ranges unresolved; **no transitive tree** |
| SPDX 2.x JSON | Partially supported (import) | Packages + `DEPENDS_ON` relationships |
| `Dockerfile` | Partially supported | Static metadata: base images/tags/digests, stages, ARG defaults, install commands, copied files. **Not** an OS package list |
| GitHub Actions workflow | Partially supported | `.github/workflows/*.yml` (or an uploaded workflow): actions, reusable workflows and job/service containers, with pin status. What an action downloads at run time is not visible |
| `yarn.lock`, `pnpm-lock.yaml` | **Not yet supported** | Recognised and reported explicitly; not parsed |

## Architecture

```
backend/
  main.py                    FastAPI app (create_app factory), endpoints, error handling
  models.py                  Pydantic models (Component, Relationship, DiscoveryResult, Graph*)
  config.py                  limits (env-overridable)
  analyzers/                 python_ / javascript_ / java_ / docker_ / workflow_analyzer + base (purl IDs, merging)
  services/
    discovery_service.py     classify files -> analyzers -> merge -> detect -> SBOM -> result
    dependency_resolver.py   merge duplicates, attach root, resolution-level honesty check
    graph_service.py         NetworkX graph, stats, cycles, Plotly figure, subtree, shortest paths (PathFinder)
    vulnerability_service.py OSV.dev batch lookup, alias merging, CVSS v3 scoring, fixed versions
    risk_service.py          suspicious-change rules, change diff vs previous analysis, risk summary
    popular_packages.py      popular PyPI/npm names for typosquat detection
    sbom_service.py          CycloneDX 1.6 generate (+vulnerabilities) + validate, CycloneDX/SPDX import, optional Syft
    repository_service.py    safe GitHub retrieval
    storage_service.py       bounded SQLite storage (newest 200 analyses), previous-analysis lookup
  utils/file_utils.py        format registry, classification, path/decoding safety
frontend/                    Streamlit dashboard (app.py) + HTTP client (api_client.py)
sample-projects/  tests/  reports/
```

Design choices worth knowing:
* **We do not write a resolver.** Transitive data comes only from lockfiles/SBOMs produced by the ecosystem's own tools. Without them, transitive dependencies are reported as *not discovered*.
* **Stable IDs** are Package URLs (`pkg:pypi/flask@2.2.2`), so a package reachable through several parents is one graph node.
* The graph's root is the application; **cycles** are detected (strongly-connected components) and drawn safely.
* Graphs above 250 nodes switch to a relationship **table**; "Focus" draws one component's subtree.

## API

| Endpoint | Purpose |
|---|---|
| `GET /` | App metadata + format support levels |
| `GET /health` | Health |
| `POST /api/discover/file` | Multipart `files` (1–10): manifests, lockfiles, SBOMs, Dockerfile |
| `POST /api/discover/repository` | `{"url": "https://github.com/owner/repo"}` |
| `GET /api/discovery/{id}` · `/graph` · `/sbom` | Stored result (incl. `findings`, `risk`, `changes`), graph JSON, CycloneDX SBOM |
| `GET /api/discovery/{id}/findings` | Findings only, highest initial risk first, each with paths and evidence |
| `POST /api/discover/image` | Optional Syft image scan — **disabled by default**, needs `approve=true` and `SSC_ENABLE_SYFT=true` |

Errors: 400 bad URL/input · 404 not found · 413 too large · 415 unsupported type · 422 unparseable · 502/504 repository retrieval.

## Security design

* Uploads are parsed **in memory as data**; never written to disk, never executed. Names are reduced to a base name (no traversal). Limits: 5 MB/file, 10 files.
* Repository URLs: `https` + host exactly `github.com`, `owner/repo` only — no credentials, ports, queries, IPs, localhost, internal hosts (prevents SSRF).
* Retrieval uses `git` with an argument list (no shell), minimal environment (no inherited tokens), prompts/hooks/credential helpers off, `https` protocol only, shallow blob-less clone. The repository is **never checked out**: only whitelisted manifest files are read with `git cat-file`, so symlinks, hooks, LFS filters and path traversal cannot apply. Time budget 90 s, ≤ 60 files, ≤ 5 MB each (streamed with a hard cap), temp dir always removed.
* XML parsed with `defusedxml` (XXE / entity-bomb safe). SBOMs validated against the official CycloneDX schema.
* Nothing is installed, built, resolved over the network, or run: no pip/npm/Maven/Docker invocations. The only outbound call besides GitHub is the OSV.dev lookup (package names + versions; turn off with `SSC_VULN_SCAN=false`).
* Errors never include filesystem paths; unexpected errors return a generic 500 (details only in server logs).

## Known limitations

* **No transitive discovery without a lockfile/SBOM** (requirements.txt, pyproject.toml, package.json, pom.xml). This is reported in every result's *limitations*.
* Maven: no dependency tree, no parent POM / BOM / profile / multi-module following.
* `requirements.txt`: `-r`/`-c` includes are not followed (analyse those files too); pip-compile output lists transitive pins as ordinary lines, so they appear as *direct*.
* Environment markers (Python) and platform-specific optional dependencies are recorded, **not evaluated** — the lockfile content is shown as written. Universal `uv.lock` files list several versions per package.
* Dockerfile analysis cannot know the final image's OS packages (use an image scanner; the optional Syft hook is implemented but **untested against a real Syft install**).
* GitHub repositories: public only, default branch, no submodules, no auth. Test-fixture manifests inside a repo are analysed like any other (paths shown per component). Per-file size is checked while streaming, so one oversized file may be fetched partially before being dropped.
* SBOM imported from SPDX is best-effort. Imported SBOMs without a `dependencies` section give `unknown` classification.
* Storage is local SQLite, single-user: there is no authentication or rate limiting — **do not expose the backend publicly as-is.**
* yarn.lock and pnpm-lock.yaml are not parsed yet.
* Vulnerability results are only as complete as OSV.dev and as the versions we know: unresolved versions and Docker image OS packages are not checked. Universal `uv.lock` files can report a vulnerability for a version only selected on older Pythons.
* Suspicious-change rules are heuristics. Typosquat detection compares against a curated popular-package list (false positives are possible for legitimate look-alike names; `KNOWN_LEGITIMATE` in `popular_packages.py` suppresses them). "What changed" needs a previous analysis of the same source on this server.
