# 🛡️ Software Supply Chain Guardian — Stage 1: Discovery

Discovers a project's software supply chain: **dependencies (direct + transitive), versions, relationships, a dependency graph, and a CycloneDX SBOM**, from a public GitHub repository or uploaded files.

> Stage 1 deliberately does **not** detect vulnerabilities, prioritise risk, use AI/agents, or recommend fixes. Those are later stages.

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
| `sample-projects/python-sample/` | `requirements.txt` | 4 direct, pinned versions; **no** transitive data (and a clear limitation notice) |
| `sample-projects/python-uv-sample/` | `pyproject.toml` + `uv.lock` | 5 direct + 23 transitive, all resolved, valid complete SBOM. Note: the lock is a *universal* lock, so `requests`/`pytest` legitimately appear in two versions selected by Python-version markers |
| `sample-projects/javascript-sample/` | `package.json` + `package-lock.json` | 3 direct, ~135 transitive (real lockfile generated with `npm install --package-lock-only --ignore-scripts`) |
| `sample-projects/java-sample/` | `pom.xml` | 5 declared dependencies; the range-versioned `guava` stays **unresolved**; no transitive claims |
| `sample-projects/docker-sample/` | `Dockerfile` | multi-stage base images, ARG substitution, digest pin, requested packages — static metadata only |

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
.venv/bin/python -m pytest                              # offline: no GitHub or registry access needed
.venv/bin/python -m pytest tests/test_e2e_live.py --run-e2e   # optional live test against public GitHub
```

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
| `yarn.lock`, `pnpm-lock.yaml` | **Not yet supported** | Recognised and reported explicitly; not parsed |

## Architecture

```
backend/
  main.py                    FastAPI app (create_app factory), endpoints, error handling
  models.py                  Pydantic models (Component, Relationship, DiscoveryResult, Graph*)
  config.py                  limits (env-overridable)
  analyzers/                 python_ / javascript_ / java_ / docker_analyzer + base (purl IDs, merging)
  services/
    discovery_service.py     classify files -> analyzers -> merge -> SBOM -> result
    dependency_resolver.py   merge duplicates, attach root, resolution-level honesty check
    graph_service.py         NetworkX graph, stats, cycles, Plotly figure, subtree/paths
    sbom_service.py          CycloneDX 1.6 generate+validate, CycloneDX/SPDX import, optional Syft
    repository_service.py    safe GitHub retrieval
    storage_service.py       bounded SQLite storage (newest 200 analyses)
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
| `GET /api/discovery/{id}` · `/graph` · `/sbom` | Stored result, graph JSON, CycloneDX SBOM |
| `POST /api/discover/image` | Optional Syft image scan — **disabled by default**, needs `approve=true` and `SSC_ENABLE_SYFT=true` |

Errors: 400 bad URL/input · 404 not found · 413 too large · 415 unsupported type · 422 unparseable · 502/504 repository retrieval.

## Security design

* Uploads are parsed **in memory as data**; never written to disk, never executed. Names are reduced to a base name (no traversal). Limits: 5 MB/file, 10 files.
* Repository URLs: `https` + host exactly `github.com`, `owner/repo` only — no credentials, ports, queries, IPs, localhost, internal hosts (prevents SSRF).
* Retrieval uses `git` with an argument list (no shell), minimal environment (no inherited tokens), prompts/hooks/credential helpers off, `https` protocol only, shallow blob-less clone. The repository is **never checked out**: only whitelisted manifest files are read with `git cat-file`, so symlinks, hooks, LFS filters and path traversal cannot apply. Time budget 90 s, ≤ 60 files, ≤ 5 MB each (streamed with a hard cap), temp dir always removed.
* XML parsed with `defusedxml` (XXE / entity-bomb safe). SBOMs validated against the official CycloneDX schema.
* Nothing is installed, built, resolved over the network, or run: no pip/npm/Maven/Docker invocations.
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
