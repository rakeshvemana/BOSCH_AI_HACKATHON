"""Safe, read-only retrieval of dependency files from a PUBLIC GitHub repository.

Security design (why it is built this way)
------------------------------------------
* Only ``https://github.com/<owner>/<repo>`` is accepted. The host must be
  exactly github.com, so localhost / private IPs / other hosts are impossible
  (no SSRF). Credentials, ports, queries and odd paths are rejected.
* ``git`` is run with an argument LIST (never a shell), a minimal environment,
  prompts disabled, hooks disabled and only the https protocol allowed.
* We make a shallow, blob-less clone (just the file tree), list the tree with
  ``git ls-tree`` and read ONLY whitelisted dependency files with
  ``git cat-file``. The repository is never checked out, so no repo file is
  ever written to disk, executed, or followed through a symlink, and path
  traversal is impossible. Hooks / LFS / smudge filters never run.
* Hard limits: total time budget, number of files, size per file.
* The temporary directory is always removed (``TemporaryDirectory``).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlsplit

from backend.config import settings
from backend.utils.file_utils import (
    FileValidationError, classify_file, decode_text, is_skipped_repo_path, safe_relative_path,
)

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class RepositoryError(FileValidationError):
    pass


@dataclass(frozen=True)
class ParsedRepo:
    owner: str
    repo: str

    @property
    def web_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return self.web_url + ".git"

    @property
    def name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class RepoFiles:
    repo: ParsedRepo
    files: dict[str, str] = field(default_factory=dict)
    commit: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    skipped_unsupported: list[str] = field(default_factory=list)


def parse_github_url(url: str) -> ParsedRepo:
    """Validate a GitHub repository URL. Raises RepositoryError (HTTP 400) when unsafe/invalid."""
    if not isinstance(url, str):
        raise RepositoryError("Repository URL must be text.")
    url = url.strip()
    if not url or len(url) > 200 or re.search(r"[\s\x00-\x1f\\]", url):
        raise RepositoryError("Invalid repository URL.")
    try:
        parts = urlsplit(url)
        port = parts.port  # may raise ValueError
    except ValueError:
        raise RepositoryError("Invalid repository URL.")
    if parts.scheme != "https":
        raise RepositoryError("Only https:// GitHub URLs are accepted.")
    host = (parts.hostname or "").lower()
    if host not in {"github.com", "www.github.com"} or parts.username or parts.password or port is not None:
        raise RepositoryError("Only public repositories on github.com are supported (no credentials, ports or other hosts).")
    if parts.query or parts.fragment:
        raise RepositoryError("Provide the plain repository URL without query strings or fragments.")
    segments = [s for s in parts.path.split("/") if s != ""]
    if len(segments) != 2:
        raise RepositoryError("URL must look like https://github.com/<owner>/<repository>.")
    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo) or repo in {".", ".."}:
        raise RepositoryError("Invalid GitHub owner or repository name.")
    return ParsedRepo(owner, repo)


class RepositoryService:
    def __init__(
        self,
        git_exe: Optional[str] = None,
        remote_override: Optional[Callable[[ParsedRepo], str]] = None,
        extra_git_config: Optional[list[str]] = None,
    ) -> None:
        """``remote_override`` and ``extra_git_config`` exist ONLY so tests can use a local repo."""
        self._git = git_exe or shutil.which("git")
        self._remote_override = remote_override
        self._extra = extra_git_config or []

    # -- subprocess helpers ------------------------------------------------
    def _base_cmd(self) -> list[str]:
        base = [
            self._git, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", f"core.hooksPath={os.devnull}", "-c", "credential.helper=", "-c", "core.fsmonitor=false",
        ]
        for item in self._extra:
            base += ["-c", item]
        return base

    @staticmethod
    def _env(home: str) -> dict[str, str]:
        # Minimal environment: no inherited tokens/secrets, no prompts, no system/global git config.
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": home, "LANG": "C", "LC_ALL": "C",
            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "true",
        }

    def _run(self, args: list[str], cwd: Optional[str], deadline: float, home: str, text: bool = True):
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise RepositoryError("Repository retrieval exceeded the time limit.", 504)
        try:
            return subprocess.run(self._base_cmd() + args, cwd=cwd, env=self._env(home), capture_output=True, text=text,
                                  timeout=remaining, check=False, shell=False)
        except subprocess.TimeoutExpired:
            raise RepositoryError("Repository retrieval exceeded the time limit.", 504)

    def _read_blob(self, sha: str, cwd: str, deadline: float, home: str, limit: int) -> Optional[bytes]:
        """Read one blob, stopping early (and killing git) if it exceeds ``limit`` bytes.

        Returns the bytes, or None when the blob is too large / unreadable.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise RepositoryError("Repository retrieval exceeded the time limit.", 504)
        proc = subprocess.Popen(self._base_cmd() + ["cat-file", "blob", sha], cwd=cwd, env=self._env(home),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
        timer = None
        try:
            import threading
            timer = threading.Timer(remaining, proc.kill)
            timer.start()
            data = proc.stdout.read(limit + 1)  # type: ignore[union-attr]
            if len(data) > limit:
                proc.kill()
                return None
            proc.wait()
            if time.monotonic() > deadline:
                raise RepositoryError("Repository retrieval exceeded the time limit.", 504)
            return data if proc.returncode == 0 else b""
        finally:
            if timer:
                timer.cancel()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout:
                proc.stdout.close()

    @staticmethod
    def _dir_size(path: str) -> int:
        total = 0
        for root, _d, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return total

    # -- main entry --------------------------------------------------------
    def fetch_files(self, url: str) -> RepoFiles:
        repo = parse_github_url(url)
        if not self._git:
            raise RepositoryError("git is not installed on the server.", 500)
        deadline = time.monotonic() + settings.git_timeout_seconds
        remote = self._remote_override(repo) if self._remote_override else repo.clone_url
        out = RepoFiles(repo=repo)

        with tempfile.TemporaryDirectory(prefix="ssc-repo-") as tmp:
            dest = os.path.join(tmp, "repo")
            clone = ["clone", "--depth=1", "--single-branch", "--no-tags", "--no-checkout", "--quiet"]
            proc = self._run(clone + ["--filter=blob:none", "--", remote, dest], tmp, deadline, tmp)
            if proc.returncode != 0:
                shutil.rmtree(dest, ignore_errors=True)
                err = (proc.stderr or "").lower()
                if "not found" in err or "could not read username" in err or "authentication" in err or "terminal prompts disabled" in err:
                    raise RepositoryError("Repository not found or not public.", 404)
                # fall back to a plain shallow clone (e.g. server without partial-clone support)
                proc = self._run(clone + ["--", remote, dest], tmp, deadline, tmp)
                if proc.returncode != 0:
                    raise RepositoryError("Could not retrieve the repository (it may not exist, may be private, or GitHub is unreachable).", 502)
            if self._dir_size(dest) > 300 * 1024 * 1024:
                raise RepositoryError("Repository is too large to analyse.", 413)

            head = self._run(["rev-parse", "HEAD"], dest, deadline, tmp)
            out.commit = head.stdout.strip()[:12] if head.returncode == 0 else None

            tree = self._run(["ls-tree", "-r", "-z", "HEAD"], dest, deadline, tmp)
            if tree.returncode != 0:
                raise RepositoryError("Could not read the repository file list.", 502)

            # NOTE: no `-l` on purpose: in a blob-less clone it would download every blob just to learn sizes.
            candidates: list[tuple[str, str]] = []
            for entry in tree.stdout.split("\0"):
                if not entry:
                    continue
                meta, _, path = entry.partition("\t")
                try:
                    mode, otype, sha = meta.split()
                except ValueError:
                    continue
                if otype != "blob" or mode == "120000":  # skip submodules and symlinks
                    continue
                try:
                    path = safe_relative_path(path)
                except FileValidationError:
                    continue
                if is_skipped_repo_path(path):
                    continue
                fmt = classify_file(path)
                if fmt is None:
                    continue
                if fmt in {"cyclonedx", "spdx"} and not re.search(r"(^|/)(bom|sbom)\.json$|\.(cdx|spdx)\.json$", path.lower()):
                    continue
                candidates.append((path, sha))

            candidates.sort(key=lambda c: (c[0].count("/"), c[0]))
            if len(candidates) > settings.max_repo_files:
                out.warnings.append(f"Repository has {len(candidates)} supported files; only the {settings.max_repo_files} "
                                    "closest to the root were analysed.")
                candidates = candidates[: settings.max_repo_files]

            limit = settings.max_repo_file_bytes

            def read(item: tuple[str, str]):
                return item[0], self._read_blob(item[1], dest, deadline, tmp, limit)

            # Blobs are fetched lazily (one network round-trip each), so read several at once.
            with ThreadPoolExecutor(max_workers=8) as pool:
                fetched = list(pool.map(read, candidates))
            if self._dir_size(dest) > 300 * 1024 * 1024:
                raise RepositoryError("Repository is too large to analyse.", 413)
            for path, data in fetched:
                if data is None:
                    out.warnings.append(f"{path}: skipped (exceeds the {limit // (1024 * 1024)} MB per-file limit).")
                elif data == b"":
                    out.warnings.append(f"{path}: could not be read.")
                else:
                    try:
                        out.files[path] = decode_text(data, path)
                    except FileValidationError as exc:
                        out.warnings.append(str(exc))
        return out
