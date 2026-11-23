"""Shared fixtures. Tests never touch the network unless marked e2e."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample-projects"

# Offline by default: the OSV.dev vulnerability lookup is replaced by fakes in the tests that need it.
os.environ.setdefault("SSC_VULN_SCAN", "false")


def pytest_addoption(parser):
    parser.addoption("--run-e2e", action="store_true", default=False, help="run live network end-to-end tests")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-e2e"):
        return
    skip = pytest.mark.skip(reason="live e2e test: use --run-e2e")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip)


def read_sample(project: str, *names: str) -> dict[str, bytes]:
    return {n: (SAMPLES / project / n).read_bytes() for n in names}


@pytest.fixture
def samples():
    return read_sample


def make_git_repo(path: Path, files: dict[str, str | bytes], symlinks: dict[str, str] | None = None) -> Path:
    """Create a local git repo used as a stand-in for GitHub in tests."""
    path.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

    def git(*args):
        subprocess.run(["git", *args], cwd=path, env=env, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "uploadpack.allowFilter", "true")
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    for rel, content in files.items():
        p = path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
    for rel, target in (symlinks or {}).items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).symlink_to(target)
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return path


@pytest.fixture
def local_repo_service(tmp_path):
    """Returns (factory, service-builder). The service clones local repos via file:// instead of GitHub."""
    from backend.services.repository_service import RepositoryService

    def build(files, symlinks=None):
        src = make_git_repo(tmp_path / "remote", files, symlinks)
        return RepositoryService(remote_override=lambda repo: f"file://{src}",
                                 extra_git_config=["protocol.file.allow=always"])
    return build
