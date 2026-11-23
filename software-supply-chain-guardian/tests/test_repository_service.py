import glob
import tempfile

import pytest

from backend.services import discovery_service
from backend.services.repository_service import RepositoryError, RepositoryService, parse_github_url
from backend.utils.file_utils import FileValidationError

GOOD = [
    ("https://github.com/pallets/flask", "pallets/flask"),
    ("https://github.com/pallets/flask/", "pallets/flask"),
    ("https://github.com/pallets/flask.git", "pallets/flask"),
    ("  https://www.github.com/Owner-1/repo.name_x  ", "Owner-1/repo.name_x"),
]
BAD = [
    "", "   ", "github.com/pallets/flask", "http://github.com/pallets/flask", "ftp://github.com/a/b",
    "https://gitlab.com/a/b", "https://github.com.evil.com/a/b", "https://evil.com/github.com/a/b",
    "https://localhost/a/b", "https://127.0.0.1/a/b", "https://169.254.169.254/latest", "https://10.0.0.5/a/b",
    "https://[::1]/a/b", "https://user:pw@github.com/a/b", "https://github.com:8443/a/b",
    "https://github.com/a", "https://github.com/a/b/c", "https://github.com/a/b/tree/main", "https://github.com/a/b?x=1",
    "https://github.com/a/b#frag", "https://github.com/../b", "https://github.com/a/..", "https://github.com/-bad/b",
    "https://github.com/a/b c", "file:///etc/passwd", "https://github.com/a/b;rm -rf", "https://github.com/a\\b/c",
    "https://github.com/" + "a" * 300 + "/b", "-oProxyCommand=x",
]


@pytest.mark.parametrize("url,name", GOOD)
def test_valid_github_urls(url, name):
    assert parse_github_url(url).name == name


@pytest.mark.parametrize("url", BAD)
def test_unsafe_or_invalid_urls_rejected(url):
    with pytest.raises(RepositoryError) as e:
        parse_github_url(url)
    assert e.value.status_code == 400


def test_non_string_url_rejected():
    with pytest.raises(RepositoryError):
        parse_github_url(None)  # type: ignore[arg-type]


REPO_FILES = {
    "requirements.txt": "Flask==2.2.2\n",
    "package.json": '{"name":"x","dependencies":{"left-pad":"1.3.0"}}',
    "services/api/pom.xml": "<project><artifactId>api</artifactId><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>",
    "node_modules/evil/package.json": '{"dependencies":{"should-be-skipped":"1.0.0"}}',
    "vendor/lib/requirements.txt": "vendored==1.0\n",
    "README.md": "# not a dependency file",
    "Dockerfile": "FROM python:3.12-slim\n",
    "big/requirements.txt": "x" * 10,
}


def test_fetch_reads_only_whitelisted_files_without_checkout(local_repo_service):
    svc = local_repo_service(REPO_FILES, symlinks={"link/requirements.txt": "../requirements.txt"})
    rf = svc.fetch_files("https://github.com/o/r")
    assert set(rf.files) == {"requirements.txt", "package.json", "services/api/pom.xml", "Dockerfile", "big/requirements.txt"}
    assert rf.commit and len(rf.commit) == 12
    assert "evil" not in " ".join(rf.files)           # node_modules skipped
    assert "link/requirements.txt" not in rf.files    # symlinks never followed


def test_per_file_size_limit(local_repo_service, monkeypatch):
    monkeypatch.setenv("SSC_MAX_REPO_FILE_BYTES", "20")
    svc = local_repo_service({"requirements.txt": "a==1\n", "big/requirements.txt": "flask==2.0.0\n" * 50})
    rf = svc.fetch_files("https://github.com/o/r")
    assert set(rf.files) == {"requirements.txt"} and any("per-file limit" in w for w in rf.warnings)


def test_file_count_limit(local_repo_service, monkeypatch):
    monkeypatch.setenv("SSC_MAX_REPO_FILES", "2")
    svc = local_repo_service({f"p{i}/requirements.txt": "a==1\n" for i in range(5)} | {"requirements.txt": "b==1\n"})
    rf = svc.fetch_files("https://github.com/o/r")
    assert len(rf.files) == 2 and "requirements.txt" in rf.files and any("only the 2 closest" in w for w in rf.warnings)


def test_retrieval_failure_is_reported_safely(tmp_path):
    svc = RepositoryService(remote_override=lambda r: f"file://{tmp_path}/does-not-exist",
                            extra_git_config=["protocol.file.allow=always"])
    with pytest.raises(RepositoryError) as e:
        svc.fetch_files("https://github.com/o/r")
    assert e.value.status_code in (404, 502)
    assert str(tmp_path) not in str(e.value)      # no filesystem paths leak


def test_real_https_protocol_only_blocks_file_scheme(tmp_path):
    """Without the test-only config override, a file:// remote must be refused by git itself."""
    svc = RepositoryService(remote_override=lambda r: f"file://{tmp_path}")
    with pytest.raises(RepositoryError):
        svc.fetch_files("https://github.com/o/r")


def test_timeout_budget(local_repo_service, monkeypatch):
    monkeypatch.setenv("SSC_GIT_TIMEOUT_SECONDS", "0")
    svc = local_repo_service({"requirements.txt": "a==1\n"})
    with pytest.raises(RepositoryError) as e:
        svc.fetch_files("https://github.com/o/r")
    assert e.value.status_code == 504


def test_temp_directories_are_cleaned_up(local_repo_service):
    before = set(glob.glob(f"{tempfile.gettempdir()}/ssc-repo-*"))
    svc = local_repo_service({"requirements.txt": "a==1\n"})
    svc.fetch_files("https://github.com/o/r")
    failing = RepositoryService(remote_override=lambda r: "file:///nonexistent")
    with pytest.raises(RepositoryError):  # failure path must clean up too
        failing.fetch_files("https://github.com/o/r")
    assert set(glob.glob(f"{tempfile.gettempdir()}/ssc-repo-*")) == before


def test_combined_multi_ecosystem_repository_discovery(local_repo_service):
    svc = local_repo_service(REPO_FILES)
    res, sbom = discovery_service.discover_repository(svc.fetch_files("https://github.com/o/r"))
    assert res.input_type == "repository" and res.project_name == "o/r" and res.source == "https://github.com/o/r"
    assert set(res.summary.ecosystems) == {"pypi", "npm", "maven", "docker"}
    assert "left-pad" in {c.name for c in res.components} and "should-be-skipped" not in {c.name for c in res.components}
    assert {f.path for f in res.files} >= {"requirements.txt", "package.json", "services/api/pom.xml", "Dockerfile"}
    assert sbom is not None


def test_repository_without_supported_files(local_repo_service):
    svc = local_repo_service({"README.md": "hi"})
    with pytest.raises(FileValidationError) as e:
        discovery_service.discover_repository(svc.fetch_files("https://github.com/o/r"))
    assert "No supported dependency files" in str(e.value)
