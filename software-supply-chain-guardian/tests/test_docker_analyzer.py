from backend.analyzers.docker_analyzer import DockerAnalyzer, split_image
from backend.services.discovery_service import discover_uploads


def test_split_image_forms():
    assert split_image("python:3.11-slim") == ("python", "3.11-slim", None)
    assert split_image("localhost:5000/team/app:1.0") == ("localhost:5000/team/app", "1.0", None)
    assert split_image("nginx@sha256:abc") == ("nginx", None, "sha256:abc")
    assert split_image("ubuntu") == ("ubuntu", None, None)


def test_dockerfile_metadata_extraction(samples):
    part = DockerAnalyzer().analyze({"Dockerfile": samples("docker-sample", "Dockerfile")["Dockerfile"].decode()})
    meta = part.docker[0]
    assert meta.stage_count == 3
    imgs = {i.stage_index: i for i in meta.images}
    assert imgs[0].image == "python" and imgs[0].tag == "3.11-slim" and imgs[0].stage_name == "builder"   # ARG substituted
    assert imgs[1].pinned_by_digest and imgs[1].digest.startswith("sha256:")
    assert imgs[2].image == "nginx" and imgs[2].tag == "latest"
    assert imgs[2].is_final_stage and not imgs[0].is_final_stage
    installs = {(i.manager, p) for i in meta.installs for p in i.packages}
    assert ("apt", "curl=7.88.1-10") in installs and ("apk", "bash") in installs
    assert any(i.manager == "pip" for i in meta.installs)
    assert "requirements.txt" in meta.copied_files and "./static" in meta.copied_files
    assert "/app" not in meta.copied_files  # COPY --from=builder is a stage copy, not a local file
    assert meta.exposed_ports == ["80", "443"] and meta.user == "nginx"


def test_stage_reference_is_not_an_external_image():
    text = "FROM golang:1.21 AS build\nRUN true\nFROM build AS test\nFROM scratch\n"
    part = DockerAnalyzer().analyze({"Dockerfile": text})
    assert [c.name for c in part.components] == ["golang"]
    notes = [n for i in part.docker[0].images for n in i.notes]
    assert any("earlier build stage" in n for n in notes)


def test_unresolved_arg_is_not_guessed():
    part = DockerAnalyzer().analyze({"Dockerfile": "ARG BASE\nFROM ${BASE}\n"})
    assert part.components == []
    assert "no default" in part.docker[0].images[0].notes[0]


def test_docker_components_and_honest_limitation(samples):
    res, sbom = discover_uploads(samples("docker-sample", "Dockerfile"))
    by = {c.name: c for c in res.components}
    assert by["python"].version == "3.11-slim" and by["python"].version_status == "declared"
    assert by["node"].version_status == "pinned"
    assert res.docker[0].analysis_kind.startswith("Dockerfile metadata analysis")
    assert any("does NOT list the OS packages" in l for l in res.limitations)
    assert sbom is not None
