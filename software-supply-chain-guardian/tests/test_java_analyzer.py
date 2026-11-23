import pytest

from backend.services.discovery_service import discover_uploads
from backend.utils.file_utils import FileValidationError


def test_pom_declared_dependencies(samples):
    res, _ = discover_uploads(samples("java-sample", "pom.xml"))
    by = {c.name: c for c in res.components}
    assert res.project_name == "com.example:java-sample"
    assert by["com.fasterxml.jackson.core:jackson-databind"].version == "2.15.2"        # ${property}
    assert by["com.fasterxml.jackson.core:jackson-databind"].version_status == "declared"
    assert by["org.apache.commons:commons-lang3"].version == "3.12.0"
    assert by["org.slf4j:slf4j-api"].version == "2.0.9"                                # dependencyManagement
    assert by["com.google.guava:guava"].version is None                                 # range => unresolved
    assert by["com.google.guava:guava"].declared_constraint == "[31.0,32.0)"
    assert by["org.junit.jupiter:junit-jupiter"].scope == "test"
    assert by["org.apache.commons:commons-lang3"].purl == "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
    assert res.summary.transitive_dependencies == 0 and res.summary.unresolved_dependencies == 1


def test_pom_never_claims_transitive_resolution(samples):
    res, _ = discover_uploads(samples("java-sample", "pom.xml"))
    assert res.summary.transitive_resolution == "none"
    assert any("NOT discovered" in l for l in res.limitations)
    assert res.files[0].provides_transitive is False


def test_inherited_version_is_unresolved_with_parent_warning():
    pom = b"""<project><modelVersion>4.0.0</modelVersion>
      <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.1.0</version></parent>
      <artifactId>app</artifactId>
      <dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
      <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${undefined.prop}</version></dependency></dependencies></project>"""
    res, _ = discover_uploads({"pom.xml": pom})
    assert all(c.version is None for c in res.components)
    assert any("<parent>" in w for w in res.warnings)


def test_malformed_and_non_pom_xml_rejected():
    for bad in (b"<project><unclosed>", b"<root/>"):
        with pytest.raises(FileValidationError) as e:
            discover_uploads({"pom.xml": bad})
        assert e.value.status_code == 422


def test_xml_entity_attack_is_blocked():
    bomb = b'<?xml version="1.0"?><!DOCTYPE project [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><project>&b;</project>'
    with pytest.raises(FileValidationError):
        discover_uploads({"pom.xml": bomb})
