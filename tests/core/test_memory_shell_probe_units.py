# -*- coding: utf-8 -*-
"""Unit tests for the memory-shell probe artifact itself.

These tests pin down behaviour that was learned the hard way in the lab:

* Tomcat 7 compiles JSPs at source level 1.6, so the probe must not use the
  diamond operator or anything newer;
* ``config`` is a JSP implicit object, so a scriptlet local may not use that
  name (Jasper fails with "Duplicate local variable config");
* the probe must never be deletable through a path that left the site root.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from anteumbra.domain.memory_shell import PROBE_MARKER, ProbeArtifact, SiteTarget
from anteumbra.infrastructure.internal_artifacts import InMemoryInternalArtifactRegistry
from anteumbra.infrastructure.memory_shell.probe_deployer import (
    MemoryShellProbeDeployer,
    ProbeError,
    load_probe_template,
    render_probe,
)

JSP_TEMPLATE = load_probe_template()


class FakeClock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_target(root) -> SiteTarget:
    return SiteTarget(site_id="site-a", name="Site A", root=root, base_url="http://127.0.0.1:8081",
                      port=8081)


def make_deployer(artifacts, template: str = JSP_TEMPLATE, reader=None):
    return MemoryShellProbeDeployer(
        artifacts=artifacts,
        reader=reader or (lambda url, timeout: b"{}"),
        template_loader=lambda: template,
    )


# ── template ────────────────────────────────────────────────────────
def test_template_carries_marker_and_token_placeholder():
    assert PROBE_MARKER in JSP_TEMPLATE
    assert "{{PROBE_TOKEN}}" in JSP_TEMPLATE


def test_template_avoids_java7_and_implicit_object_pitfalls():
    """Regression guards for two real Jasper failures in the lab."""
    assert "<>" not in JSP_TEMPLATE, "Tomcat 7 compiles JSP at source level 1.6"
    assert "Object config = " not in JSP_TEMPLATE, "config is a JSP implicit object"
    assert "String config = " not in JSP_TEMPLATE


def test_template_covers_every_memory_only_surface():
    """Filters, servlets, listeners and session-held classes are the four places
    a memory shell can hide; the probe has to look at all of them."""
    for kind in ('"filter"', '"servlet"', '"listener"', '"session"'):
        assert kind in JSP_TEMPLATE, f"probe never reports {kind} entries"
    # JDK classes parked in a session are ordinary state, not payloads
    assert "getClassLoader() == null" in JSP_TEMPLATE


def test_render_replaces_every_placeholder():
    token = "abc123"
    rendered = render_probe(JSP_TEMPLATE, token)
    assert "{{PROBE_TOKEN}}" not in rendered
    assert token in rendered
    assert PROBE_MARKER in rendered


def test_missing_template_raises(tmp_path):
    missing = tmp_path / "nope.jsp"
    with pytest.raises(ProbeError):
        load_probe_template(missing)


# ── internal artifact registry ──────────────────────────────────────
def test_registry_matches_paths_directories_and_urls(tmp_path):
    clock = FakeClock()
    registry = InMemoryInternalArtifactRegistry(clock=clock, default_ttl=30.0)
    probe_dir = tmp_path / "site" / "mb-abc"
    probe_file = probe_dir / "p.jsp"

    registry.register(path=probe_file, url_fragment="/mb-abc/p.jsp", ttl=30.0)
    registry.register(path=probe_dir, url_fragment="/mb-abc/p.jsp", ttl=30.0)

    assert registry.is_internal_path(probe_file)
    assert registry.is_internal_path(probe_dir)
    assert registry.is_internal_path(probe_dir / "anything.jsp")
    assert not registry.is_internal_path(tmp_path / "site" / "mb-abc-sibling.jsp")
    assert registry.contains_url('127.0.0.1 - - "GET /mb-abc/p.jsp?t=deadbeef HTTP/1.1"')
    assert not registry.contains_url('127.0.0.1 - - "GET /uploads/x.jsp HTTP/1.1"')


def test_registry_entries_expire(tmp_path):
    clock = FakeClock()
    registry = InMemoryInternalArtifactRegistry(clock=clock, default_ttl=5.0)
    probe = tmp_path / "mb-abc" / "p.jsp"
    registry.register(path=probe, url_fragment="/mb-abc/p.jsp", ttl=5.0)

    assert registry.is_internal_path(probe)
    clock.advance(6.0)
    assert not registry.is_internal_path(probe)
    assert not registry.contains_url("/mb-abc/p.jsp")
    assert registry.snapshot() == []


def test_registry_release_is_immediate(tmp_path):
    registry = InMemoryInternalArtifactRegistry()
    probe = tmp_path / "mb-abc" / "p.jsp"
    registry.register(path=probe, url_fragment="/mb-abc/p.jsp", ttl=60.0)
    registry.release(probe)
    assert not registry.is_internal_path(probe)


# ── deployer ────────────────────────────────────────────────────────
def test_deploy_writes_random_probe_and_registers_it(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    deployer = make_deployer(artifacts)
    target = make_target(tmp_path)

    artifact = deployer.deploy(target, ttl=60.0)

    assert artifact.file_path.exists()
    body = artifact.file_path.read_text(encoding="utf-8")
    assert PROBE_MARKER in body
    assert artifact.token in body
    assert artifact.file_path.parent.parent == tmp_path
    assert artifact.relative_url_path.startswith("/")
    assert artifact.url == f"http://127.0.0.1:8081{artifact.relative_url_path}?t={artifact.token}"
    assert artifacts.is_internal_path(artifact.file_path)
    assert artifacts.contains_url(artifact.relative_url_path)


def test_deploy_refuses_missing_site_root(tmp_path):
    deployer = make_deployer(InMemoryInternalArtifactRegistry())
    target = make_target(tmp_path / "does-not-exist")
    with pytest.raises(ProbeError):
        deployer.deploy(target, ttl=60.0)


def test_cleanup_removes_probe_and_directory(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    deployer = make_deployer(artifacts)
    artifact = deployer.deploy(make_target(tmp_path), ttl=60.0)
    directory = artifact.directory

    deployer.cleanup(artifact)

    assert not directory.exists()
    assert not artifacts.is_internal_path(artifact.file_path)
    assert list(tmp_path.iterdir()) == []


def test_cleanup_keeps_a_foreign_file_and_reports_failure(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    deployer = make_deployer(artifacts)
    artifact = deployer.deploy(make_target(tmp_path), ttl=60.0)

    # somebody replaced our probe with their own file
    artifact.file_path.write_text("<% out.print(\"x\"); %>", encoding="utf-8")

    with pytest.raises(ProbeError, match="replaced"):
        deployer.cleanup(artifact)

    assert artifact.file_path.exists(), "a foreign file must never be deleted"
    # and it must not stay suppressed from detection
    assert not artifacts.is_internal_path(artifact.file_path)


def test_cleanup_refuses_paths_outside_the_site_root(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    deployer = make_deployer(artifacts)
    site_root = tmp_path / "site"
    site_root.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    victim = outside / "keep.jsp"
    victim.write_text(PROBE_MARKER, encoding="utf-8")

    stray = ProbeArtifact(
        site_id="site-a",
        site_root=site_root,
        directory=outside,
        file_path=victim,
        token="t",
        url="http://127.0.0.1/x.jsp",
        created_at=0.0,
    )

    with pytest.raises(ProbeError, match="outside the site root"):
        deployer.cleanup(stray)
    assert victim.exists()


def test_read_wraps_transport_errors(tmp_path):
    def boom(url, timeout):
        raise OSError("connection refused")

    artifacts = InMemoryInternalArtifactRegistry()
    deployer = make_deployer(artifacts, reader=boom)
    artifact = deployer.deploy(make_target(tmp_path), ttl=60.0)

    with pytest.raises(ProbeError, match="probe request failed"):
        deployer.read(artifact, timeout=1.0)
    deployer.cleanup(artifact)


# ── parsing ─────────────────────────────────────────────────────────
def _payload(**overrides) -> bytes:
    data = {
        "probe": PROBE_MARKER,
        "version": "1.0.0",
        "context_path": "/dshlab",
        "container": ["context_class:org.apache.catalina.core.StandardContext"],
        "error": None,
        "entry_count": 2,
        "duration_ms": 3,
        "entries": [
            {
                "type": "filter",
                "name": "WsFilter",
                "urls": ["/*"],
                "class": "org.apache.tomcat.websocket.server.WsFilter",
                "class_loader": "org.apache.catalina.loader.WebappClassLoader",
                "resource": "file:/opt/tomcat/lib/tomcat-websocket.jar",
                "code_source": "file:/opt/tomcat/lib/tomcat-websocket.jar",
                "suspect": False,
                "reasons": [],
            },
            {
                "type": "filter",
                "name": "abcdefgh",
                "urls": ["/*"],
                "class": "org.apache.jsp.dshlab.behinder_jsp$U",
                "class_loader": "org.apache.jsp.dshlab.behinder_jsp$U",
                "resource": None,
                "code_source": None,
                "suspect": True,
                "reasons": ["class_not_on_disk", "anonymous_classloader"],
            },
        ],
    }
    data.update(overrides)
    return json.dumps(data).encode("utf-8")


def test_parse_reads_entries_and_suspects(tmp_path):
    deployer = make_deployer(InMemoryInternalArtifactRegistry())
    artifact = ProbeArtifact(
        site_id="site-a",
        site_root=tmp_path,
        directory=tmp_path / "mb-abc",
        file_path=tmp_path / "mb-abc" / "p.jsp",
        token="t",
        url="http://127.0.0.1:8081/mb-abc/p.jsp?t=t",
        created_at=0.0,
    )

    report = deployer.parse(_payload(), artifact)

    assert report.ok
    assert report.context_path == "/dshlab"
    assert report.counts() == {"filter": 2}
    assert len(report.suspects) == 1
    suspect = report.suspects[0]
    assert suspect.suspect and not suspect.on_disk
    assert "anonymous_classloader" in suspect.reasons
    assert report.as_dict()["entries"][0]["on_disk"] is True


def test_probe_template_is_shipped_in_the_wheel():
    """A source-only wheel would break the feature after `pip install`."""
    from anteumbra.infrastructure.memory_shell.probe_deployer import default_template_path

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert "infrastructure/memory_shell/assets/*.jsp" in text
    assert default_template_path().is_file()


def test_parse_rejects_foreign_or_empty_payloads(tmp_path):
    deployer = make_deployer(InMemoryInternalArtifactRegistry())
    artifact = ProbeArtifact(
        site_id="site-a",
        site_root=tmp_path,
        directory=tmp_path / "mb-abc",
        file_path=tmp_path / "mb-abc" / "p.jsp",
        token="t",
        url="http://127.0.0.1/whatever",
        created_at=0.0,
    )

    with pytest.raises(ProbeError, match="non-JSON"):
        deployer.parse(b"<html>404</html>", artifact)
    with pytest.raises(ProbeError, match="marker"):
        deployer.parse(json.dumps({"probe": "someone-else"}).encode(), artifact)
    with pytest.raises(ProbeError, match="not an object"):
        deployer.parse(b"[]", artifact)


# ── probe location resolution (Tomcat container roots) ──────────────
class _Site:
    def __init__(self, site_id: str, path) -> None:
        self.site_id = site_id
        self.name = site_id.title()
        self.path = path
        self.port = 8081


class _Provider:
    def __init__(self, config: dict, websites: list) -> None:
        self._config = config
        self._websites = websites

    def get(self) -> dict:
        return self._config

    def get_enabled_websites(self) -> list:
        return self._websites


def _service(tmp_path, config: dict, websites: list):
    from anteumbra.application.memory_shell_service import MemoryShellService

    artifacts = InMemoryInternalArtifactRegistry()
    return MemoryShellService(
        config_provider=_Provider({"plugins": {"memory_shell_probe": config}}, websites),
        deployer=make_deployer(artifacts),
        artifacts=artifacts,
    )


def test_probe_location_falls_back_when_many_contexts_exist(tmp_path):
    """A Tomcat appBase root is not servable: the probe must not land there."""
    for name in ("appA", "appB"):
        (tmp_path / name / "WEB-INF").mkdir(parents=True)
        (tmp_path / name / "WEB-INF" / "web.xml").write_text("<web-app/>", encoding="utf-8")

    service = _service(tmp_path, {}, [_Site("tomcat", tmp_path)])
    target = service.target("tomcat")

    assert target is not None
    assert target.deployment_root == tmp_path
    assert "probe_base_dirs" in target.base_note
    assert target.url_prefix == ""


def test_probe_location_uses_the_single_deployed_context(tmp_path):
    (tmp_path / "site" / "WEB-INF").mkdir(parents=True)
    (tmp_path / "site" / "WEB-INF" / "web.xml").write_text("<web-app/>", encoding="utf-8")

    service = _service(tmp_path, {}, [_Site("tomcat", tmp_path)])
    target = service.target("tomcat")

    assert target is not None
    assert target.deployment_root == tmp_path / "site"
    assert target.url_prefix == "/site"
    assert "single deployed context" in target.base_note


def test_probe_location_accepts_an_explicit_base_dir(tmp_path):
    (tmp_path / "webapps" / "dshlab").mkdir(parents=True)

    service = _service(
        tmp_path,
        {"probe_base_dirs": {"tomcat": "dshlab"}},
        [_Site("tomcat", tmp_path / "webapps")],
    )
    target = service.target("tomcat")

    assert target is not None
    assert target.deployment_root == (tmp_path / "webapps" / "dshlab").resolve()
    assert target.url_prefix == "/dshlab"
    assert "probe_base_dirs" in target.base_note

    artifact = service._deployer.deploy(target, ttl=30.0)
    assert artifact.file_path.parent.parent == (tmp_path / "webapps" / "dshlab").resolve()
    assert artifact.url.startswith("http://127.0.0.1:8081/dshlab/")
    service._deployer.cleanup(artifact)


def test_probe_location_honours_a_url_prefix_on_a_document_root(tmp_path):
    (tmp_path / "WEB-INF").mkdir()
    (tmp_path / "WEB-INF" / "web.xml").write_text("<web-app/>", encoding="utf-8")

    service = _service(
        tmp_path, {"url_prefixes": {"tomcat": "/blog"}}, [_Site("tomcat", tmp_path)]
    )
    target = service.target("tomcat")

    assert target is not None
    assert target.deployment_root == tmp_path
    assert target.url_prefix == "/blog"
    assert target.url_for("/mb-x/p.jsp") == "http://127.0.0.1:8081/blog/mb-x/p.jsp"
