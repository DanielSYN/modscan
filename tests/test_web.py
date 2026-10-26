import logging

import pytest
from fastapi.testclient import TestClient

from modscan import summary
from modscan.web import app as web
from tests.factory import clean_mod, cls, make_jar

FAKE_KEY = "sk-ant-api03-" + "y" * 40


@pytest.fixture
def client():
    web.limiter.reset()
    with TestClient(web.app) as test_client:
        yield test_client


def upload(client, data: bytes, name: str = "mod.jar"):
    return client.post(f"/api/scan?filename={name}", content=data,
                       headers={"Content-Type": "application/octet-stream"})


def test_page_is_served_with_a_strict_content_security_policy(client):
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["referrer-policy"] == "no-referrer"


def test_scan_returns_a_report(client):
    response = upload(client, clean_mod(), "coolmod.jar")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    report = response.json()
    assert report["verdict"] == "no_known_threats" and report["file_name"] == "coolmod.jar"
    assert report["mods"][0]["name"] == "Cool Mod"


def test_scan_flags_a_stealer(client):
    jar = make_jar({"x/Y.class": cls("x/Y").string("https://discord.com/api/webhooks/1/z").string("\\Login Data")})
    assert upload(client, jar).json()["verdict"] == "likely_malicious"


def test_scan_rejects_bad_uploads(client, monkeypatch):
    assert upload(client, b"").status_code == 400
    assert upload(client, b"just some text").status_code == 415
    monkeypatch.setattr(web, "MAX_UPLOAD_BYTES", 100)
    assert upload(client, clean_mod()).status_code == 413


def test_path_in_filename_is_dropped(client):
    assert upload(client, clean_mod(), "..%2F..%2Fetc%2Fpasswd.jar").json()["file_name"] == "passwd.jar"


def test_scans_are_rate_limited(client, monkeypatch):
    monkeypatch.setattr(web, "SCANS_PER_MINUTE", 2)
    assert [upload(client, clean_mod()).status_code for _ in range(3)] == [200, 200, 429]


def test_summary_requires_the_users_own_key(client):
    report = upload(client, clean_mod()).json()
    response = client.post("/api/summary", json=report)
    assert response.status_code == 400 and "API key" in response.json()["detail"]


def test_summary_passes_the_key_through_and_returns_text(client, monkeypatch):
    seen = {}

    def fake_summarise(report, api_key):
        seen["key"], seen["verdict"] = api_key, report["verdict"]
        return "Looks fine."

    monkeypatch.setattr(summary, "summarise", fake_summarise)
    report = upload(client, clean_mod()).json()
    response = client.post("/api/summary", json=report, headers={"X-Anthropic-Key": FAKE_KEY})
    assert response.json()["summary"] == "Looks fine."
    assert seen == {"key": FAKE_KEY, "verdict": "no_known_threats"}


def test_a_rejected_key_is_never_echoed_or_logged(client, monkeypatch, caplog):
    def rejected(report, api_key):
        raise summary.SummaryError("Anthropic rejected that API key. Check it and try again.", 401)

    monkeypatch.setattr(summary, "summarise", rejected)
    caplog.set_level(logging.DEBUG)
    response = client.post("/api/summary", json={"verdict": "x"}, headers={"X-Anthropic-Key": FAKE_KEY})
    assert response.status_code == 401
    assert FAKE_KEY not in response.text and FAKE_KEY not in caplog.text


def test_summary_rejects_bad_bodies(client, monkeypatch):
    headers = {"X-Anthropic-Key": FAKE_KEY, "Content-Type": "application/json"}
    assert client.post("/api/summary", content=b"{nope", headers=headers).status_code == 400
    assert client.post("/api/summary", content=b"[1, 2]", headers=headers).status_code == 400
    monkeypatch.setattr(web, "MAX_REPORT_BYTES", 10)
    assert client.post("/api/summary", json={"verdict": "x" * 50}, headers=headers).status_code == 413
