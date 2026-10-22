import io
import json
import zipfile
from datetime import date, datetime, timedelta, timezone

from mtw.collectors import crtsh, openphish, urlhaus, whoisds
from mtw.config import Brand


class FakeResponse:
    def __init__(self, text="", content=b"", status=200):
        self.text = text
        self.content = content or text.encode()
        self.status_code = status

    def json(self):
        return json.loads(self.text)


def test_openphish_parses_lines(monkeypatch):
    monkeypatch.setattr(openphish, "get", lambda *a, **k: FakeResponse("https://a.example/x\n\n# c\nhttp://b.example/\n"))
    res = openphish.collect_openphish()
    assert res.status == "ok"
    assert [o.url for o in res.observations] == ["https://a.example/x", "http://b.example/"]


def test_openphish_error_does_not_raise(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(openphish, "get", boom)
    res = openphish.collect_openphish()
    assert res.status == "error"
    assert res.observations == []


def test_whoisds_reads_zip(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("domain-names.txt", "biat-login.xyz\nexample.com\n")
    monkeypatch.setattr(whoisds, "get", lambda *a, **k: FakeResponse(content=buf.getvalue()))
    res = whoisds.collect_whoisds(day=date(2026, 10, 21))
    assert [o.value for o in res.observations] == ["biat-login.xyz", "example.com"]
    assert whoisds._token(date(2026, 10, 21)) == "MjAyNi0xMC0yMS56aXA="


def test_crtsh_keeps_only_recent_certificates(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        {"id": 1, "name_value": "biat-login.xyz\nwww.biat-login.xyz", "entry_timestamp": now.isoformat()},
        {"id": 2, "name_value": "old-biat.xyz", "entry_timestamp": (now - timedelta(days=30)).isoformat()},
    ]
    monkeypatch.setattr(crtsh, "get", lambda *a, **k: FakeResponse(json.dumps(rows)))
    monkeypatch.setattr(crtsh.time, "sleep", lambda s: None)
    brand = Brand(id="biat", name="BIAT", country="TN", sector="bank", keywords=["biat"], weak_keywords=["xx"])
    res = crtsh.collect_crtsh([brand], lookback_days=3)
    assert sorted(o.value for o in res.observations) == ["biat-login.xyz", "www.biat-login.xyz"]


def test_crtsh_treats_404_as_no_results(monkeypatch):
    monkeypatch.setattr(crtsh, "get", lambda *a, **k: FakeResponse("not found", status=404))
    monkeypatch.setattr(crtsh.time, "sleep", lambda s: None)
    brand = Brand(id="atb", name="ATB", country="TN", sector="bank", keywords=["atbbank"])
    res = crtsh.collect_crtsh([brand])
    assert res.status == "ok" and res.observations == [] and "failed" not in res.detail


def test_crtsh_rotates_keywords_daily():
    kws = ["a", "b", "c"]
    days = {tuple(crtsh._rotate(kws, date(2026, 10, d))) for d in (20, 21, 22)}
    assert len(days) == 3
    assert all(sorted(k) == kws for k in days)


def test_crtsh_stops_at_time_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(crtsh, "get", lambda *a, **k: calls.append(1) or FakeResponse("[]"))
    monkeypatch.setattr(crtsh.time, "sleep", lambda s: None)
    brand = Brand(id="x", name="X", country="TN", sector="bank", keywords=["alpha", "bravo", "charlie"])
    res = crtsh.collect_crtsh([brand], budget_minutes=0)
    assert calls == []
    assert "time budget" in res.detail


def test_crtsh_skips_weak_keywords():
    brand = Brand(id="stb", name="STB", country="TN", sector="bank", keywords=["stbbank"], weak_keywords=["stb"])
    assert crtsh._keywords([brand]) == ["stbbank"]


def test_urlhaus_skipped_without_key(monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    res = urlhaus.collect_urlhaus()
    assert res.status == "skipped"


def test_urlhaus_with_key(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test")
    payload = {"query_status": "ok", "urls": [{"url": "http://evil.example/x.exe", "threat": "malware_download"}]}
    monkeypatch.setattr(urlhaus, "get", lambda *a, **k: FakeResponse(json.dumps(payload)))
    res = urlhaus.collect_urlhaus()
    assert res.observations[0].url == "http://evil.example/x.exe"
