import json
from datetime import date

from mtw.config import ROOT, load_allowlist
from mtw.pipeline import run

SAMPLE = str(ROOT / "examples" / "sample_feed.txt")


def _run(tmp_path, brands, settings, day, inputs=(SAMPLE,)):
    return run(root=tmp_path, brands=brands, settings=settings, allowlist=load_allowlist(),
               sources=[], inputs=list(inputs), day=day)


def test_full_run_writes_every_output(tmp_path, brands, settings):
    s = _run(tmp_path, brands, settings, date(2026, 10, 22))
    assert s.new_findings == 18
    assert s.new_by_severity["high"] >= 10
    for rel in ("reports/2026/10/2026-10-22.md", "reports/LATEST.md", "data/findings.jsonl",
                "data/state.json", "feeds/domains.txt", "feeds/domains.csv", "hunts/latest.xql",
                "hunts/latest.spl", "out/summary.json", "out/alert.md"):
        assert (tmp_path / rel).exists(), rel
    report = (tmp_path / "reports/LATEST.md").read_text()
    assert "biat-secure-login[.]xyz" in report
    assert "biat-secure-login.xyz" not in report        # defanged everywhere
    assert "posterflex" not in report                  # noise filtered


def test_second_run_does_not_repeat_known_domains(tmp_path, brands, settings):
    _run(tmp_path, brands, settings, date(2026, 10, 22))
    s2 = _run(tmp_path, brands, settings, date(2026, 10, 23))
    assert s2.new_findings == 0
    assert s2.findings == 18
    assert not (tmp_path / "out/alert.md").exists()
    history = (tmp_path / "data/findings.jsonl").read_text().splitlines()
    assert len(history) == 18
    state = json.loads((tmp_path / "data/state.json").read_text())["hosts"]
    assert state["biat-secure-login.xyz"]["first_seen"] == "2026-10-22"
    assert state["biat-secure-login.xyz"]["last_seen"] == "2026-10-23"


def test_feed_only_keeps_medium_and_high(tmp_path, brands, settings):
    _run(tmp_path, brands, settings, date(2026, 10, 22))
    feed = (tmp_path / "feeds/domains.txt").read_text()
    assert "biat-secure-login.xyz" in feed
    assert "cmi-paiement.com" not in feed              # low severity


def test_feed_window_drops_old_findings(tmp_path, brands, settings):
    _run(tmp_path, brands, settings, date(2026, 8, 1))
    _run(tmp_path, brands, settings, date(2026, 10, 22), inputs=[])
    feed = (tmp_path / "feeds/domains.txt").read_text()
    assert "biat-secure-login.xyz" not in feed
