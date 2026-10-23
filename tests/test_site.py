from datetime import date

from mtw.config import ROOT, load_allowlist
from mtw.pipeline import run
from mtw.site import build

SAMPLE = str(ROOT / "examples" / "sample_feed.txt")


def test_site_renders_findings_defanged(tmp_path, brands, settings):
    run(root=tmp_path, brands=brands, settings=settings, allowlist=load_allowlist(),
        sources=[], inputs=[SAMPLE], day=date(2026, 10, 22))
    index = build(tmp_path, tmp_path / "site", brands)
    page = index.read_text()
    assert "18 new suspicious domains on 22 October 2026." in page
    assert "biat-secure-login[.]xyz" in page
    assert "biat-secure-login.xyz" not in page.split('<code id="xql">')[0]  # defanged outside the hunts
    assert "dataset = xdr_data" in page
    for rel in ("favicon.svg", "feeds/domains.txt", "feeds/domains.csv", "hunts/latest.xql", "hunts/latest.spl"):
        assert (tmp_path / "site" / rel).exists(), rel


def test_site_escapes_html(tmp_path, brands, settings):
    feed = tmp_path / "evil.txt"
    feed.write_text("biat-login.xyz\n")
    run(root=tmp_path, brands=brands, settings=settings, allowlist=load_allowlist(),
        sources=[], inputs=[str(feed)], day=date(2026, 10, 22))
    hist = tmp_path / "data" / "findings.jsonl"
    hist.write_text(hist.read_text().replace('"brand_name": "BIAT"', '"brand_name": "<script>x</script>"'))
    page = build(tmp_path, tmp_path / "site", brands).read_text()
    assert "<script>x</script>" not in page
    assert "&lt;script&gt;x&lt;/script&gt;" in page


def test_site_empty_state(tmp_path, brands, settings):
    run(root=tmp_path, brands=brands, settings=settings, allowlist=load_allowlist(),
        sources=[], inputs=[], day=date(2026, 10, 22))
    page = build(tmp_path, tmp_path / "site", brands).read_text()
    assert "No new lookalikes on 22 October 2026." in page
    assert "Nothing medium or high in the last 30 days" in page


def test_site_writes_stats_json(tmp_path, brands, settings):
    import json
    run(root=tmp_path, brands=brands, settings=settings, allowlist=load_allowlist(),
        sources=[], inputs=[SAMPLE], day=date(2026, 10, 22))
    build(tmp_path, tmp_path / "site", brands)
    st = json.loads((tmp_path / "site" / "stats.json").read_text())
    assert st["last_run_day"] == "2026-10-22"
    assert st["domains_checked_last_run"] == 29
    assert st["new_last_run"] == 18
    assert st["findings_30d"] == 17 and st["brands"] == 45
