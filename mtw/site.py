"""Render the public dashboard (threatwatch.rayenskhiri.online) as static files.

    python -m mtw site            # writes ./site from ./data, ./feeds, ./hunts

The page is plain HTML with no build step, so any static host can serve it.
Every domain on the page is defanged; raw domains only appear in the
downloadable feeds and hunt queries, which is what they are for.
"""

from __future__ import annotations

import html
import json
import shutil
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .config import Brand, load_brands
from .report import defang_host

REPO_URL = "https://github.com/Raynskhiri/maghreb-threat-watch"
AUTHOR_URL = "https://rayenskhiri.online"
SITE_URL = "https://threatwatch.rayenskhiri.online"
WINDOW_DAYS = 30
COUNTRY_NAMES = {"TN": "Tunisia", "MA": "Morocco", "DZ": "Algeria"}
SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low"}


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _nice_date(iso: str) -> str:
    try:
        d = date.fromisoformat(iso)
    except ValueError:
        return iso
    return f"{d.day} {d.strftime('%B %Y')}"


def _finding_rows(findings: list[dict]) -> str:
    out = []
    for f in findings:
        shown = _e(defang_host(f.get("unicode_host") or f["host"]))
        if f.get("unicode_host") and f["unicode_host"] != f["host"]:
            shown += f'<span class="puny">{_e(defang_host(f["host"]))}</span>'
        reasons = "".join(f"<li>{_e(r)}</li>" for r in f.get("reasons", []))
        out.append(
            f'<tr class="sev-{_e(f["severity"])}">'
            f'<td class="score"><span class="pill">{_e(f["score"])}</span></td>'
            f'<td class="dom">{shown}'
            f'<details><summary>Why it was flagged</summary><ul>{reasons}</ul></details></td>'
            f'<td>{_e(f["brand_name"])}<span class="sub">{_e(COUNTRY_NAMES.get(f["country"].split(",")[0], f["country"]))}</span></td>'
            f'<td class="when">{_e(_nice_date(f.get("date", "")))}<span class="sub">{_e(", ".join(f.get("sources", [])))}</span></td>'
            "</tr>"
        )
    return "\n".join(out)


def _table(findings: list[dict], caption: str) -> str:
    return (
        '<div class="table-wrap"><table class="findings">'
        f'<caption class="vh">{_e(caption)}</caption>'
        '<thead><tr><th scope="col">Score</th><th scope="col">Domain</th>'
        '<th scope="col">Impersonating</th><th scope="col">First seen</th></tr></thead>'
        f"<tbody>{_finding_rows(findings)}</tbody></table></div>"
    )


def _headline(today_new: list[dict], last_day: str | None) -> tuple[str, str]:
    if last_day is None:
        return ("Waiting for the first run.", "The first daily run has not finished yet. Check back tomorrow morning.")
    when = _nice_date(last_day)
    if not today_new:
        return (f"No new lookalikes on {when}.",
                "Quiet days are normal. Real campaigns show up a few times a week, and the feed below keeps the last 30 days.")
    n = len(today_new)
    sev = Counter(f["severity"] for f in today_new)
    parts = [f"{sev[s]} {s}" for s in ("high", "medium", "low") if sev.get(s)]
    noun = "domain" if n == 1 else "domains"
    return (f"{n} new suspicious {noun} on {when}.", "Severity: " + ", ".join(parts) + ".")


def _sources(run: dict | None) -> str:
    if not run:
        return "<p>No run recorded yet.</p>"
    rows = []
    for name, info in run.get("sources", {}).items():
        status = info.get("status", "")
        rows.append(
            f'<tr><th scope="row">{_e(name)}</th><td class="st st-{_e(status)}">{_e(status)}</td>'
            f'<td class="num">{int(info.get("items", 0)):,}</td><td>{_e(info.get("detail", ""))}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table class="sources"><thead><tr><th scope="col">Source</th>'
        '<th scope="col">Status</th><th scope="col" class="num">Items</th><th scope="col">Note</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
        f'<p class="note">Last run checked {int(run.get("observations", 0)):,} domains and URLs.</p>'
    )


def _coverage(brands: list[Brand]) -> str:
    by_country: dict[str, list[str]] = {}
    for b in brands:
        by_country.setdefault(b.country.split(",")[0], []).append(b.name)
    blocks = []
    for code in ("TN", "MA", "DZ"):
        names = by_country.get(code, [])
        if names:
            items = "".join(f"<li>{_e(n)}</li>" for n in names)
            blocks.append(f'<div class="country"><h3>{COUNTRY_NAMES[code]} <span class="sub">{len(names)}</span></h3><ul>{items}</ul></div>')
    return f'<div class="coverage">{"".join(blocks)}</div>'


def render(root: Path, brands: list[Brand], today: date | None = None) -> str:
    findings = _load_jsonl(root / "data" / "findings.jsonl")
    runs = _load_jsonl(root / "data" / "runs.jsonl")
    last_run = runs[-1] if runs else None
    last_day = last_run["day"] if last_run else (findings[-1]["date"] if findings else None)
    today = today or (date.fromisoformat(last_day) if last_day else date.today())
    cutoff = (today - timedelta(days=WINDOW_DAYS)).isoformat()

    key = lambda f: ({"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3), -f["score"], f["host"])
    today_new = sorted((f for f in findings if f.get("date") == last_day), key=key)
    window = sorted((f for f in findings if f.get("date", "") >= cutoff and f["severity"] in ("high", "medium")),
                    key=lambda f: (f["date"], f["score"]), reverse=True)
    today_low = [f for f in today_new if f["severity"] == "low"]
    title, sub = _headline(today_new, last_day)

    xql = (root / "hunts" / "latest.xql").read_text(encoding="utf-8") if (root / "hunts" / "latest.xql").exists() else ""
    spl = (root / "hunts" / "latest.spl").read_text(encoding="utf-8") if (root / "hunts" / "latest.spl").exists() else ""
    countries = len({b.country.split(",")[0] for b in brands})
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if window:
        feed_html = _table(window, "Medium and high findings, last 30 days")
    else:
        feed_html = ('<p class="empty">Nothing medium or high in the last 30 days. That usually means the brands '
                     'covered here were not being actively impersonated with new domains, not that the watch stopped: '
                     'see the source health below.</p>')
    low_html = ""
    if today_low:
        low_html = (f'<details class="low"><summary>Low-confidence signals from the latest run ({len(today_low)})</summary>'
                    f'{_table(today_low, "Low-confidence findings")}</details>')

    return PAGE.format(
        title=_e(title), sub=_e(sub), feed=feed_html, low=low_html,
        xql=_e(xql), spl=_e(spl), sources=_sources(last_run), coverage=_coverage(brands),
        brands=len(brands), countries=countries, window=WINDOW_DAYS, repo=REPO_URL, author=AUTHOR_URL,
        site=SITE_URL, updated=_e(updated),
    )


def build(root: Path, out: Path, brands: list[Brand] | None = None, today: date | None = None) -> Path:
    brands = brands if brands is not None else load_brands()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / "index.html").write_text(render(root, brands, today), encoding="utf-8")
    (out / "favicon.svg").write_text(FAVICON, encoding="utf-8")
    for sub, name in (("feeds", "domains.txt"), ("feeds", "domains.csv"), ("hunts", "latest.xql"), ("hunts", "latest.spl")):
        src = root / sub / name
        if src.exists():
            (out / sub).mkdir(exist_ok=True)
            shutil.copy2(src, out / sub / name)
    (out / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")
    (out / "stats.json").write_text(json.dumps(stats(root, brands), indent=1) + "\n", encoding="utf-8")
    return out / "index.html"


def stats(root: Path, brands: list[Brand]) -> dict:
    """Small public summary that rayenskhiri.online reads to show live numbers."""
    findings = _load_jsonl(root / "data" / "findings.jsonl")
    runs = _load_jsonl(root / "data" / "runs.jsonl")
    last = runs[-1] if runs else {}
    day = last.get("day")
    cutoff = ((date.fromisoformat(day) if day else date.today()) - timedelta(days=WINDOW_DAYS)).isoformat()
    window = [f for f in findings if f.get("date", "") >= cutoff and f.get("severity") in ("high", "medium")]
    return {
        "last_run_day": day,
        "domains_checked_last_run": last.get("observations"),
        "new_last_run": last.get("new_findings"),
        "findings_30d": len(window),
        "high_30d": sum(1 for f in window if f["severity"] == "high"),
        "runs": len(runs),
        "brands": len(brands),
        "countries": len({b.country.split(",")[0] for b in brands}),
        "sources_ok": sorted(k for k, v in last.get("sources", {}).items() if v.get("status") == "ok"),
    }


FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#FF6B1A"/><circle cx="32" cy="32" r="15" fill="none" stroke="#1A0B02" stroke-width="5"/><circle cx="32" cy="32" r="4.5" fill="#1A0B02"/></svg>
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Maghreb Threat Watch | Phishing lookalikes targeting North Africa</title>
<meta name="description" content="Daily, open early warning for lookalike and phishing domains targeting banks, telecoms and public services in Tunisia, Morocco and Algeria.">
<meta property="og:title" content="Maghreb Threat Watch">
<meta property="og:description" content="{title} Open early warning for phishing aimed at North Africa.">
<meta property="og:url" content="{site}/">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,300..900&display=swap" rel="stylesheet">
<style>
:root {{
  /* Same brand as rayenskhiri.online: near-black, orange accent. */
  --wash: #0A0C10; --ink: #F2F4F7; --blue: #FF8C42; --blue-soft: #1C1510; --stone: #A3ABB8;
  --rule: #242B37; --marker: #FF6B1A; --high: #FF6B6B; --high-soft: #2E1719; --med: #FFB067; --med-soft: #2E2215;
  --code: #131821; --ok: #3DDC97; --accent: #FF6B1A; --accent-ink: #1A0B02;
  color-scheme: dark;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--wash); color: var(--ink); font-family: "Archivo", system-ui, sans-serif; -webkit-font-smoothing: antialiased; font-size: 1rem; line-height: 1.6; }}
a {{ color: var(--blue); text-underline-offset: 0.18em; text-decoration-thickness: 1px; }}
a:hover {{ text-decoration-thickness: 2px; }}
:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 2px; }}
.vh {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }}
.wrap {{ max-width: 1120px; margin: 0 auto; padding: 0 24px; }}
@media (max-width: 600px) {{ .wrap {{ padding: 0 16px; }} }}

header.top {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; padding: 24px 0 0; }}
.brand {{ display: flex; align-items: center; gap: 10px; font-weight: 600; text-decoration: none; color: var(--ink); }}
.brand svg {{ width: 28px; height: 28px; }}
header nav {{ display: flex; gap: 8px 20px; flex-wrap: wrap; }}
header nav a {{ color: var(--stone); text-decoration: none; font-size: 0.95rem; }}
header nav a:hover {{ color: var(--ink); }}

.hero {{ padding: 64px 0 40px; border-bottom: 1px solid var(--rule); }}
.hero p.what {{ color: var(--stone); margin: 0 0 14px; max-width: 46em; }}
.hero h1 {{ font-size: clamp(2.2rem, 5.6vw, 4.2rem); line-height: 1.02; letter-spacing: -0.02em; font-weight: 850; font-stretch: 108%; margin: 0 0 14px; max-width: 18ch; }}
.hero p.sub {{ font-size: 1.15rem; margin: 0; max-width: 40em; }}
.hero .scope {{ margin: 22px 0 0; color: var(--stone); font-size: 0.95rem; }}

section {{ padding: 48px 0; border-bottom: 1px solid var(--rule); }}
section > h2 {{ font-size: 1.6rem; letter-spacing: -0.01em; font-weight: 800; margin: 0 0 6px; }}
section > p.lede {{ color: var(--stone); margin: 0 0 22px; max-width: 46em; }}

.table-wrap {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; vertical-align: top; padding: 12px 14px 12px 0; border-bottom: 1px solid var(--rule); }}
thead th {{ font-weight: 500; color: var(--stone); font-size: 0.9rem; }}
.findings .score {{ width: 76px; }}
.pill {{ display: inline-block; min-width: 2.6em; text-align: center; padding: 2px 8px; border-radius: 6px; font-weight: 700; font-variant-numeric: tabular-nums; }}
.sev-high .pill {{ background: var(--high-soft); color: var(--high); }}
.sev-medium .pill {{ background: var(--med-soft); color: var(--med); }}
.sev-low .pill {{ background: var(--code); color: var(--stone); }}
.dom {{ font-weight: 600; word-break: break-all; min-width: 220px; }}
.puny, .sub {{ display: block; font-weight: 400; color: var(--stone); font-size: 0.88rem; }}
details summary {{ cursor: pointer; color: var(--blue); font-weight: 500; font-size: 0.9rem; margin-top: 4px; }}
details ul {{ margin: 6px 0 0; padding-left: 18px; font-weight: 400; color: var(--ink); font-size: 0.92rem; }}
.when {{ white-space: nowrap; }}
details.low {{ margin-top: 22px; }}
details.low > summary {{ font-size: 1rem; }}
@media (max-width: 640px) {{
  .findings thead {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }}
  .findings, .findings tbody {{ display: block; }}
  .findings tr {{ display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 4px 14px; padding: 14px 0; border-bottom: 1px solid var(--rule); }}
  .findings td {{ display: block; border: 0; padding: 0; }}
  .findings td.score {{ grid-row: span 3; width: auto; }}
  .findings td.dom {{ min-width: 0; }}
  .findings td.when {{ white-space: normal; }}
  .findings td.when, .findings td:nth-child(3) {{ font-size: 0.92rem; }}
  .findings td:nth-child(3) .sub, .findings td.when .sub {{ display: inline; margin-left: 6px; }}
}}
.empty {{ background: var(--blue-soft); border: 1px solid rgba(255,107,26,0.3); padding: 18px 20px; border-radius: 10px; max-width: 46em; margin: 0; }}

.hunts {{ display: grid; grid-template-columns: minmax(0, 1fr); gap: 26px; }}
.hunt {{ min-width: 0; }}
.hunt h3 {{ font-size: 1.1rem; margin: 0 0 8px; display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }}
.hunt pre {{ margin: 0; background: var(--code); padding: 16px 18px; border-radius: 10px; overflow-x: auto; font-size: 0.85rem; line-height: 1.55; }}
.hunt code {{ font-family: ui-monospace, "SF Mono", Consolas, monospace; }}
button.copy {{ font: inherit; font-size: 0.85rem; font-weight: 500; padding: 4px 12px; border-radius: 999px; border: 1px solid var(--rule); background: transparent; color: var(--ink); cursor: pointer; }}
button.copy:hover {{ border-color: var(--blue); }}
.downloads {{ display: flex; gap: 22px; flex-wrap: wrap; margin-top: 22px; font-weight: 500; }}

.sources td.num, .sources th.num {{ text-align: right; font-variant-numeric: tabular-nums; padding-right: 24px; }}
.st {{ font-weight: 600; }}
.st-ok {{ color: var(--ok); }}
.st-error {{ color: var(--high); }}
.st-skipped {{ color: var(--stone); }}
.note {{ color: var(--stone); font-size: 0.92rem; }}

.coverage {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 28px; }}
.coverage .country:first-child {{ grid-column: span 2; }}
.coverage .country:first-child ul {{ columns: 2; column-gap: 28px; }}
.country li {{ break-inside: avoid; }}
@media (max-width: 760px) {{
  .coverage {{ grid-template-columns: 1fr; }}
  .coverage .country:first-child {{ grid-column: auto; }}
}}
.country h3 {{ font-size: 1.1rem; margin: 0 0 8px; }}
.country h3 .sub {{ display: inline; margin-left: 6px; }}
.country ul {{ margin: 0; padding: 0; list-style: none; columns: 1; font-size: 0.95rem; }}
.country li {{ padding: 3px 0; border-bottom: 1px solid var(--rule); }}

.method p {{ max-width: 46em; }}
footer {{ padding: 28px 0 48px; color: var(--stone); font-size: 0.9rem; display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; align-items: center; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <a class="brand" href="/"><svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#FF6B1A"/><circle cx="32" cy="32" r="15" fill="none" stroke="#1A0B02" stroke-width="5"/><circle cx="32" cy="32" r="4.5" fill="#1A0B02"/></svg>Maghreb Threat Watch</a>
    <nav aria-label="Sections">
      <a href="#feed">Findings</a>
      <a href="#hunt">Hunt</a>
      <a href="#coverage">Coverage</a>
      <a href="{repo}">Source</a>
      <a href="{author}">Rayen Skhiri</a>
    </nav>
  </header>

  <main>
    <div class="hero">
      <p class="what">Open early warning for lookalike and phishing domains aimed at North African banks, telecoms, postal services and government portals.</p>
      <h1>{title}</h1>
      <p class="sub">{sub}</p>
      <p class="scope">Watching {brands} brands in {countries} countries. Updated every morning from certificate transparency, newly registered domains and public phishing feeds.</p>
    </div>

    <section id="feed" aria-labelledby="feed-title">
      <h2 id="feed-title">Findings, last {window} days</h2>
      <p class="lede">Medium and high confidence only. Domains are defanged: [.] stands for a dot. A finding is a lead to verify, not a verdict.</p>
      {feed}
      {low}
    </section>

    <section id="hunt" aria-labelledby="hunt-title">
      <h2 id="hunt-title">Hunt for them in your environment</h2>
      <p class="lede">Paste one of these into your SIEM to see whether anyone already resolved or visited these domains. They cover every medium and high finding of the last {window} days, subdomains included.</p>
      <div class="hunts">
        <div class="hunt">
          <h3>Cortex XDR or XSIAM (XQL) <button class="copy" type="button" data-target="xql">Copy query</button></h3>
          <pre><code id="xql">{xql}</code></pre>
        </div>
        <div class="hunt">
          <h3>Splunk (CIM Network_Resolution) <button class="copy" type="button" data-target="spl">Copy query</button></h3>
          <pre><code id="spl">{spl}</code></pre>
        </div>
      </div>
      <div class="downloads">
        <a href="feeds/domains.txt" download>Download blocklist (.txt)</a>
        <a href="feeds/domains.csv" download>Download with context (.csv)</a>
      </div>
    </section>

    <section aria-labelledby="health-title">
      <h2 id="health-title">Source health</h2>
      <p class="lede">What the latest run could reach. Free sources fail now and then; the watch carries on with the rest.</p>
      {sources}
    </section>

    <section id="coverage" aria-labelledby="coverage-title">
      <h2 id="coverage-title">Coverage</h2>
      <p class="lede">Brands watched today. Missing one? Open an issue or a pull request on <a href="{repo}">GitHub</a>.</p>
      {coverage}
    </section>

    <section class="method" aria-labelledby="method-title">
      <h2 id="method-title">How it works</h2>
      <p>Each new domain or certificate name is compared with every brand. Exact names, look-alike Unicode letters, leetspeak and typos score points, and so do the words phishing kits add (login, colis, facture, remboursement), country hints and heavily abused TLDs. Every point is written down, so you can see exactly why a domain was flagged. Official domains are never flagged.</p>
      <p>The watch is passive: it reads public feeds and certificate logs and never visits, scans or touches a suspected site. Report anything you confirm to the brand and to your national CERT.</p>
    </section>
  </main>

  <footer>
    <span>Built and maintained by <a href="{author}">Rayen Skhiri</a>. Open source under the MIT license. Page generated {updated}.</span>
  </footer>
</div>
<script>
(function () {{
  document.querySelectorAll('button.copy').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      var text = document.getElementById(btn.dataset.target).textContent;
      var done = function () {{ btn.textContent = 'Copied'; setTimeout(function () {{ btn.textContent = 'Copy query'; }}, 1600); }};
      if (navigator.clipboard) {{ navigator.clipboard.writeText(text).then(done, function () {{ btn.textContent = 'Select and copy'; }}); }}
    }});
  }});
}})();
</script>
</body>
</html>
"""
