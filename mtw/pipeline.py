"""One daily run: collect, score, deduplicate, write reports, feeds and hunts."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from .collectors import COLLECTORS, SourceResult, collect_file
from .config import Brand, Settings
from .matcher import Matcher
from .report import (
    SEVERITY_ORDER,
    render_alert,
    render_daily_report,
    render_feed_csv,
    render_feed_txt,
    render_spl,
    render_xql,
)
from .state import State

log = logging.getLogger(__name__)
FEED_WINDOW_DAYS = 30
MAX_URLS_PER_HOST = 3


@dataclass
class RunSummary:
    day: str
    observations: int
    findings: int
    new_findings: int
    new_by_severity: dict = field(default_factory=dict)
    alert: bool = False
    report_path: str = ""
    sources: dict = field(default_factory=dict)


def collect(sources: list[str], inputs: list[str], brands: list[Brand], settings: Settings,
            day: date) -> list[SourceResult]:
    results: list[SourceResult] = []
    for name in sources:
        cfg = dict(settings.sources.get(name, {}) or {})
        if not cfg.pop("enabled", True):
            log.info("source %s disabled in settings", name)
            continue
        fn = COLLECTORS[name]
        log.info("collecting from %s", name)
        if name == "crtsh":
            res = fn(brands, lookback_days=settings.lookback_days, **cfg)
        elif name == "whoisds":
            res = fn(day=day - timedelta(days=1))
        else:
            res = fn(**cfg)
        log.info("  %s: %s, %d items, %ss %s", res.name, res.status, len(res.observations), res.seconds, res.detail)
        results.append(res)
    for path in inputs:
        res = collect_file(path)
        log.info("  %s: %s, %d items", res.name, res.status, len(res.observations))
        results.append(res)
    return results


def score(results: list[SourceResult], matcher: Matcher) -> dict[str, dict]:
    """Best finding per host, with every source and a few URLs that mentioned it."""
    by_host: dict[str, dict] = {}
    for res in results:
        for obs in res.observations:
            f = matcher.evaluate(obs.value)
            if f is None:
                continue
            entry = by_host.get(f.host)
            if entry is None or f.score > entry["score"]:
                merged_sources = entry["sources"] if entry else []
                merged_urls = entry["urls"] if entry else []
                entry = f.to_dict() | {"sources": merged_sources, "urls": merged_urls}
                by_host[f.host] = entry
            if obs.source not in entry["sources"]:
                entry["sources"].append(obs.source)
            if obs.url and obs.url not in entry["urls"] and len(entry["urls"]) < MAX_URLS_PER_HOST:
                entry["urls"].append(obs.url)
    return by_host


def _sort_key(f: dict) -> tuple:
    return SEVERITY_ORDER.get(f["severity"], 9), -f["score"], f["host"]


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def run(*, root: Path, brands: list[Brand], settings: Settings, allowlist: set[str],
        sources: list[str], inputs: list[str] | None = None, day: date | None = None,
        use_state: bool = True) -> RunSummary:
    day = day or date.today()
    inputs = inputs or []
    matcher = Matcher(brands, settings, allowlist)

    results = collect(sources, inputs, brands, settings, day)
    total = sum(len(r.observations) for r in results)
    found = score(results, matcher)

    state = State(root / "data" / "state.json")
    if not use_state:
        state.hosts = {}
    new = sorted((f for h, f in found.items() if state.is_new(h)), key=_sort_key)
    repeats = len(found) - len(new)
    for h, f in found.items():
        state.touch(h, day, f["score"], f["severity"])
    pruned = state.prune(day, settings.state_retention_days)
    if pruned:
        log.info("forgot %d domains not seen for %d days", pruned, settings.state_retention_days)

    # Daily report
    report_rel = Path("reports") / f"{day:%Y}" / f"{day:%m}" / f"{day.isoformat()}.md"
    report_path = root / report_rel
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_daily_report(day, new, results, total, repeats), encoding="utf-8")
    (root / "reports" / "LATEST.md").write_text(
        render_daily_report(day, new, results, total, repeats, root="../"), encoding="utf-8")

    # History of every new finding
    history_path = root / "data" / "findings.jsonl"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as fh:
        for f in new:
            fh.write(json.dumps({"date": day.isoformat(), **f}, ensure_ascii=False) + "\n")

    # Rolling feeds and hunting queries (medium and high, last 30 days)
    cutoff = (day - timedelta(days=FEED_WINDOW_DAYS)).isoformat()
    history = _load_jsonl(history_path)
    window = sorted((f for f in history if f.get("date", "") >= cutoff and f.get("severity") in ("high", "medium")),
                    key=lambda f: (f["date"], -f["score"]), reverse=True)
    for sub, name, text in (
        ("feeds", "domains.txt", render_feed_txt(window, day)),
        ("feeds", "domains.csv", render_feed_csv(window)),
        ("hunts", "latest.xql", render_xql(window, day)),
        ("hunts", "latest.spl", render_spl(window, day)),
    ):
        (root / sub).mkdir(parents=True, exist_ok=True)
        (root / sub / name).write_text(text, encoding="utf-8")

    if use_state:
        state.save()

    # Machine-readable summary and optional alert for the workflow
    alert_level = SEVERITY_ORDER.get(settings.alert_severity, 0)
    alert_findings = [f for f in new if SEVERITY_ORDER.get(f["severity"], 9) <= alert_level]
    out_dir = root / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    alert_file = out_dir / "alert.md"
    if alert_findings:
        alert_file.write_text(render_alert(day, alert_findings, str(report_rel)), encoding="utf-8")
    elif alert_file.exists():
        alert_file.unlink()

    by_sev: dict[str, int] = {}
    for f in new:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    summary = RunSummary(
        day=day.isoformat(),
        observations=total,
        findings=len(found),
        new_findings=len(new),
        new_by_severity=by_sev,
        alert=bool(alert_findings),
        report_path=str(report_rel),
        sources={r.name: {"status": r.status, "items": len(r.observations), "detail": r.detail} for r in results},
    )
    (out_dir / "summary.json").write_text(json.dumps(summary.__dict__, indent=2) + "\n", encoding="utf-8")
    return summary
