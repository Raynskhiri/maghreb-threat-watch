"""Markdown reports, blocklist feeds and SIEM hunting queries."""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import date
from urllib.parse import urlsplit, urlunsplit

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


# ---------------------------------------------------------------- defanging
def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return defang_host(url).replace("http", "hxxp", 1)
    scheme = parts.scheme.replace("http", "hxxp") if parts.scheme else ""
    return urlunsplit((scheme, defang_host(parts.netloc), parts.path, parts.query, parts.fragment))


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


# ------------------------------------------------------------- daily report
def render_daily_report(day: date, new_findings: list[dict], source_results: list, total_observations: int,
                        repeat_count: int, root: str = "../../../") -> str:
    counts = Counter(f["severity"] for f in new_findings)
    lines = [
        f"# Maghreb Threat Watch | {day.isoformat()}",
        "",
        "Lookalike and phishing domains targeting North African banks, telecoms, postal",
        "services and government portals. Domains are defanged: `[.]` stands for a dot.",
        "",
    ]
    if new_findings:
        parts = [f"{SEVERITY_ICON[s]} **{counts[s]} {s}**" for s in ("high", "medium", "low") if counts.get(s)]
        noun = "domain" if len(new_findings) == 1 else "domains"
        lines.append(f"**{len(new_findings)} new suspicious {noun}:** " + ", ".join(parts))
    else:
        lines.append("**No new suspicious domains today.**")
    lines.append("")
    seen_again = ""
    if repeat_count:
        noun = "domain was" if repeat_count == 1 else "domains were"
        seen_again = f" {repeat_count} already-reported {noun} seen again and not repeated below."
    lines.append(f"Checked {total_observations:,} domains and URLs.{seen_again}")
    lines.append("")

    # Sources table
    lines += ["## Sources", "", "| Source | Status | Items | Time | Note |", "|---|---|---:|---:|---|"]
    for r in source_results:
        lines.append(f"| {r.name} | {r.status} | {len(r.observations):,} | {r.seconds}s | {_md(r.detail)} |")
    lines.append("")

    if new_findings:
        by_brand = Counter(f["brand_name"] for f in new_findings)
        lines += ["## Most targeted today", ""]
        for name, n in by_brand.most_common(5):
            lines.append(f"- {name}: {n}")
        lines.append("")

    for sev in ("high", "medium"):
        rows = [f for f in new_findings if f["severity"] == sev]
        if not rows:
            continue
        lines += [f"## {SEVERITY_ICON[sev]} {sev.capitalize()}", "",
                  "| Score | Domain | Brand | Why it was flagged | Seen in |", "|---:|---|---|---|---|"]
        for f in rows:
            lines.append(_finding_row(f))
        lines.append("")

    low = [f for f in new_findings if f["severity"] == "low"]
    if low:
        lines += ["<details>", f"<summary>🟡 Low confidence ({len(low)}): weak signals worth a glance</summary>", "",
                  "| Score | Domain | Brand | Why it was flagged | Seen in |", "|---:|---|---|---|---|"]
        for f in low:
            lines.append(_finding_row(f))
        lines += ["", "</details>", ""]

    lines += [
        "## Hunt for these in your environment",
        "",
        "Ready-made queries covering the last 30 days of medium and high findings:",
        "",
        f"- Cortex XDR / XSIAM (XQL): [`hunts/latest.xql`]({root}hunts/latest.xql)",
        f"- Splunk (CIM Network_Resolution): [`hunts/latest.spl`]({root}hunts/latest.spl)",
        f"- Plain blocklist: [`feeds/domains.txt`]({root}feeds/domains.txt)",
        "",
        "---",
        "",
        "Generated automatically from public sources only. Nothing here was visited, scanned",
        "or probed. A flagged domain is a lead, not a verdict: verify before blocking.",
        "Report confirmed phishing to the brand owner and to the national CERT",
        "(tunCERT at ANCS in Tunisia, maCERT at DGSSI in Morocco).",
        "",
    ]
    return "\n".join(lines)


def _finding_row(f: dict) -> str:
    shown = defang_host(f["unicode_host"])
    if f["unicode_host"] != f["host"]:
        shown += f" <br><sub>{defang_host(f['host'])}</sub>"
    if f.get("urls"):
        shown += f" <br><sub>{_md(defang_url(f['urls'][0])[:120])}</sub>"
    why = "<br>".join(_md(r) for r in f["reasons"])
    return (f"| {f['score']} | {shown} | {_md(f['brand_name'])} ({f['country']}) | {why} | "
            f"{', '.join(f['sources'])} |")


# --------------------------------------------------------- feeds and hunts
def _hunt_domains(findings: list[dict]) -> list[str]:
    """Domains to hunt for: the registrable domain covers every subdomain."""
    out: list[str] = []
    for f in findings:
        d = f.get("registrable") or f["host"]
        if d not in out:
            out.append(d)
    return out


def render_feed_txt(findings: list[dict], day: date) -> str:
    header = [
        "# Maghreb Threat Watch: suspected lookalike/phishing domains (medium and high)",
        f"# Updated {day.isoformat()} | rolling 30 days | verify before blocking",
    ]
    return "\n".join(header + _hunt_domains(findings)) + "\n"


def render_feed_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["first_seen", "domain", "host", "brand", "country", "sector", "severity", "score", "match_type", "sources"])
    for f in findings:
        w.writerow([f["date"], f.get("registrable") or f["host"], f["host"], f["brand_name"], f["country"],
                    f["sector"], f["severity"], f["score"], f["match_type"], " ".join(f["sources"])])
    return buf.getvalue()


def render_xql(findings: list[dict], day: date) -> str:
    domains = _hunt_domains(findings)
    if not domains:
        return ("// Maghreb Threat Watch: no medium or high findings in the last 30 days.\n"
                "// Nothing to hunt for today.\n")
    alternation = "|".join(d.replace(".", "[.]") for d in domains)
    regex = f"(^|[.])(?:{alternation})$"
    return "\n".join([
        f"// Maghreb Threat Watch hunt | generated {day.isoformat()}",
        f"// {len(domains)} lookalike/phishing domains (medium and high, rolling 30 days)",
        "// Finds endpoints that resolved or connected to any of them, subdomains included.",
        "// Source: https://github.com/Raynskhiri/maghreb-threat-watch",
        "config case_sensitive = false",
        "| dataset = xdr_data",
        "| filter event_type = ENUM.NETWORK",
        f'| filter dns_query_name ~= "{regex}"',
        f'      or action_external_hostname ~= "{regex}"',
        "| fields _time, agent_hostname, actor_effective_username, actor_process_image_name,",
        "         dns_query_name, action_external_hostname, action_remote_ip",
        "| sort desc _time",
        "",
    ])


def render_spl(findings: list[dict], day: date) -> str:
    domains = _hunt_domains(findings)
    if not domains:
        return "``` Maghreb Threat Watch: no medium or high findings in the last 30 days. ```\n"
    values = ", ".join(f'"{d}", "*.{d}"' for d in domains)
    return "\n".join([
        f"``` Maghreb Threat Watch hunt | generated {day.isoformat()} | {len(domains)} domains ```",
        "``` Needs DNS data mapped to the CIM Network_Resolution data model. ```",
        "| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen",
        "    from datamodel=Network_Resolution",
        f"    where DNS.query IN ({values})",
        "    by DNS.src DNS.query",
        "| convert ctime(first_seen) ctime(last_seen)",
        "| sort - count",
        "",
    ])


def render_alert(day: date, findings: list[dict], report_path: str) -> str:
    lines = [
        f"Maghreb Threat Watch found **{len(findings)}** new high-confidence lookalike or phishing "
        f"domain(s) on {day.isoformat()}.",
        "",
        "| Score | Domain | Brand | Seen in |",
        "|---:|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f['score']} | {defang_host(f['unicode_host'])} | {_md(f['brand_name'])} | "
                     f"{', '.join(f['sources'])} |")
    lines += ["", f"Full report with the reasoning for each domain: `{report_path}`", "",
              "Triage checklist:",
              "- [ ] Confirm the site is live and impersonating the brand (use a sandboxed browser or urlscan.io)",
              "- [ ] Notify the brand owner's security team",
              "- [ ] Report to the national CERT and request a takedown",
              "- [ ] Hunt for the domain with `hunts/latest.xql` or `hunts/latest.spl`"]
    return "\n".join(lines) + "\n"
