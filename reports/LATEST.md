# Maghreb Threat Watch | 2026-10-29

Lookalike and phishing domains targeting North African banks, telecoms, postal
services and government portals. Domains are defanged: `[.]` stands for a dot.

**No new suspicious domains today.**

Checked 71,300 domains and URLs.

## Sources

| Source | Status | Items | Time | Note |
|---|---|---:|---:|---|
| crt.sh | ok | 0 | 929.1s | 8/67 queries failed (crt.sh is often overloaded) |
| openphish | ok | 300 | 0.0s |  |
| whoisds | ok | 70,000 | 2.5s | newly registered on 2026-10-28 |
| urlhaus | ok | 1,000 | 1.2s |  |

## Hunt for these in your environment

Ready-made queries covering the last 30 days of medium and high findings:

- Cortex XDR / XSIAM (XQL): [`hunts/latest.xql`](../hunts/latest.xql)
- Splunk (CIM Network_Resolution): [`hunts/latest.spl`](../hunts/latest.spl)
- Plain blocklist: [`feeds/domains.txt`](../feeds/domains.txt)

---

Generated automatically from public sources only. Nothing here was visited, scanned
or probed. A flagged domain is a lead, not a verdict: verify before blocking.
Report confirmed phishing to the brand owner and to the national CERT
(tunCERT at ANCS in Tunisia, maCERT at DGSSI in Morocco).
