# Maghreb Threat Watch | 2026-11-14

Lookalike and phishing domains targeting North African banks, telecoms, postal
services and government portals. Domains are defanged: `[.]` stands for a dot.

**1 new suspicious domain:** 🟡 **1 low**

Checked 71,248 domains and URLs.

## Sources

| Source | Status | Items | Time | Note |
|---|---|---:|---:|---|
| crt.sh | ok | 0 | 1301.5s | 11/67 queries failed (crt.sh is often overloaded) |
| openphish | ok | 300 | 0.1s |  |
| whoisds | ok | 70,000 | 2.1s | newly registered on 2026-11-13 |
| urlhaus | ok | 948 | 1.1s |  |

## Most targeted today

- CPA (Credit Populaire d'Algerie): 1

<details>
<summary>🟡 Low confidence (1): weak signals worth a glance</summary>

| Score | Domain | Brand | Why it was flagged | Seen in |
|---:|---|---|---|---|
| 38 | caabank[.]com | CPA (Credit Populaire d'Algerie) (DZ) | typo match on 'cpabank' in 'caabank' (+38) | whoisds |

</details>

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
