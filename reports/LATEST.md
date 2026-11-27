# Maghreb Threat Watch | 2026-11-27

Lookalike and phishing domains targeting North African banks, telecoms, postal
services and government portals. Domains are defanged: `[.]` stands for a dot.

**2 new suspicious domains:** 🟠 **1 medium**, 🟡 **1 low**

Checked 71,300 domains and URLs.

## Sources

| Source | Status | Items | Time | Note |
|---|---|---:|---:|---|
| crt.sh | ok | 0 | 1176.5s | 14/67 queries failed (crt.sh is often overloaded) |
| openphish | ok | 300 | 0.0s |  |
| whoisds | ok | 70,000 | 2.4s | newly registered on 2026-11-26 |
| urlhaus | ok | 1,000 | 1.1s |  |

## Most targeted today

- Wifak International Bank: 1
- STB (Societe Tunisienne de Banque): 1

## 🟠 Medium

| Score | Domain | Brand | Why it was flagged | Seen in |
|---:|---|---|---|---|
| 50 | wifak-agency[.]com | Wifak International Bank (TN) | exact match on 'wifak' in 'wifak' (+50) | whoisds |

<details>
<summary>🟡 Low confidence (1): weak signals worth a glance</summary>

| Score | Domain | Brand | Why it was flagged | Seen in |
|---:|---|---|---|---|
| 40 | sms-stb[.]com | STB (Societe Tunisienne de Banque) (TN) | weak match on 'stb' in 'stb' (+25)<br>lure words ['sms'] (+15) | whoisds |

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
