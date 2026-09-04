# Cyber Threat Wall

A filterable, stock-wall-style dashboard for vulnerabilities that CISA says are **known to be actively exploited**.

**Primary data source:** CISA Known Exploited Vulnerabilities (KEV)  
**Enrichment sources:** NIST National Vulnerability Database (NVD) + FIRST EPSS

Live site: https://mattsimoto.github.io/cyber-threat-wall/

## What it shows

- Every vulnerability currently listed in CISA KEV
- Transparent **Threat Signal** from 0–100
- CVSS score where NVD enrichment is available
- FIRST EPSS exploitation probability and percentile
- Vendor, product and technology classification
- Date added to KEV and federal remediation due date
- Known ransomware campaign use
- Network-exploitable / no-privileges-required / public-exploit indicators where NVD data supports them
- 24-hour and 7-day rank movement as historical snapshots accumulate
- Rank-history sparklines
- Market Movers, Analyst View and Executive View
- Vendor intelligence pages generated from the live data
- Shareable filtered URLs
- “New since yesterday” mode
- CSV export of the current filtered view
- Weekly threat summary
- JSON and RSS outputs for automation and syndication

## Threat Signal

The current 100-point model is intentionally transparent:

- **35 points** — confirmed active exploitation through CISA KEV membership
- **0–20 points** — NVD CVSS severity
- **0–20 points** — FIRST EPSS exploitation probability
- **0–10 points** — recency of addition to CISA KEV
- **0–10 points** — known ransomware campaign use
- **0–5 points** — CISA remediation urgency

Maximum: **100**

Threat Signal is a prioritization aid, not an organization-specific risk score. Organizational risk still depends on asset presence, exposure, compensating controls and business context.

## Practitioner workflows

### Vendor intelligence

Selecting a vendor opens a vendor-specific intelligence panel showing active KEVs, average Threat Signal, ransomware-linked vulnerabilities, network-exploitable entries, new additions, technology concentration and top CVEs. Vendor views are shareable through URL parameters.

### Shareable views

The browser URL tracks relevant filters such as vendor, technology, CVSS, EPSS, ransomware status, exploit traits, due-date status, search and sort mode. Use **Copy share link** to send the current view to another person.

### New since yesterday

The **New since yesterday** control compares the current catalog against the most recent previous daily snapshot. On a new deployment with no prior snapshot, it falls back to entries added today.

### CSV export

**Export CSV** downloads the currently visible filtered result set, including Threat Signal, movement, CVSS, EPSS, technology, ransomware and exploit traits.

## Public JSON / RSS outputs

The scheduled data job publishes:

- `data/api-index.json` — endpoint directory
- `data/threat-wall.json` — full dashboard payload
- `data/latest-movers.json` — 24H / 7D movers and newest entries
- `data/new-since-yesterday.json` — daily change set
- `data/vendors.json` — vendor summaries and top vulnerabilities
- `data/weekly-summary.json` — seven-day intelligence brief
- `data/history.json` — retained daily snapshots
- `feed/latest-movers.xml` — RSS feed for latest movers
- `feed/new-kevs.xml` — RSS feed for new KEVs
- `feed/weekly-summary.xml` — RSS feed for the weekly brief

These are static GitHub Pages resources and can be consumed by scripts, dashboards, newsletters or other tools without a backend.

## Historical data

The sync job keeps one daily market snapshot and retains the latest 90 days. Each snapshot stores current ranking and Threat Signal values so the interface can calculate authentic movement rather than estimating historical changes.

- 24H movement appears once a legitimate approximately one-day-old baseline exists.
- 7D movement appears once a legitimate approximately seven-day-old baseline exists.
- Sparklines grow automatically as observations accumulate.

## Data updates

GitHub Actions runs every six hours.

1. Downloads CISA's official KEV JSON mirror.
2. Uses a local NVD cache and enriches missing/stale CVEs through the NVD CVE 2.0 API.
3. Fetches FIRST EPSS values in multi-CVE batches.
4. Calculates Threat Signal and technology categories.
5. Compares current rankings with historical snapshots.
6. Rebuilds dashboard, API, vendor, daily-change, weekly-summary and RSS outputs.
7. Commits changed data automatically.
8. GitHub Pages deploys the current repository.

### Optional NVD API key

The dashboard works without one, but initial NVD enrichment is deliberately gradual to respect public API limits.

For faster enrichment:

1. Request an NVD API key from NIST.
2. In the GitHub repository, open **Settings → Secrets and variables → Actions**.
3. Create a repository secret named `NVD_API_KEY`.
4. Run **Actions → Update threat data → Run workflow**.

CISA KEV and EPSS content remain available while NVD enrichment fills the cache.

## GitHub Pages

The repository includes a Pages deployment workflow. In the repository:

**Settings → Pages → Source → GitHub Actions**

## Local preview

Any static web server works:

```bash
python -m http.server 8000
```

Open `http://localhost:8000`.

## Data attribution

- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV data repository: https://github.com/cisagov/kev-data
- NIST National Vulnerability Database: https://nvd.nist.gov/
- FIRST Exploit Prediction Scoring System: https://www.first.org/epss/

## License

Application code: MIT.  
Source data remains subject to the terms of its respective sources. CISA's KEV data repository states that its KEV data is published under CC0.
