# Cyber Threat Wall

A filterable, stock-wall-style dashboard for vulnerabilities that CISA says are **known to be actively exploited**.

**Primary data source:** CISA Known Exploited Vulnerabilities (KEV)  
**Enrichment source:** NIST National Vulnerability Database (NVD)

## What it shows

- Every vulnerability currently listed in CISA KEV
- Threat Score from 0–100 for prioritization
- CVSS score where NVD enrichment is available
- Vendor and product
- Date added to KEV
- Federal remediation due date
- Known ransomware campaign use
- CWE weakness identifiers
- Search, vendor, CVSS, age, ransomware and due-date filters
- Wall and table views
- Direct links to CISA KEV and NVD

## Threat Score

The score is intentionally simple and auditable:

- **35 points** — baseline for being in CISA KEV
- **0–25 points** — NVD CVSS base score
- **0–20 points** — recency of addition to KEV
- **0–10 points** — CISA remediation due-date urgency
- **10 points** — CISA reports known ransomware campaign use

Maximum: **100**

This is a prioritization aid, not a replacement for CISA/NVD guidance or an organization's own asset and exposure context.

## Data updates

GitHub Actions runs every six hours.

1. Downloads CISA's official KEV JSON mirror.
2. Uses a local NVD cache.
3. Enriches missing/stale CVEs using the NVD CVE 2.0 API.
4. Rebuilds `data/threat-wall.json`.
5. Commits data changes automatically.
6. GitHub Pages deploys the current repository.

### Optional NVD API key

The dashboard works without one, but initial NVD enrichment is deliberately gradual to respect public API limits.

For faster enrichment:

1. Request an NVD API key from NIST.
2. In the GitHub repository, open **Settings → Secrets and variables → Actions**.
3. Create a repository secret named `NVD_API_KEY`.
4. Run **Actions → Update threat data → Run workflow**.

CISA KEV content is available immediately even while NVD enrichment is filling the cache.

## GitHub Pages

The repository includes a Pages deployment workflow. In the repository:

**Settings → Pages → Source → GitHub Actions**

Then run the **Update threat data** workflow once.

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

## License

Application code: MIT.  
Source data remains subject to the terms of its respective government data sources. CISA's KEV data repository states that its KEV data is published under CC0.
