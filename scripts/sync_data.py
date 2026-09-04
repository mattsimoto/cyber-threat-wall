#!/usr/bin/env python3
"""
Build data/threat-wall.json from CISA KEV and enrich entries from NVD.

CISA KEV is authoritative for inclusion. NVD is optional enrichment.
The script maintains data/nvd-cache.json so scheduled runs only query
NVD for missing/stale CVEs.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUT_FILE = DATA_DIR / "threat-wall.json"
CACHE_FILE = DATA_DIR / "nvd-cache.json"

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_KEY = os.getenv("NVD_API_KEY", "").strip()
MAX_NVD_REQUESTS = int(os.getenv("MAX_NVD_REQUESTS", "40" if not API_KEY else "250"))
REQUEST_DELAY = float(os.getenv("NVD_REQUEST_DELAY", "6.2" if not API_KEY else "0.75"))
CACHE_MAX_AGE_DAYS = int(os.getenv("NVD_CACHE_MAX_AGE_DAYS", "30"))

DATA_DIR.mkdir(parents=True, exist_ok=True)


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 45):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Cyber-Threat-Wall/1.0 (+GitHub Pages)",
            "Accept": "application/json",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def load_cache():
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def parse_nvd(cve_id: str, payload: dict):
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {"fetchedAt": datetime.now(timezone.utc).isoformat(), "cvssScore": None, "cwes": []}

    cve = vulnerabilities[0].get("cve", {})
    metrics = cve.get("metrics", {})

    score = None
    vector = None
    version = None

    for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        rows = metrics.get(key) or []
        if rows:
            rows = sorted(rows, key=lambda r: 0 if r.get("type") == "Primary" else 1)
            data = rows[0].get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            version = label
            break

    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    return {
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
        "cvssScore": score,
        "cvssVector": vector,
        "cvssVersion": version,
        "cwes": cwes,
        "nvdPublished": cve.get("published"),
        "nvdLastModified": cve.get("lastModified"),
    }


def cache_stale(entry: dict | None):
    if not entry or not entry.get("fetchedAt"):
        return True
    try:
        fetched = datetime.fromisoformat(entry["fetchedAt"].replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - fetched
        return age.days >= CACHE_MAX_AGE_DAYS
    except Exception:
        return True


def fetch_nvd(cve_id: str):
    params = urllib.parse.urlencode({"cveId": cve_id})
    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY
    return parse_nvd(cve_id, fetch_json(f"{NVD_URL}?{params}", headers=headers))


def day_delta(date_string: str | None):
    if not date_string:
        return 99999
    try:
        d = date.fromisoformat(date_string[:10])
        return (date.today() - d).days
    except Exception:
        return 99999


def days_until(date_string: str | None):
    if not date_string:
        return 99999
    try:
        d = date.fromisoformat(date_string[:10])
        return (d - date.today()).days
    except Exception:
        return 99999


def threat_score(v: dict):
    score = 35

    cvss = v.get("cvssScore")
    if isinstance(cvss, (int, float)):
        score += round((float(cvss) / 10.0) * 25)

    age = day_delta(v.get("dateAdded"))
    if age <= 7:
        score += 20
    elif age <= 30:
        score += 15
    elif age <= 90:
        score += 10
    elif age <= 365:
        score += 5

    due = days_until(v.get("dueDate"))
    if due < 0:
        score += 10
    elif due <= 7:
        score += 8
    elif due <= 30:
        score += 4

    if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
        score += 10

    return min(100, score)


def main():
    print("Fetching CISA KEV…")
    kev = fetch_json(KEV_URL)
    vulns = kev.get("vulnerabilities") or []
    cache = load_cache()

    ordered = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    candidates = [v["cveID"] for v in ordered if cache_stale(cache.get(v["cveID"]))]

    attempts = 0
    for cve_id in candidates[:MAX_NVD_REQUESTS]:
        try:
            print(f"NVD {cve_id}")
            cache[cve_id] = fetch_nvd(cve_id)
            attempts += 1
            save_cache(cache)
            if REQUEST_DELAY:
                time.sleep(REQUEST_DELAY)
        except urllib.error.HTTPError as e:
            print(f"Warning: NVD HTTP {e.code} for {cve_id}")
            if e.code in (403, 429):
                break
        except Exception as e:
            print(f"Warning: NVD error for {cve_id}: {e}")

    output = []
    for item in vulns:
        merged = dict(item)
        enrich = cache.get(item.get("cveID"), {})
        merged.update({
            "cvssScore": enrich.get("cvssScore"),
            "cvssVector": enrich.get("cvssVector"),
            "cvssVersion": enrich.get("cvssVersion"),
            "cwes": enrich.get("cwes") or [],
            "nvdPublished": enrich.get("nvdPublished"),
            "nvdLastModified": enrich.get("nvdLastModified"),
        })
        merged["threatScore"] = threat_score(merged)
        output.append(merged)

    output.sort(key=lambda x: (x.get("threatScore", 0), x.get("dateAdded", "")), reverse=True)

    payload = {
        "meta": {
            "title": kev.get("title", "CISA Known Exploited Vulnerabilities"),
            "catalogVersion": kev.get("catalogVersion"),
            "catalogDateReleased": kev.get("dateReleased"),
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "kevSource": KEV_URL,
            "nvdSource": NVD_URL,
            "nvdCachedEntries": len(cache),
            "nvdRequestsThisRun": attempts,
            "rankingVersion": "1.0",
        },
        "vulnerabilities": output,
    }
    OUT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    save_cache(cache)
    print(f"Wrote {OUT_FILE} with {len(output)} vulnerabilities.")


if __name__ == "__main__":
    main()
