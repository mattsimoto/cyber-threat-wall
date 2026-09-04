#!/usr/bin/env python3
"""Build Cyber Threat Wall data from CISA KEV, NVD and FIRST EPSS.

Phase 3 also produces stable JSON/RSS outputs for downstream use:
- data/latest-movers.json
- data/new-since-yesterday.json
- data/vendors.json
- data/weekly-summary.json
- data/api-index.json
- feed/latest-movers.xml
- feed/new-kevs.xml
- feed/weekly-summary.xml
"""
from __future__ import annotations

import html
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone, date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
FEED_DIR = ROOT / "feed"
OUT_FILE = DATA_DIR / "threat-wall.json"
CACHE_FILE = DATA_DIR / "nvd-cache.json"
HISTORY_FILE = DATA_DIR / "history.json"

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
SITE_URL = "https://mattsimoto.github.io/cyber-threat-wall/"

API_KEY = os.getenv("NVD_API_KEY", "").strip()
MAX_NVD_REQUESTS = int(os.getenv("MAX_NVD_REQUESTS", "40" if not API_KEY else "250"))
REQUEST_DELAY = float(os.getenv("NVD_REQUEST_DELAY", "6.2" if not API_KEY else "0.75"))
CACHE_MAX_AGE_DAYS = int(os.getenv("NVD_CACHE_MAX_AGE_DAYS", "30"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
FEED_DIR.mkdir(parents=True, exist_ok=True)


def fetch_json(url, headers=None, timeout=60):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Cyber-Threat-Wall/3.0 (+GitHub Pages)",
            "Accept": "application/json",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def read_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")


def parse_vector(vector):
    result = {"networkExploitable": False, "noPrivilegesRequired": False}
    if not vector:
        return result
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    result["networkExploitable"] = parts.get("AV") == "N"
    result["noPrivilegesRequired"] = parts.get("PR") == "N"
    return result


def parse_nvd(payload):
    rows = payload.get("vulnerabilities") or []
    if not rows:
        return {"fetchedAt": datetime.now(timezone.utc).isoformat(), "cvssScore": None, "cwes": []}
    cve = rows[0].get("cve", {})
    metrics = cve.get("metrics", {})
    score = vector = version = None
    for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        vals = metrics.get(key) or []
        if vals:
            vals = sorted(vals, key=lambda r: 0 if r.get("type") == "Primary" else 1)
            d = vals[0].get("cvssData", {})
            score = d.get("baseScore")
            vector = d.get("vectorString")
            version = label
            break
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val = desc.get("value")
            if val and val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    refs = cve.get("references") or []
    public_exploit = any(any(str(t).lower() == "exploit" for t in (r.get("tags") or [])) for r in refs)
    traits = parse_vector(vector)
    return {
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
        "cvssScore": score,
        "cvssVector": vector,
        "cvssVersion": version,
        "cwes": cwes,
        "nvdPublished": cve.get("published"),
        "nvdLastModified": cve.get("lastModified"),
        "publicExploit": public_exploit,
        **traits,
    }


def cache_stale(entry):
    if not entry or not entry.get("fetchedAt"):
        return True
    try:
        fetched = datetime.fromisoformat(entry["fetchedAt"].replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - fetched).days >= CACHE_MAX_AGE_DAYS
    except Exception:
        return True


def fetch_nvd(cve):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    return parse_nvd(fetch_json(f"{NVD_URL}?{urllib.parse.urlencode({'cveId': cve})}", headers=headers))


def fetch_epss(cves):
    result = {}
    batch = []
    length = 0

    def run(items):
        if not items:
            return
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(items), 'limit': '10000'})}"
        try:
            payload = fetch_json(url)
            for row in payload.get("data") or []:
                result[row.get("cve")] = {
                    "epss": float(row["epss"]) if row.get("epss") else None,
                    "epssPercentile": float(row["percentile"]) if row.get("percentile") else None,
                    "epssDate": row.get("date"),
                }
        except Exception as exc:
            print(f"Warning: EPSS batch failed: {exc}")

    for cve in cves:
        add = len(cve) + (1 if batch else 0)
        if length + add > 1900:
            run(batch)
            batch = []
            length = 0
        batch.append(cve)
        length += add
    run(batch)
    return result


def day_delta(value):
    try:
        return (date.today() - date.fromisoformat((value or "")[:10])).days
    except Exception:
        return 99999


def days_until(value):
    try:
        return (date.fromisoformat((value or "")[:10]) - date.today()).days
    except Exception:
        return 99999


def classify_technology(v):
    text = " ".join(
        [str(v.get("vendorProject", "")), str(v.get("product", "")), str(v.get("vulnerabilityName", ""))]
    ).lower()
    buckets = [
        ("Network Edge / VPN", ["router", "firewall", "vpn", "gateway", "fortios", "netscaler", "connect secure", "sonicwall", "pan-os", "network appliance"]),
        ("Operating Systems", ["windows", "linux", "android", "ios", "macos", "operating system", "kernel"]),
        ("Browsers", ["chrome", "chromium", "firefox", "safari", "edge browser", "webkit"]),
        ("Security Tools", ["antivirus", "endpoint", "security", "edr", "secure access", "siem"]),
        ("Cloud / Virtualization", ["vmware", "vcenter", "esxi", "cloud", "virtual", "hyper-v", "kubernetes"]),
        ("Web Applications / CMS", ["wordpress", "drupal", "joomla", "apache", "nginx", "web server", "confluence"]),
        ("Developer / CI-CD", ["gitlab", "github", "jenkins", "developer", "framework", "library", "build"]),
        ("OT / ICS", ["scada", "industrial", "plc", "ics", "hmi"]),
        ("Email / Collaboration", ["exchange", "outlook", "mail", "teams", "collaboration"]),
        ("Identity / Access", ["identity", "authentication", "active directory", "sso", "access management"]),
        ("Storage / Backup", ["backup", "storage", "nas", "san"]),
        ("Enterprise Software", ["office", "sharepoint", "sap", "oracle", "citrix", "server"]),
    ]
    for name, terms in buckets:
        if any(term in text for term in terms):
            return name
    return "Other"


def threat_signal(v):
    score = 35
    factors = ["Confirmed active exploitation (CISA KEV) +35"]
    cvss = v.get("cvssScore")
    if isinstance(cvss, (int, float)):
        pts = round(float(cvss) / 10 * 20)
        score += pts
        factors.append(f"CVSS {cvss:g} +{pts}")
    ep = v.get("epss")
    if isinstance(ep, (int, float)):
        pts = round(float(ep) * 20)
        score += pts
        factors.append(f"EPSS {ep * 100:.1f}% +{pts}")
    age = day_delta(v.get("dateAdded"))
    pts = 10 if age <= 7 else 7 if age <= 30 else 4 if age <= 90 else 2 if age <= 365 else 0
    score += pts
    if pts:
        factors.append(f"KEV recency +{pts}")
    due = days_until(v.get("dueDate"))
    pts = 5 if due < 0 else 4 if due <= 7 else 2 if due <= 30 else 0
    score += pts
    if pts:
        factors.append(f"Remediation urgency +{pts}")
    if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
        score += 10
        factors.append("Known ransomware use +10")
    return min(100, score), factors


def nearest_snapshot(snaps, target, max_distance_days):
    eligible = []
    for snapshot in snaps:
        try:
            d = date.fromisoformat(snapshot["date"])
            distance = abs((d - target).days)
            if distance <= max_distance_days:
                eligible.append((distance, d, snapshot))
        except Exception:
            pass
    if not eligible:
        return None
    eligible.sort(key=lambda x: (x[0], -x[1].toordinal()))
    return eligible[0][2]


def public_vuln(v):
    """Compact representation for API/RSS outputs."""
    return {
        "cveID": v.get("cveID"),
        "vendorProject": v.get("vendorProject"),
        "product": v.get("product"),
        "technology": v.get("technology"),
        "vulnerabilityName": v.get("vulnerabilityName"),
        "dateAdded": v.get("dateAdded"),
        "dueDate": v.get("dueDate"),
        "threatSignal": v.get("threatSignal"),
        "movement24h": v.get("movement24h", 0),
        "movement7d": v.get("movement7d", 0),
        "cvssScore": v.get("cvssScore"),
        "epss": v.get("epss"),
        "epssPercentile": v.get("epssPercentile"),
        "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
        "networkExploitable": bool(v.get("networkExploitable")),
        "publicExploit": bool(v.get("publicExploit")),
        "noPrivilegesRequired": bool(v.get("noPrivilegesRequired")),
        "shortDescription": v.get("shortDescription"),
        "url": f"{SITE_URL}?cve={urllib.parse.quote(v.get('cveID', ''))}",
    }


def rss_document(title, description, items, generated_at):
    rows = []
    for item in items:
        cve = item.get("cveID", "")
        vendor = item.get("vendorProject") or "Unknown vendor"
        product = item.get("product") or ""
        link = item.get("url") or SITE_URL
        signal = item.get("threatSignal")
        summary = item.get("shortDescription") or item.get("description") or ""
        pub = item.get("dateAdded") or date.today().isoformat()
        try:
            pubdate = datetime.fromisoformat(pub[:10]).replace(tzinfo=timezone.utc).strftime("%a, %d %b %Y 00:00:00 +0000")
        except Exception:
            pubdate = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        rows.append(
            "<item>"
            f"<title>{html.escape(cve)} — {html.escape(vendor)} {html.escape(product)}</title>"
            f"<link>{html.escape(link)}</link>"
            f"<guid isPermaLink=\"true\">{html.escape(link)}</guid>"
            f"<pubDate>{pubdate}</pubDate>"
            f"<description>{html.escape(f'Threat Signal {signal}. {summary}'.strip())}</description>"
            "</item>"
        )
    build_date = datetime.fromisoformat(generated_at.replace("Z", "+00:00")).strftime("%a, %d %b %Y %H:%M:%S +0000")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0"><channel>'
        f"<title>{html.escape(title)}</title>"
        f"<link>{html.escape(SITE_URL)}</link>"
        f"<description>{html.escape(description)}</description>"
        f"<lastBuildDate>{build_date}</lastBuildDate>"
        + "".join(rows)
        + "</channel></rss>\n"
    )


def build_phase3_outputs(output, snaps, generated_at, snap24, snap7):
    # New since the most recent prior daily snapshot. If history is brand new,
    # this gracefully becomes entries added today.
    prior = None
    previous = [s for s in snaps if s.get("date") != date.today().isoformat()]
    if previous:
        prior = sorted(previous, key=lambda s: s.get("date", ""))[-1]
    prior_ranks = (prior or {}).get("ranks", {})
    if prior_ranks:
        new_since = [v for v in output if v.get("cveID") not in prior_ranks]
        since_date = prior.get("date")
    else:
        new_since = [v for v in output if day_delta(v.get("dateAdded")) <= 0]
        since_date = (date.today() - timedelta(days=1)).isoformat()
    new_since.sort(key=lambda v: (v.get("threatSignal", 0), v.get("dateAdded", "")), reverse=True)

    movers24 = sorted(
        [v for v in output if (v.get("movement24h") or 0) > 0],
        key=lambda v: (v.get("movement24h", 0), v.get("threatSignal", 0)),
        reverse=True,
    )[:50]
    movers7 = sorted(
        [v for v in output if (v.get("movement7d") or 0) > 0],
        key=lambda v: (v.get("movement7d", 0), v.get("threatSignal", 0)),
        reverse=True,
    )[:50]
    newest = sorted(output, key=lambda v: v.get("dateAdded", ""), reverse=True)[:50]

    write_json(
        DATA_DIR / "latest-movers.json",
        {
            "generatedAt": generated_at,
            "has24hBaseline": bool(snap24),
            "has7dBaseline": bool(snap7),
            "movers24h": [public_vuln(v) for v in movers24],
            "movers7d": [public_vuln(v) for v in movers7],
            "newest": [public_vuln(v) for v in newest],
        },
    )
    write_json(
        DATA_DIR / "new-since-yesterday.json",
        {
            "generatedAt": generated_at,
            "since": since_date,
            "count": len(new_since),
            "vulnerabilities": [public_vuln(v) for v in new_since],
        },
    )

    by_vendor = defaultdict(list)
    for v in output:
        by_vendor[v.get("vendorProject") or "Unknown"].append(v)
    vendor_rows = []
    for vendor, rows in by_vendor.items():
        rows_sorted = sorted(rows, key=lambda v: v.get("threatSignal", 0), reverse=True)
        tech = Counter(v.get("technology") or "Other" for v in rows)
        vendor_rows.append(
            {
                "vendor": vendor,
                "activeKEVs": len(rows),
                "ransomwareLinked": sum(1 for v in rows if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"),
                "networkExploitable": sum(1 for v in rows if v.get("networkExploitable")),
                "newSinceYesterday": sum(1 for v in rows if v in new_since),
                "new7d": sum(1 for v in rows if day_delta(v.get("dateAdded")) <= 7),
                "averageThreatSignal": round(sum(v.get("threatSignal", 0) for v in rows) / len(rows)),
                "topTechnologies": [{"technology": name, "count": count} for name, count in tech.most_common(5)],
                "topVulnerabilities": [public_vuln(v) for v in rows_sorted[:10]],
                "url": f"{SITE_URL}?vendor={urllib.parse.quote(vendor)}&panel=vendor",
            }
        )
    vendor_rows.sort(key=lambda x: (x["activeKEVs"], x["averageThreatSignal"]), reverse=True)
    write_json(DATA_DIR / "vendors.json", {"generatedAt": generated_at, "vendors": vendor_rows})

    week = [v for v in output if day_delta(v.get("dateAdded")) <= 7]
    week_ransom = [v for v in week if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"]
    tech_counts = Counter(v.get("technology") or "Other" for v in week)
    vendor_counts = Counter(v.get("vendorProject") or "Unknown" for v in week)
    top_movers = movers7[:10]
    highest = sorted(week or output, key=lambda v: v.get("threatSignal", 0), reverse=True)[:10]

    observations = []
    if week:
        observations.append(f"CISA added {len(week)} actively exploited vulnerabilities during the last 7 days.")
    if week_ransom:
        observations.append(f"{len(week_ransom)} of this week's additions are associated with known ransomware campaigns.")
    if tech_counts:
        t, count = tech_counts.most_common(1)[0]
        observations.append(f"{t} is the most represented technology category among this week's new KEVs ({count}).")
    if vendor_counts:
        vname, count = vendor_counts.most_common(1)[0]
        observations.append(f"{vname} has the most new KEV entries this week ({count}).")
    if top_movers:
        observations.append(f"{top_movers[0].get('cveID')} is the largest 7-day rank riser, up {top_movers[0].get('movement7d')} positions.")
    else:
        observations.append("Seven-day rank movers will appear after a full week of daily snapshots has accumulated.")

    weekly = {
        "generatedAt": generated_at,
        "periodStart": (date.today() - timedelta(days=6)).isoformat(),
        "periodEnd": date.today().isoformat(),
        "newKEVs": len(week),
        "ransomwareLinkedNewKEVs": len(week_ransom),
        "topVendors": [{"vendor": name, "count": count} for name, count in vendor_counts.most_common(10)],
        "topTechnologies": [{"technology": name, "count": count} for name, count in tech_counts.most_common(10)],
        "topMovers": [public_vuln(v) for v in top_movers],
        "highestSignals": [public_vuln(v) for v in highest],
        "observations": observations,
        "executiveSummary": " ".join(observations[:4]),
    }
    write_json(DATA_DIR / "weekly-summary.json", weekly)

    write_json(
        DATA_DIR / "api-index.json",
        {
            "name": "Cyber Threat Wall public data endpoints",
            "generatedAt": generated_at,
            "endpoints": {
                "fullThreatWall": "data/threat-wall.json",
                "latestMovers": "data/latest-movers.json",
                "newSinceYesterday": "data/new-since-yesterday.json",
                "vendors": "data/vendors.json",
                "weeklySummary": "data/weekly-summary.json",
                "history": "data/history.json",
                "rssLatestMovers": "feed/latest-movers.xml",
                "rssNewKEVs": "feed/new-kevs.xml",
                "rssWeeklySummary": "feed/weekly-summary.xml",
            },
        },
    )

    FEED_DIR.joinpath("latest-movers.xml").write_text(
        rss_document(
            "Cyber Threat Wall — Latest Movers",
            "Actively exploited vulnerabilities rising fastest in Cyber Threat Wall rankings.",
            [public_vuln(v) for v in (movers24 or movers7 or newest[:20])],
            generated_at,
        ),
        encoding="utf-8",
    )
    FEED_DIR.joinpath("new-kevs.xml").write_text(
        rss_document(
            "Cyber Threat Wall — New KEVs",
            "Vulnerabilities newly appearing in CISA's Known Exploited Vulnerabilities catalog.",
            [public_vuln(v) for v in new_since[:50]],
            generated_at,
        ),
        encoding="utf-8",
    )
    weekly_item = {
        "cveID": f"Weekly Threat Summary — {weekly['periodEnd']}",
        "vendorProject": "Cyber Threat Wall",
        "product": "Weekly intelligence brief",
        "threatSignal": "—",
        "shortDescription": weekly["executiveSummary"],
        "dateAdded": weekly["periodEnd"],
        "url": SITE_URL + "?panel=weekly",
    }
    FEED_DIR.joinpath("weekly-summary.xml").write_text(
        rss_document(
            "Cyber Threat Wall — Weekly Threat Summary",
            "Weekly summary of new KEVs, ransomware activity, technology pressure and rank movement.",
            [weekly_item],
            generated_at,
        ),
        encoding="utf-8",
    )


def main():
    print("Fetching CISA KEV...")
    kev = fetch_json(KEV_URL)
    vulns = kev.get("vulnerabilities") or []
    cache = read_json(CACHE_FILE, {})

    ordered = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    candidates = [v["cveID"] for v in ordered if cache_stale(cache.get(v["cveID"]))]
    attempts = 0
    for cve in candidates[:MAX_NVD_REQUESTS]:
        try:
            print(f"NVD {cve}")
            cache[cve] = fetch_nvd(cve)
            attempts += 1
            write_json(CACHE_FILE, cache)
            if REQUEST_DELAY:
                time.sleep(REQUEST_DELAY)
        except urllib.error.HTTPError as exc:
            print(f"Warning: NVD HTTP {exc.code} for {cve}")
            if exc.code in (403, 429):
                break
        except Exception as exc:
            print(f"Warning: NVD error for {cve}: {exc}")

    print("Fetching FIRST EPSS...")
    epss = fetch_epss([v["cveID"] for v in vulns])
    output = []
    for item in vulns:
        merged = dict(item)
        enrich = cache.get(item.get("cveID"), {})
        ep = epss.get(item.get("cveID"), {})
        merged.update(
            {
                "cvssScore": enrich.get("cvssScore"),
                "cvssVector": enrich.get("cvssVector"),
                "cvssVersion": enrich.get("cvssVersion"),
                "cwes": enrich.get("cwes") or [],
                "nvdPublished": enrich.get("nvdPublished"),
                "nvdLastModified": enrich.get("nvdLastModified"),
                "networkExploitable": bool(enrich.get("networkExploitable")),
                "noPrivilegesRequired": bool(enrich.get("noPrivilegesRequired")),
                "publicExploit": bool(enrich.get("publicExploit")),
                "epss": ep.get("epss"),
                "epssPercentile": ep.get("epssPercentile"),
                "epssDate": ep.get("epssDate"),
            }
        )
        merged["technology"] = classify_technology(merged)
        merged["threatSignal"], merged["signalFactors"] = threat_signal(merged)
        merged["threatScore"] = merged["threatSignal"]
        output.append(merged)

    output.sort(key=lambda x: (x.get("threatSignal", 0), x.get("dateAdded", "")), reverse=True)
    current_ranks = {v["cveID"]: i + 1 for i, v in enumerate(output)}
    current_signals = {v["cveID"]: v["threatSignal"] for v in output}
    today = date.today()

    history = read_json(HISTORY_FILE, {"snapshots": []})
    snaps = history.get("snapshots") or []
    previous = [s for s in snaps if s.get("date") != today.isoformat()]
    snap24 = nearest_snapshot(previous, today - timedelta(days=1), 1)
    snap7 = nearest_snapshot(previous, today - timedelta(days=7), 1)

    for v in output:
        cve = v["cveID"]
        rank = current_ranks[cve]
        r24 = (snap24 or {}).get("ranks", {}).get(cve)
        r7 = (snap7 or {}).get("ranks", {}).get(cve)
        v["movement24h"] = (r24 - rank) if r24 else 0
        v["movement7d"] = (r7 - rank) if r7 else 0
        hist = []
        for snapshot in previous[-29:]:
            r = snapshot.get("ranks", {}).get(cve)
            if r:
                hist.append({"date": snapshot.get("date"), "rank": r, "signal": snapshot.get("signals", {}).get(cve)})
        hist.append({"date": today.isoformat(), "rank": rank, "signal": v["threatSignal"]})
        v["rankHistory"] = hist

    ransomware = sum(1 for v in output if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known")
    new7 = sum(1 for v in output if day_delta(v.get("dateAdded")) <= 7)
    avg = round(sum(v["threatSignal"] for v in output) / max(1, len(output)))
    generated_at = datetime.now(timezone.utc).isoformat()
    today_snap = {
        "date": today.isoformat(),
        "generatedAt": generated_at,
        "total": len(output),
        "ransomware": ransomware,
        "new7": new7,
        "avgSignal": avg,
        "ranks": current_ranks,
        "signals": current_signals,
    }
    snaps = [s for s in snaps if s.get("date") != today.isoformat()] + [today_snap]
    snaps = sorted(snaps, key=lambda s: s.get("date", ""))[-90:]
    write_json(HISTORY_FILE, {"snapshots": snaps})

    history_summary = [{k: s.get(k) for k in ("date", "total", "ransomware", "new7", "avgSignal")} for s in snaps]
    payload = {
        "meta": {
            "title": kev.get("title", "CISA Known Exploited Vulnerabilities"),
            "catalogVersion": kev.get("catalogVersion"),
            "catalogDateReleased": kev.get("dateReleased"),
            "generatedAt": generated_at,
            "kevSource": KEV_URL,
            "nvdSource": NVD_URL,
            "epssSource": EPSS_URL,
            "nvdCachedEntries": len(cache),
            "epssEntries": len(epss),
            "nvdRequestsThisRun": attempts,
            "rankingVersion": "3.0",
            "has24hBaseline": bool(snap24),
            "has7dBaseline": bool(snap7),
        },
        "historySummary": history_summary,
        "vulnerabilities": output,
    }
    write_json(OUT_FILE, payload)
    write_json(CACHE_FILE, cache)
    build_phase3_outputs(output, snaps, generated_at, snap24, snap7)
    print(f"Wrote {len(output)} vulnerabilities; {len(snaps)} daily snapshots; {len(epss)} EPSS scores and Phase 3 feeds.")


if __name__ == "__main__":
    main()
