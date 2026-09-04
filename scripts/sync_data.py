#!/usr/bin/env python3
"""Build Cyber Threat Wall data from CISA KEV, NVD and FIRST EPSS."""
from __future__ import annotations
import json, os, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone, date, timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DATA_DIR=ROOT/"data"; OUT_FILE=DATA_DIR/"threat-wall.json"; CACHE_FILE=DATA_DIR/"nvd-cache.json"; HISTORY_FILE=DATA_DIR/"history.json"
KEV_URL="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL="https://api.first.org/data/v1/epss"
API_KEY=os.getenv("NVD_API_KEY","").strip(); MAX_NVD_REQUESTS=int(os.getenv("MAX_NVD_REQUESTS","40" if not API_KEY else "250")); REQUEST_DELAY=float(os.getenv("NVD_REQUEST_DELAY","6.2" if not API_KEY else "0.75")); CACHE_MAX_AGE_DAYS=int(os.getenv("NVD_CACHE_MAX_AGE_DAYS","30"))
DATA_DIR.mkdir(parents=True,exist_ok=True)

def fetch_json(url,headers=None,timeout=60):
    req=urllib.request.Request(url,headers={"User-Agent":"Cyber-Threat-Wall/2.0 (+GitHub Pages)","Accept":"application/json",**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as r:return json.load(r)

def read_json(path,default):
    if not path.exists():return default
    try:return json.loads(path.read_text(encoding="utf-8"))
    except Exception:return default

def write_json(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=False),encoding="utf-8")

def parse_vector(vector):
    result={"networkExploitable":False,"noPrivilegesRequired":False}
    if not vector:return result
    parts=dict(p.split(":",1) for p in vector.split("/")[1:] if ":" in p)
    result["networkExploitable"]=parts.get("AV")=="N"; result["noPrivilegesRequired"]=parts.get("PR")=="N"; return result

def parse_nvd(payload):
    rows=payload.get("vulnerabilities") or []
    if not rows:return {"fetchedAt":datetime.now(timezone.utc).isoformat(),"cvssScore":None,"cwes":[]}
    cve=rows[0].get("cve",{}); metrics=cve.get("metrics",{}); score=vector=version=None
    for key,label in (("cvssMetricV40","4.0"),("cvssMetricV31","3.1"),("cvssMetricV30","3.0")):
        vals=metrics.get(key) or []
        if vals:
            vals=sorted(vals,key=lambda r:0 if r.get("type")=="Primary" else 1); d=vals[0].get("cvssData",{}); score=d.get("baseScore"); vector=d.get("vectorString"); version=label; break
    cwes=[]
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val=desc.get("value")
            if val and val.startswith("CWE-") and val not in cwes:cwes.append(val)
    refs=cve.get("references") or []; public_exploit=any(any(str(t).lower()=="exploit" for t in (r.get("tags") or [])) for r in refs)
    traits=parse_vector(vector)
    return {"fetchedAt":datetime.now(timezone.utc).isoformat(),"cvssScore":score,"cvssVector":vector,"cvssVersion":version,"cwes":cwes,"nvdPublished":cve.get("published"),"nvdLastModified":cve.get("lastModified"),"publicExploit":public_exploit,**traits}

def cache_stale(entry):
    if not entry or not entry.get("fetchedAt"):return True
    try:return (datetime.now(timezone.utc)-datetime.fromisoformat(entry["fetchedAt"].replace("Z","+00:00"))).days>=CACHE_MAX_AGE_DAYS
    except Exception:return True

def fetch_nvd(cve):
    headers={"apiKey":API_KEY} if API_KEY else {}; return parse_nvd(fetch_json(f"{NVD_URL}?{urllib.parse.urlencode({'cveId':cve})}",headers=headers))

def fetch_epss(cves):
    result={}; batch=[]; length=0
    def run(items):
        if not items:return
        url=f"{EPSS_URL}?{urllib.parse.urlencode({'cve':','.join(items),'limit':'10000'})}"
        try:
            payload=fetch_json(url)
            for row in payload.get("data") or []:
                result[row.get("cve")]={"epss":float(row["epss"]) if row.get("epss") else None,"epssPercentile":float(row["percentile"]) if row.get("percentile") else None,"epssDate":row.get("date")}
        except Exception as e:print(f"Warning: EPSS batch failed: {e}")
    for cve in cves:
        add=len(cve)+(1 if batch else 0)
        if length+add>1900:run(batch); batch=[]; length=0
        batch.append(cve); length+=add
    run(batch); return result

def day_delta(s):
    try:return (date.today()-date.fromisoformat((s or "")[:10])).days
    except Exception:return 99999

def days_until(s):
    try:return (date.fromisoformat((s or "")[:10])-date.today()).days
    except Exception:return 99999

def classify_technology(v):
    text=" ".join([str(v.get("vendorProject","")),str(v.get("product","")),str(v.get("vulnerabilityName",""))]).lower()
    buckets=[("Network / Edge",["router","firewall","vpn","gateway","fortios","netscaler","connect secure","network","sonicwall","pan-os"]),("Operating System",["windows","linux","android","ios","macos","operating system","kernel"]),("Browser",["chrome","chromium","firefox","safari","edge browser","webkit"]),("Security Product",["antivirus","endpoint","security","edr","secure access"]),("Cloud / Virtualization",["vmware","vcenter","esxi","cloud","virtual","hyper-v","kubernetes"]),("Web / CMS",["wordpress","drupal","joomla","apache","nginx","web server","confluence"]),("Development",["gitlab","github","jenkins","developer","framework","library"]),("Industrial / OT",["scada","industrial","plc","ics","hmi"]),("Enterprise Software",["exchange","office","sharepoint","sap","oracle","citrix","server"])]
    for name,terms in buckets:
        if any(t in text for t in terms):return name
    return "Other"

def threat_signal(v):
    score=35; factors=["Confirmed active exploitation (CISA KEV) +35"]
    cvss=v.get("cvssScore")
    if isinstance(cvss,(int,float)):
        pts=round(float(cvss)/10*20); score+=pts; factors.append(f"CVSS {cvss:g} +{pts}")
    ep=v.get("epss")
    if isinstance(ep,(int,float)):
        pts=round(float(ep)*20); score+=pts; factors.append(f"EPSS {ep*100:.1f}% +{pts}")
    age=day_delta(v.get("dateAdded")); pts=10 if age<=7 else 7 if age<=30 else 4 if age<=90 else 2 if age<=365 else 0
    score+=pts
    if pts:factors.append(f"KEV recency +{pts}")
    due=days_until(v.get("dueDate")); pts=5 if due<0 else 4 if due<=7 else 2 if due<=30 else 0; score+=pts
    if pts:factors.append(f"Remediation urgency +{pts}")
    if str(v.get("knownRansomwareCampaignUse","")).lower()=="known":score+=10; factors.append("Known ransomware use +10")
    return min(100,score),factors

def nearest_snapshot(snaps,target):
    eligible=[]
    for s in snaps:
        try:d=date.fromisoformat(s["date"]); eligible.append((abs((d-target).days),d,s))
        except Exception:pass
    if not eligible:return None
    eligible.sort(key=lambda x:(x[0],-x[1].toordinal())); return eligible[0][2]

def main():
    print("Fetching CISA KEV..."); kev=fetch_json(KEV_URL); vulns=kev.get("vulnerabilities") or []; cache=read_json(CACHE_FILE,{})
    ordered=sorted(vulns,key=lambda v:v.get("dateAdded",""),reverse=True); candidates=[v["cveID"] for v in ordered if cache_stale(cache.get(v["cveID"]))]
    attempts=0
    for cve in candidates[:MAX_NVD_REQUESTS]:
        try:
            print(f"NVD {cve}"); cache[cve]=fetch_nvd(cve); attempts+=1; write_json(CACHE_FILE,cache)
            if REQUEST_DELAY:time.sleep(REQUEST_DELAY)
        except urllib.error.HTTPError as e:
            print(f"Warning: NVD HTTP {e.code} for {cve}")
            if e.code in (403,429):break
        except Exception as e:print(f"Warning: NVD error for {cve}: {e}")
    print("Fetching FIRST EPSS..."); epss=fetch_epss([v["cveID"] for v in vulns])
    output=[]
    for item in vulns:
        merged=dict(item); enrich=cache.get(item.get("cveID"),{}); ep=epss.get(item.get("cveID"),{})
        merged.update({"cvssScore":enrich.get("cvssScore"),"cvssVector":enrich.get("cvssVector"),"cvssVersion":enrich.get("cvssVersion"),"cwes":enrich.get("cwes") or [],"nvdPublished":enrich.get("nvdPublished"),"nvdLastModified":enrich.get("nvdLastModified"),"networkExploitable":bool(enrich.get("networkExploitable")),"noPrivilegesRequired":bool(enrich.get("noPrivilegesRequired")),"publicExploit":bool(enrich.get("publicExploit")),"epss":ep.get("epss"),"epssPercentile":ep.get("epssPercentile"),"epssDate":ep.get("epssDate")})
        merged["technology"]=classify_technology(merged); merged["threatSignal"],merged["signalFactors"]=threat_signal(merged); merged["threatScore"]=merged["threatSignal"]; output.append(merged)
    output.sort(key=lambda x:(x.get("threatSignal",0),x.get("dateAdded","")),reverse=True)
    current_ranks={v["cveID"]:i+1 for i,v in enumerate(output)}; current_signals={v["cveID"]:v["threatSignal"] for v in output}; today=date.today()
    history=read_json(HISTORY_FILE,{"snapshots":[]}); snaps=history.get("snapshots") or []; previous=[s for s in snaps if s.get("date")!=today.isoformat()]
    snap24=nearest_snapshot(previous,today-timedelta(days=1)); snap7=nearest_snapshot(previous,today-timedelta(days=7))
    for v in output:
        c=v["cveID"]; rank=current_ranks[c]
        r24=(snap24 or {}).get("ranks",{}).get(c); r7=(snap7 or {}).get("ranks",{}).get(c)
        v["movement24h"]=(r24-rank) if r24 else 0; v["movement7d"]=(r7-rank) if r7 else 0
        hist=[]
        for s in previous[-29:]:
            r=s.get("ranks",{}).get(c)
            if r:hist.append({"date":s.get("date"),"rank":r,"signal":s.get("signals",{}).get(c)})
        hist.append({"date":today.isoformat(),"rank":rank,"signal":v["threatSignal"]}); v["rankHistory"]=hist
    ransomware=sum(1 for v in output if str(v.get("knownRansomwareCampaignUse","")).lower()=="known"); new7=sum(1 for v in output if day_delta(v.get("dateAdded"))<=7); avg=round(sum(v["threatSignal"] for v in output)/max(1,len(output)))
    today_snap={"date":today.isoformat(),"generatedAt":datetime.now(timezone.utc).isoformat(),"total":len(output),"ransomware":ransomware,"new7":new7,"avgSignal":avg,"ranks":current_ranks,"signals":current_signals}
    snaps=[s for s in snaps if s.get("date")!=today.isoformat()]+[today_snap]; snaps=sorted(snaps,key=lambda s:s.get("date",""))[-90:]; write_json(HISTORY_FILE,{"snapshots":snaps})
    history_summary=[{k:s.get(k) for k in ("date","total","ransomware","new7","avgSignal")} for s in snaps]
    payload={"meta":{"title":kev.get("title","CISA Known Exploited Vulnerabilities"),"catalogVersion":kev.get("catalogVersion"),"catalogDateReleased":kev.get("dateReleased"),"generatedAt":datetime.now(timezone.utc).isoformat(),"kevSource":KEV_URL,"nvdSource":NVD_URL,"epssSource":EPSS_URL,"nvdCachedEntries":len(cache),"epssEntries":len(epss),"nvdRequestsThisRun":attempts,"rankingVersion":"2.0"},"historySummary":history_summary,"vulnerabilities":output}
    write_json(OUT_FILE,payload); write_json(CACHE_FILE,cache); print(f"Wrote {len(output)} vulnerabilities; {len(snaps)} daily snapshots; {len(epss)} EPSS scores.")

if __name__=="__main__":main()
