const state = { data: [], filtered: [], meta: {}, history: [], view: "wall", mode: "analyst", movementWindow: "24h" };

const $ = s => document.querySelector(s);
const els = {
  stats: $("#stats"), ticker: $("#ticker"), headlineIntel: $("#headlineIntel"), movers: $("#movers"),
  executiveView: $("#executiveView"), analystView: $("#analystView"), executiveBrief: $("#executiveBrief"),
  vendorLeaders: $("#vendorLeaders"), trendChart: $("#trendChart"), trendCards: $("#trendCards"),
  analystModeBtn: $("#analystModeBtn"), executiveModeBtn: $("#executiveModeBtn"),
  search: $("#search"), vendor: $("#vendorFilter"), technology: $("#technologyFilter"), severity: $("#severityFilter"),
  epss: $("#epssFilter"), age: $("#ageFilter"), ransomware: $("#ransomwareFilter"), exploit: $("#exploitFilter"), due: $("#dueFilter"), sort: $("#sortBy"),
  wall: $("#wall"), tableWrap: $("#tableWrap"), tableBody: $("#tableBody"), count: $("#resultCount"), clear: $("#clearFilters"),
  activeContext: $("#activeContext"), wallBtn: $("#wallViewBtn"), tableBtn: $("#tableViewBtn"), dataStatus: $("#dataStatus"), lastUpdated: $("#lastUpdated"),
  dialog: $("#detailDialog"), detail: $("#detailContent"), closeDialog: $("#closeDialog")
};

function escapeHtml(v="") { return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function daysSince(s){ if(!s)return Infinity; return Math.floor((Date.now()-new Date(`${s}T00:00:00Z`).getTime())/86400000); }
function daysUntil(s){ if(!s)return Infinity; return Math.ceil((new Date(`${s}T23:59:59Z`).getTime()-Date.now())/86400000); }
function fmtDate(v){ if(!v)return "—"; return new Intl.DateTimeFormat("en-US",{year:"numeric",month:"short",day:"numeric",timeZone:"UTC"}).format(new Date(`${v}T00:00:00Z`)); }
function pct(v,digits=0){ return v==null?"—":`${(Number(v)*100).toFixed(digits)}%`; }
function severity(score){ if(score==null)return "unknown"; if(score>=9)return "critical"; if(score>=7)return "high"; if(score>=4)return "medium"; return "low"; }
function ransomwareKnown(v){ return String(v.knownRansomwareCampaignUse||"").toLowerCase()==="known"; }
function dueState(v){ const d=daysUntil(v.dueDate); if(d<0)return "overdue"; if(d<=7)return "soon"; return "open"; }
function signal(v){ return Number(v.threatSignal ?? v.threatScore ?? 0); }
function movement(v,window=state.movementWindow){ return Number(window==="7d" ? (v.movement7d||0) : (v.movement24h||0)); }
function movementLabel(v,window=state.movementWindow){
  if(daysSince(v.dateAdded)<=1) return {text:"NEW",cls:"move-new"};
  const m=movement(v,window); if(m>0)return {text:`▲ ${m}`,cls:"move-up"}; if(m<0)return {text:`▼ ${Math.abs(m)}`,cls:"move-down"}; return {text:"●",cls:"move-flat"};
}
function tileLevel(v){ const s=signal(v); if(s>=85)return "level-critical"; if(s>=70)return "level-high"; if(s>=55)return "level-elevated"; return "level-watch"; }
function tileSize(v,index){ const s=signal(v); if(index<6&&s>=85)return "s4"; if(index<24&&s>=72)return "s3"; if(index<100&&s>=58)return "s2"; return "s1"; }

async function loadData(){
  try{
    const res=await fetch("data/threat-wall.json",{cache:"no-store"}); if(!res.ok)throw new Error(`HTTP ${res.status}`);
    const payload=await res.json(); state.data=payload.vulnerabilities||[]; state.meta=payload.meta||{}; state.history=payload.historySummary||[];
    els.dataStatus.textContent=`${state.data.length.toLocaleString()} active KEVs loaded`;
    if(state.meta.generatedAt) els.lastUpdated.textContent=`Updated ${new Intl.DateTimeFormat("en-US",{dateStyle:"medium",timeStyle:"short"}).format(new Date(state.meta.generatedAt))}`;
    populateFilters(); renderStats(); renderTicker(); renderHeadlineIntel(); renderMovers(); renderExecutive(); renderTrends(); applyUrlState(); applyFilters();
  }catch(err){ els.dataStatus.textContent="Data unavailable"; els.wall.innerHTML=`<div class="empty-state">Threat data is not available yet. Run the Update threat data workflow.</div>`; console.error(err); }
}

function populateFilters(){
  const vendors=[...new Set(state.data.map(v=>v.vendorProject).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
  const tech=[...new Set(state.data.map(v=>v.technology).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
  els.vendor.innerHTML=`<option value="">All vendors</option>`+vendors.map(v=>`<option>${escapeHtml(v)}</option>`).join("");
  els.technology.innerHTML=`<option value="">All technology</option>`+tech.map(v=>`<option>${escapeHtml(v)}</option>`).join("");
}

function renderTicker(){
  const new7=state.data.filter(v=>daysSince(v.dateAdded)<=7).length;
  const ransom=state.data.filter(ransomwareKnown).length;
  const highEpss=state.data.filter(v=>(v.epssPercentile||0)>=.9).length;
  const overdue=state.data.filter(v=>dueState(v)==="overdue").length;
  els.ticker.innerHTML=`<div class="ticker-track"><span><b>${state.data.length.toLocaleString()}</b> actively exploited</span><span><b>${new7}</b> new this week</span><span><b>${ransom}</b> ransomware-linked</span><span><b>${highEpss}</b> EPSS 90th percentile+</span><span><b>${overdue}</b> federal deadlines passed</span></div>`;
}

function renderStats(){
  const last30=state.data.filter(v=>daysSince(v.dateAdded)<=30).length;
  const critical=state.data.filter(v=>(v.cvssScore??0)>=9).length;
  const ransomware=state.data.filter(ransomwareKnown).length;
  const highEpss=state.data.filter(v=>(v.epssPercentile||0)>=.9).length;
  const rising=state.data.filter(v=>movement(v,"7d")>0).length;
  const rows=[[state.data.length.toLocaleString(),"Known exploited"],[last30,"Added last 30 days"],[ransomware,"Ransomware-linked"],[highEpss,"EPSS 90th percentile+"],[rising,"Rising in 7 days"]];
  els.stats.innerHTML=rows.map(([value,label])=>`<div class="stat"><div class="value">${value}</div><div class="label">${label}</div></div>`).join("");
}

function vendorCounts(){
  const map=new Map(); state.data.forEach(v=>map.set(v.vendorProject||"Unknown",(map.get(v.vendorProject||"Unknown")||0)+1));
  return [...map.entries()].sort((a,b)=>b[1]-a[1]);
}

function renderHeadlineIntel(){
  const counts=vendorCounts(); const topVendor=counts[0];
  const new7=state.data.filter(v=>daysSince(v.dateAdded)<=7);
  const newRansom=new7.filter(ransomwareKnown).length;
  const topMover=[...state.data].sort((a,b)=>movement(b,"7d")-movement(a,"7d"))[0];
  const insights=[];
  if(topVendor) insights.push(`<strong>${escapeHtml(topVendor[0])}</strong> has ${topVendor[1]} vulnerabilities in the current KEV market.`);
  insights.push(`<strong>${new7.length}</strong> vulnerabilities entered KEV in the last 7 days${newRansom?`, including ${newRansom} linked to ransomware`:""}.`);
  if(topMover&&movement(topMover,"7d")>0) insights.push(`<strong>${escapeHtml(topMover.cveID)}</strong> is the fastest-rising vulnerability, up ${movement(topMover,"7d")} ranks in 7 days.`);
  else insights.push(`Historical rank movement will become visible as daily snapshots accumulate.`);
  els.headlineIntel.innerHTML=insights.map((x,i)=>`<article class="intel-card"><span class="intel-num">0${i+1}</span><p>${x}</p></article>`).join("");
}

function moverCard(v,label){ const mv=movementLabel(v); return `<button class="mover-card" data-cve="${escapeHtml(v.cveID)}"><span class="mover-label">${label}</span><strong>${escapeHtml(v.cveID)}</strong><span>${escapeHtml(v.vendorProject||"")} · ${escapeHtml(v.product||"")}</span><div><b>${signal(v)}</b> Signal <em class="${mv.cls}">${mv.text}</em></div></button>`; }
function renderMovers(){
  const rising=[...state.data].filter(v=>movement(v)>0).sort((a,b)=>movement(b)-movement(a)).slice(0,3);
  const newest=[...state.data].sort((a,b)=>(b.dateAdded||"").localeCompare(a.dateAdded||"")).slice(0,3);
  const ransom=[...state.data].filter(ransomwareKnown).sort((a,b)=>signal(b)-signal(a)).slice(0,3);
  const due=[...state.data].sort((a,b)=>(a.dueDate||"9999").localeCompare(b.dueDate||"9999")).slice(0,3);
  const groups=[...[rising.length?rising:newest].map(v=>moverCard(v,"Fastest Rising")),...newest.map(v=>moverCard(v,"Newest Threat")),...ransom.map(v=>moverCard(v,"Ransomware Watch")),...due.map(v=>moverCard(v,"Remediation Pressure"))];
  els.movers.innerHTML=groups.join("");
  els.movers.querySelectorAll("[data-cve]").forEach(b=>b.addEventListener("click",()=>openByCve(b.dataset.cve)));
}

function renderExecutive(){
  const new7=state.data.filter(v=>daysSince(v.dateAdded)<=7); const newRansom=new7.filter(ransomwareKnown); const network=state.data.filter(v=>v.networkExploitable).length;
  const top5=[...state.data].sort((a,b)=>signal(b)-signal(a)).slice(0,5);
  els.executiveBrief.innerHTML=`
    <article class="brief-card"><span class="brief-kicker">This week</span><strong>${new7.length}</strong><p>new actively exploited vulnerabilities entered CISA KEV.</p></article>
    <article class="brief-card"><span class="brief-kicker">Ransomware</span><strong>${newRansom.length}</strong><p>new additions are associated with known ransomware campaigns.</p></article>
    <article class="brief-card"><span class="brief-kicker">Remote exposure</span><strong>${network}</strong><p>current KEVs have a network attack vector where NVD data is available.</p></article>
    <article class="brief-card wide"><span class="brief-kicker">Highest signals</span><ol>${top5.map(v=>`<li><button data-cve="${escapeHtml(v.cveID)}">${escapeHtml(v.cveID)} <span>${escapeHtml(v.vendorProject||"")}</span><b>${signal(v)}</b></button></li>`).join("")}</ol></article>`;
  els.executiveBrief.querySelectorAll("[data-cve]").forEach(b=>b.addEventListener("click",()=>openByCve(b.dataset.cve)));
  const vendors=vendorCounts().slice(0,8); const max=vendors[0]?.[1]||1;
  els.vendorLeaders.innerHTML=vendors.map(([vendor,count])=>`<button class="bar-row" data-vendor="${escapeHtml(vendor)}"><span>${escapeHtml(vendor)}</span><i><u style="width:${count/max*100}%"></u></i><b>${count}</b></button>`).join("");
  els.vendorLeaders.querySelectorAll("[data-vendor]").forEach(b=>b.addEventListener("click",()=>showVendor(b.dataset.vendor)));
  renderTrendChart();
}

function renderTrendChart(){
  const h=state.history.slice(-30); if(h.length<2){ els.trendChart.innerHTML=`<div class="chart-placeholder">Daily history starts now. Trend lines appear after multiple snapshots.</div>`; return; }
  const vals=h.map(x=>x.total||0), max=Math.max(...vals), min=Math.min(...vals); const w=600,hgt=180;
  const pts=vals.map((v,i)=>`${(i/(vals.length-1))*w},${hgt-((v-min)/(Math.max(1,max-min)))*(hgt-30)-15}`).join(" ");
  els.trendChart.innerHTML=`<svg viewBox="0 0 ${w} ${hgt}" class="spark-chart" role="img" aria-label="Known exploited vulnerability count over time"><polyline points="${pts}" fill="none" vector-effect="non-scaling-stroke"/><text x="0" y="172">${escapeHtml(h[0].date)}</text><text x="600" y="172" text-anchor="end">${escapeHtml(h[h.length-1].date)}</text></svg>`;
}

function renderTrends(){
  const h=state.history.slice(-30); const latest=h[h.length-1]; const prior=h[h.length-2];
  const delta=latest&&prior?(latest.total-prior.total):0;
  const cards=[
    [latest?.total??state.data.length,"Active KEVs",delta?`${delta>0?"+":""}${delta} vs previous snapshot`:"Snapshot baseline"],
    [latest?.ransomware??state.data.filter(ransomwareKnown).length,"Ransomware-linked","Current catalog"],
    [latest?.new7??state.data.filter(v=>daysSince(v.dateAdded)<=7).length,"New in 7 days","Rolling window"],
    [latest?.avgSignal??Math.round(state.data.reduce((a,v)=>a+signal(v),0)/Math.max(1,state.data.length)),"Average Threat Signal","Across current KEV market"]
  ];
  els.trendCards.innerHTML=cards.map(([v,l,s])=>`<article class="trend-card"><strong>${v}</strong><span>${l}</span><small>${s}</small></article>`).join("");
}

function applyFilters(){
  const q=els.search.value.trim().toLowerCase(), vendor=els.vendor.value, tech=els.technology.value, sev=els.severity.value, epss=Number(els.epss.value||0)/100, age=Number(els.age.value||0), ransom=els.ransomware.value, exploit=els.exploit.value, due=els.due.value;
  state.filtered=state.data.filter(v=>{
    const hay=[v.cveID,v.vendorProject,v.product,v.vulnerabilityName,v.shortDescription,v.technology,...(v.cwes||[])].join(" ").toLowerCase();
    if(q&&!hay.includes(q))return false; if(vendor&&v.vendorProject!==vendor)return false; if(tech&&v.technology!==tech)return false; if(sev&&severity(v.cvssScore)!==sev)return false;
    if(epss&&(v.epssPercentile??0)<epss)return false; if(age&&daysSince(v.dateAdded)>age)return false; if(ransom==="known"&&!ransomwareKnown(v))return false; if(ransom==="unknown"&&ransomwareKnown(v))return false;
    if(exploit==="remote"&&!v.networkExploitable)return false; if(exploit==="public"&&!v.publicExploit)return false; if(exploit==="noauth"&&!v.noPrivilegesRequired)return false; if(due&&dueState(v)!==due)return false; return true;
  });
  const sort=els.sort.value; state.filtered.sort((a,b)=>{
    if(sort==="rising")return movement(b)-movement(a)||signal(b)-signal(a); if(sort==="newest")return (b.dateAdded||"").localeCompare(a.dateAdded||""); if(sort==="epss")return (b.epss??-1)-(a.epss??-1); if(sort==="cvss")return (b.cvssScore??-1)-(a.cvssScore??-1); if(sort==="due")return (a.dueDate||"9999").localeCompare(b.dueDate||"9999"); if(sort==="vendor")return (a.vendorProject||"").localeCompare(b.vendorProject||""); return signal(b)-signal(a)||(b.dateAdded||"").localeCompare(a.dateAdded||"");
  });
  els.count.textContent=state.filtered.length.toLocaleString(); els.activeContext.textContent=vendor?`· Vendor view: ${vendor}`:""; renderWall(); renderTable();
}

function tile(v,index){
  const mv=movementLabel(v), cvss=v.cvssScore==null?"—":Number(v.cvssScore).toFixed(1), epss=v.epss==null?"—":pct(v.epss,0);
  const flags=[`<span class="badge">CVSS ${cvss}</span>`,v.epss!=null?`<span class="badge">EPSS ${epss}</span>`:"",ransomwareKnown(v)?`<span class="badge ransomware">RANSOMWARE</span>`:"",daysSince(v.dateAdded)<=3?`<span class="badge new-badge">NEW</span>`:"",dueState(v)==="overdue"?`<span class="badge">DUE</span>`:""].join("");
  return `<article class="tile ${tileLevel(v)} ${tileSize(v,index)} ${ransomwareKnown(v)?"ransomware-tile":""} ${daysSince(v.dateAdded)<=3?"new-tile":""}" data-index="${index}" tabindex="0"><div class="rank">#${index+1}</div><div class="cve">${escapeHtml(v.cveID)}</div><button class="vendor vendor-link" data-vendor="${escapeHtml(v.vendorProject||"")}">${escapeHtml(v.vendorProject||"Unknown vendor")}</button><div class="product">${escapeHtml(v.product||"")}</div><div class="score-row"><div class="threat-score">${signal(v)}</div><div class="score-label">Threat<br>Signal</div><span class="movement ${mv.cls}">${mv.text}</span></div><div class="badges">${flags}</div></article>`;
}
function renderWall(){
  els.wall.innerHTML=state.filtered.map(tile).join("");
  els.wall.querySelectorAll(".tile").forEach(el=>{ const open=e=>{ if(e?.target?.closest(".vendor-link"))return; showDetail(state.filtered[Number(el.dataset.index)],Number(el.dataset.index)+1); }; el.addEventListener("click",open); el.addEventListener("keydown",e=>{if(e.key==="Enter")open(e);}); });
  els.wall.querySelectorAll("[data-vendor]").forEach(b=>b.addEventListener("click",e=>{e.stopPropagation();showVendor(b.dataset.vendor);}));
}
function renderTable(){
  els.tableBody.innerHTML=state.filtered.map((v,i)=>{const mv=movementLabel(v);return `<tr data-index="${i}"><td>#${i+1}</td><td><strong>${escapeHtml(v.cveID)}</strong></td><td><strong>${signal(v)}</strong></td><td><span class="${mv.cls}">${mv.text}</span></td><td>${v.cvssScore==null?"—":Number(v.cvssScore).toFixed(1)}</td><td>${v.epss==null?"—":pct(v.epss,1)}</td><td>${escapeHtml(v.vendorProject||"")} / ${escapeHtml(v.product||"")}</td><td>${fmtDate(v.dateAdded)}</td><td>${ransomwareKnown(v)?"Known":"—"}</td></tr>`;}).join("");
  els.tableBody.querySelectorAll("tr").forEach(tr=>tr.addEventListener("click",()=>showDetail(state.filtered[Number(tr.dataset.index)],Number(tr.dataset.index)+1)));
}

function showVendor(vendor){ els.vendor.value=vendor; setMode("analyst"); updateUrl({vendor,cve:null}); applyFilters(); window.scrollTo({top:document.querySelector(".controls").offsetTop-20,behavior:"smooth"}); }
function openByCve(cve){ const v=state.data.find(x=>x.cveID===cve); if(v)showDetail(v,state.data.indexOf(v)+1); }
function showDetail(v,rank){
  const mv24=movementLabel(v,"24h"),mv7=movementLabel(v,"7d"), nvd=`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cveID)}`, cisa=`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`;
  els.detail.innerHTML=`<div class="detail"><div class="eyebrow">Threat rank #${rank}</div><h2>${escapeHtml(v.cveID)}</h2><div class="muted">${escapeHtml(v.vulnerabilityName||"")}</div>
  <div class="detail-grid"><div class="detail-stat"><strong>${signal(v)}</strong><span>Threat Signal</span></div><div class="detail-stat"><strong>${v.cvssScore==null?"—":Number(v.cvssScore).toFixed(1)}</strong><span>CVSS</span></div><div class="detail-stat"><strong>${v.epss==null?"—":pct(v.epss,1)}</strong><span>EPSS probability</span></div><div class="detail-stat"><strong class="${mv7.cls}">${mv7.text}</strong><span>7-day rank move</span></div></div>
  <div class="signal-breakdown"><h3>Why this signal is elevated</h3><div>${(v.signalFactors||[]).map(x=>`<span class="factor">${escapeHtml(x)}</span>`).join("")||"<span class='muted'>Signal factors will expand as enrichment completes.</span>"}</div></div>
  <h3>Affected product</h3><p><button class="inline-vendor" data-vendor="${escapeHtml(v.vendorProject||"")}">${escapeHtml(v.vendorProject||"Unknown vendor")}</button> — ${escapeHtml(v.product||"Unknown product")} <span class="muted">· ${escapeHtml(v.technology||"Other")}</span></p>
  <h3>Why it matters</h3><p>CISA lists this vulnerability in its Known Exploited Vulnerabilities catalog, meaning there is evidence of active exploitation. ${v.epss!=null?`FIRST EPSS currently estimates a ${pct(v.epss,1)} probability of exploitation activity in its prediction window. `:""}${ransomwareKnown(v)?"CISA also reports known use in ransomware campaigns. ":""}${v.networkExploitable?"NVD scoring indicates a network attack vector. ":""}</p>
  <h3>Description</h3><p>${escapeHtml(v.shortDescription||"No description available.")}</p><h3>Required action</h3><p>${escapeHtml(v.requiredAction||"See CISA guidance.")}</p>
  <h3>Timing</h3><p>Added to KEV: <strong>${fmtDate(v.dateAdded)}</strong><br>Federal remediation due date: <strong>${fmtDate(v.dueDate)}</strong><br>24-hour movement: <strong class="${mv24.cls}">${mv24.text}</strong></p>
  ${v.cwes?.length?`<h3>Weaknesses</h3><p>${v.cwes.map(escapeHtml).join(", ")}</p>`:""}
  <div class="detail-links"><a href="${nvd}" target="_blank" rel="noopener">Open in NVD ↗</a><a href="${cisa}" target="_blank" rel="noopener">Open in CISA KEV ↗</a><button id="copyLink">Copy share link</button></div></div>`;
  els.detail.querySelector("[data-vendor]")?.addEventListener("click",()=>{els.dialog.close();showVendor(v.vendorProject);});
  els.detail.querySelector("#copyLink")?.addEventListener("click",async e=>{updateUrl({cve:v.cveID,vendor:null}); await navigator.clipboard?.writeText(location.href); e.target.textContent="Copied";});
  updateUrl({cve:v.cveID,vendor:null},false); els.dialog.showModal();
}

function updateUrl({cve,vendor},push=true){ const u=new URL(location.href); if(cve)u.searchParams.set("cve",cve); else u.searchParams.delete("cve"); if(vendor)u.searchParams.set("vendor",vendor); else u.searchParams.delete("vendor"); history[push?"pushState":"replaceState"]({},"",u); }
function applyUrlState(){ const p=new URLSearchParams(location.search); const vendor=p.get("vendor"),cve=p.get("cve"); if(vendor&&[...els.vendor.options].some(o=>o.value===vendor))els.vendor.value=vendor; if(cve)setTimeout(()=>openByCve(cve),0); }
function setView(view){ state.view=view; const wall=view==="wall"; els.wall.classList.toggle("hidden",!wall); els.tableWrap.classList.toggle("hidden",wall); els.wallBtn.classList.toggle("active",wall); els.tableBtn.classList.toggle("active",!wall); }
function setMode(mode){ state.mode=mode; const analyst=mode==="analyst"; els.analystView.classList.toggle("hidden",!analyst); els.executiveView.classList.toggle("hidden",analyst); els.analystModeBtn.classList.toggle("active",analyst); els.executiveModeBtn.classList.toggle("active",!analyst); }

[els.search,els.vendor,els.technology,els.severity,els.epss,els.age,els.ransomware,els.exploit,els.due,els.sort].forEach(el=>el.addEventListener(el.tagName==="INPUT"?"input":"change",()=>{ if(el===els.vendor)updateUrl({vendor:els.vendor.value||null,cve:null},false); applyFilters(); }));
els.clear.addEventListener("click",()=>{ [els.search,els.vendor,els.technology,els.severity,els.epss,els.age,els.ransomware,els.exploit,els.due].forEach(x=>x.value=""); els.sort.value="signal"; updateUrl({vendor:null,cve:null},false); applyFilters(); });
els.wallBtn.addEventListener("click",()=>setView("wall")); els.tableBtn.addEventListener("click",()=>setView("table"));
els.analystModeBtn.addEventListener("click",()=>setMode("analyst")); els.executiveModeBtn.addEventListener("click",()=>setMode("executive"));
document.querySelectorAll(".timeframe button").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".timeframe button").forEach(x=>x.classList.remove("active"));b.classList.add("active");state.movementWindow=b.dataset.window;renderMovers();applyFilters();}));
els.closeDialog.addEventListener("click",()=>{els.dialog.close();updateUrl({vendor:els.vendor.value||null,cve:null},false);}); els.dialog.addEventListener("click",e=>{if(e.target===els.dialog){els.dialog.close();updateUrl({vendor:els.vendor.value||null,cve:null},false);}});
window.addEventListener("popstate",()=>location.reload());
loadData();
