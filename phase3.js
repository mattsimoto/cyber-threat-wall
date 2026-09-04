(() => {
  const p3 = {
    data: [],
    vendors: [],
    weekly: null,
    newSince: new Set(),
    newSinceDate: null,
    newMode: false,
    ready: false,
  };

  const q = (s, root = document) => root.querySelector(s);
  const qa = (s, root = document) => [...root.querySelectorAll(s)];
  const esc = (v = "") => String(v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const signalOf = v => Number(v?.threatSignal ?? v?.threatScore ?? 0);
  const ransomware = v => String(v?.knownRansomwareCampaignUse || "").toLowerCase() === "known";
  const daysSinceP3 = value => {
    if (!value) return Infinity;
    return Math.floor((Date.now() - new Date(`${value}T00:00:00Z`).getTime()) / 86400000);
  };

  function injectUI() {
    if (q("#phase3Toolbar")) return;
    const headline = q("#headlineIntel");
    const toolbar = document.createElement("section");
    toolbar.id = "phase3Toolbar";
    toolbar.className = "phase3-toolbar";
    toolbar.innerHTML = `
      <div class="phase3-primary-actions">
        <button id="newSinceBtn" class="p3-action" type="button"><span class="p3-dot"></span> New since yesterday <b id="newSinceCount">0</b></button>
        <button id="exportCsvBtn" class="p3-action" type="button">Export CSV</button>
        <button id="copyLinkBtn" class="p3-action" type="button">Copy share link</button>
        <button id="weeklyBriefBtn" class="p3-action" type="button">Weekly threat summary</button>
      </div>
      <div class="phase3-data-links" aria-label="Machine-readable feeds">
        <span>Feeds</span>
        <a href="data/api-index.json" target="_blank" rel="noopener">API index</a>
        <a href="data/latest-movers.json" target="_blank" rel="noopener">Movers JSON</a>
        <a href="feed/latest-movers.xml" target="_blank" rel="noopener">Movers RSS</a>
        <a href="feed/new-kevs.xml" target="_blank" rel="noopener">New KEVs RSS</a>
      </div>`;
    headline?.insertAdjacentElement("afterend", toolbar);

    const analyst = q("#analystView");
    const vendorPage = document.createElement("section");
    vendorPage.id = "vendorPage";
    vendorPage.className = "vendor-page hidden";
    analyst?.insertAdjacentElement("beforebegin", vendorPage);

    const methodology = q(".methodology");
    const weekly = document.createElement("section");
    weekly.id = "weeklySummaryPanel";
    weekly.className = "section-block weekly-summary-panel";
    weekly.innerHTML = `<div class="section-heading"><div><span class="eyebrow">7-Day Intelligence</span><h2>Weekly Threat Summary</h2></div><div class="weekly-actions"><button id="copyWeeklyBtn" class="p3-action" type="button">Copy summary</button><a class="p3-action linkish" href="data/weekly-summary.json" target="_blank" rel="noopener">JSON</a><a class="p3-action linkish" href="feed/weekly-summary.xml" target="_blank" rel="noopener">RSS</a></div></div><div id="weeklySummaryContent" class="weekly-summary-content"><div class="chart-placeholder">Loading weekly intelligence…</div></div>`;
    methodology?.insertAdjacentElement("beforebegin", weekly);

    const executive = q("#executiveView");
    if (executive && !q("#executivePhase3", executive)) {
      executive.insertAdjacentHTML("beforeend", `<section id="executivePhase3" class="executive-phase3"><div class="intel-two-col"><section class="panel"><h3>Technology Pressure</h3><div id="executiveTech"></div></section><section class="panel"><h3>Weekly Intelligence</h3><div id="executiveWeekly"></div></section></div></section>`);
    }
  }

  async function loadPhase3Data() {
    const safe = async path => {
      try {
        const r = await fetch(path, {cache: "no-store"});
        return r.ok ? await r.json() : null;
      } catch (_) { return null; }
    };
    const [threat, vendorData, weekly, newData] = await Promise.all([
      safe("data/threat-wall.json"),
      safe("data/vendors.json"),
      safe("data/weekly-summary.json"),
      safe("data/new-since-yesterday.json"),
    ]);
    p3.data = threat?.vulnerabilities || (typeof state !== "undefined" ? state.data : []) || [];
    p3.vendors = vendorData?.vendors || [];
    p3.weekly = weekly;
    p3.newSince = new Set((newData?.vulnerabilities || []).map(v => v.cveID));
    p3.newSinceDate = newData?.since || null;
    if (!p3.newSince.size) {
      p3.data.filter(v => daysSinceP3(v.dateAdded) <= 0).forEach(v => p3.newSince.add(v.cveID));
    }
  }

  function currentRows() {
    let rows = (typeof state !== "undefined" && Array.isArray(state.filtered)) ? [...state.filtered] : [...p3.data];
    if (p3.newMode) rows = rows.filter(v => p3.newSince.has(v.cveID));
    return rows;
  }

  function applyNewModeVisual() {
    if (typeof state === "undefined" || !Array.isArray(state.filtered)) return;
    if (p3.newMode) state.filtered = state.filtered.filter(v => p3.newSince.has(v.cveID));
    if (typeof renderWall === "function") renderWall();
    if (typeof renderTable === "function") renderTable();
    const count = q("#resultCount");
    if (count) count.textContent = state.filtered.length.toLocaleString();
    const ctx = q("#activeContext");
    if (ctx && p3.newMode) ctx.textContent = ` · new since ${p3.newSinceDate || "yesterday"}`;
  }

  function rerunAndApply() {
    if (typeof applyFilters === "function") applyFilters();
    applyNewModeVisual();
    renderVendorPage();
    syncUrl();
  }

  function toggleNewMode(force) {
    p3.newMode = typeof force === "boolean" ? force : !p3.newMode;
    const btn = q("#newSinceBtn");
    btn?.classList.toggle("active", p3.newMode);
    if (btn) btn.setAttribute("aria-pressed", String(p3.newMode));
    rerunAndApply();
  }

  function csvCell(value) {
    if (value == null) return "";
    const s = Array.isArray(value) ? value.join("; ") : String(value);
    return `"${s.replaceAll('"', '""')}"`;
  }

  function exportCsv() {
    const rows = currentRows();
    const headers = [
      "rank","cveID","vendorProject","product","technology","threatSignal","movement24h","movement7d","cvssScore","epss","epssPercentile","dateAdded","dueDate","knownRansomwareCampaignUse","networkExploitable","publicExploit","noPrivilegesRequired","cwes","vulnerabilityName","shortDescription"
    ];
    const rankMap = new Map(p3.data.map((v, i) => [v.cveID, i + 1]));
    const body = rows.map(v => headers.map(h => csvCell(h === "rank" ? rankMap.get(v.cveID) : v[h])).join(","));
    const csv = [headers.join(","), ...body].join("\n");
    const blob = new Blob([csv], {type: "text/csv;charset=utf-8"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    const vendor = q("#vendorFilter")?.value;
    const suffix = p3.newMode ? "new-since-yesterday" : vendor ? vendor.toLowerCase().replace(/[^a-z0-9]+/g, "-") : "filtered";
    a.download = `cyber-threat-wall-${suffix}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function filterParamMap() {
    return {
      q: q("#search")?.value || "",
      vendor: q("#vendorFilter")?.value || "",
      technology: q("#technologyFilter")?.value || "",
      severity: q("#severityFilter")?.value || "",
      epss: q("#epssFilter")?.value || "",
      age: q("#ageFilter")?.value || "",
      ransomware: q("#ransomwareFilter")?.value || "",
      exploit: q("#exploitFilter")?.value || "",
      due: q("#dueFilter")?.value || "",
      sort: q("#sortBy")?.value || "signal",
    };
  }

  function syncUrl(extra = {}) {
    const url = new URL(location.href);
    const map = {...filterParamMap(), ...extra};
    for (const [key, value] of Object.entries(map)) {
      if (value && !(key === "sort" && value === "signal")) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    if (p3.newMode) url.searchParams.set("new", "yesterday"); else url.searchParams.delete("new");
    const vendor = q("#vendorFilter")?.value;
    if (vendor) url.searchParams.set("panel", "vendor"); else if (url.searchParams.get("panel") === "vendor") url.searchParams.delete("panel");
    history.replaceState({}, "", url);
  }

  async function copyShareLink() {
    syncUrl();
    try {
      await navigator.clipboard.writeText(location.href);
      flash(q("#copyLinkBtn"), "Copied");
    } catch (_) {
      const input = document.createElement("textarea"); input.value = location.href; document.body.appendChild(input); input.select(); document.execCommand("copy"); input.remove(); flash(q("#copyLinkBtn"), "Copied");
    }
  }

  function flash(el, text) {
    if (!el) return;
    const old = el.textContent; el.textContent = text; el.classList.add("success");
    setTimeout(() => { el.textContent = old; el.classList.remove("success"); }, 1400);
  }

  function restoreUrlState() {
    const params = new URLSearchParams(location.search);
    const ids = {q:"#search",vendor:"#vendorFilter",technology:"#technologyFilter",severity:"#severityFilter",epss:"#epssFilter",age:"#ageFilter",ransomware:"#ransomwareFilter",exploit:"#exploitFilter",due:"#dueFilter",sort:"#sortBy"};
    for (const [key, sel] of Object.entries(ids)) {
      const value = params.get(key);
      const el = q(sel);
      if (value && el) el.value = value;
    }
    if (params.get("new") === "yesterday") p3.newMode = true;
    q("#newSinceBtn")?.classList.toggle("active", p3.newMode);
    if (params.get("panel") === "weekly") setTimeout(() => q("#weeklySummaryPanel")?.scrollIntoView({behavior:"smooth", block:"start"}), 200);
    if (typeof applyFilters === "function") applyFilters();
    applyNewModeVisual();
  }

  function computeVendor(vendor) {
    const existing = p3.vendors.find(v => v.vendor === vendor);
    if (existing) return existing;
    const rows = p3.data.filter(v => v.vendorProject === vendor);
    if (!rows.length) return null;
    const tech = new Map(); rows.forEach(v => tech.set(v.technology || "Other", (tech.get(v.technology || "Other") || 0) + 1));
    return {
      vendor,
      activeKEVs: rows.length,
      ransomwareLinked: rows.filter(ransomware).length,
      networkExploitable: rows.filter(v => v.networkExploitable).length,
      newSinceYesterday: rows.filter(v => p3.newSince.has(v.cveID)).length,
      new7d: rows.filter(v => daysSinceP3(v.dateAdded) <= 7).length,
      averageThreatSignal: Math.round(rows.reduce((a,v)=>a+signalOf(v),0)/rows.length),
      topTechnologies: [...tech.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5).map(([technology,count])=>({technology,count})),
      topVulnerabilities: [...rows].sort((a,b)=>signalOf(b)-signalOf(a)).slice(0,10),
    };
  }

  function renderVendorPage() {
    const panel = q("#vendorPage");
    const vendor = q("#vendorFilter")?.value;
    if (!panel) return;
    if (!vendor) { panel.classList.add("hidden"); panel.innerHTML = ""; return; }
    const info = computeVendor(vendor);
    if (!info) return;
    const rows = p3.data.filter(v => v.vendorProject === vendor).sort((a,b)=>signalOf(b)-signalOf(a));
    const topProducts = [...new Set(rows.map(v=>v.product).filter(Boolean))].slice(0,8);
    panel.classList.remove("hidden");
    panel.innerHTML = `
      <div class="vendor-page-head">
        <div><span class="eyebrow">Vendor Intelligence</span><h2>${esc(vendor)}</h2><p>Current actively exploited vulnerability exposure for ${esc(vendor)} across CISA KEV, enriched with NVD and EPSS.</p></div>
        <div class="vendor-head-actions"><button id="vendorExportBtn" class="p3-action" type="button">Export vendor CSV</button><button id="vendorCloseBtn" class="p3-action" type="button">Clear vendor</button></div>
      </div>
      <div class="vendor-kpis">
        <article><strong>${info.activeKEVs}</strong><span>Active KEVs</span></article>
        <article><strong>${info.averageThreatSignal}</strong><span>Avg. Threat Signal</span></article>
        <article><strong>${info.ransomwareLinked}</strong><span>Ransomware-linked</span></article>
        <article><strong>${info.networkExploitable}</strong><span>Network exploitable</span></article>
        <article><strong>${info.newSinceYesterday}</strong><span>New since yesterday</span></article>
        <article><strong>${info.new7d}</strong><span>New in 7 days</span></article>
      </div>
      <div class="vendor-detail-grid">
        <section class="panel"><h3>Top technology categories</h3>${(info.topTechnologies||[]).map(x=>`<div class="vendor-row"><span>${esc(x.technology)}</span><b>${x.count}</b></div>`).join("") || '<p class="muted">No classifications yet.</p>'}</section>
        <section class="panel"><h3>Products in current KEV set</h3><div class="product-chips">${topProducts.map(p=>`<span>${esc(p)}</span>`).join("") || '<span>Unknown products</span>'}</div></section>
        <section class="panel vendor-top-cves"><h3>Highest Threat Signals</h3>${rows.slice(0,8).map(v=>`<button data-cve="${esc(v.cveID)}"><span>${esc(v.cveID)}</span><small>${esc(v.product||"")}</small><b>${signalOf(v)}</b></button>`).join("")}</section>
      </div>`;
    qa("[data-cve]", panel).forEach(btn => btn.addEventListener("click", () => { if (typeof openByCve === "function") openByCve(btn.dataset.cve); }));
    q("#vendorExportBtn")?.addEventListener("click", exportCsv);
    q("#vendorCloseBtn")?.addEventListener("click", () => { const el=q("#vendorFilter"); if(el){el.value=""; el.dispatchEvent(new Event("change",{bubbles:true}));} });
  }

  function weeklyFallback() {
    const week = p3.data.filter(v => daysSinceP3(v.dateAdded) <= 7);
    const vendors = new Map(), tech = new Map();
    week.forEach(v => { vendors.set(v.vendorProject||"Unknown", (vendors.get(v.vendorProject||"Unknown")||0)+1); tech.set(v.technology||"Other", (tech.get(v.technology||"Other")||0)+1); });
    return {
      periodStart: new Date(Date.now()-6*86400000).toISOString().slice(0,10), periodEnd: new Date().toISOString().slice(0,10),
      newKEVs: week.length, ransomwareLinkedNewKEVs: week.filter(ransomware).length,
      topVendors:[...vendors.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5).map(([vendor,count])=>({vendor,count})),
      topTechnologies:[...tech.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5).map(([technology,count])=>({technology,count})),
      topMovers:[...p3.data].filter(v=>(v.movement7d||0)>0).sort((a,b)=>(b.movement7d||0)-(a.movement7d||0)).slice(0,5),
      highestSignals:[...week].sort((a,b)=>signalOf(b)-signalOf(a)).slice(0,5),
      observations:[`${week.length} vulnerabilities entered CISA KEV in the last 7 days.`]
    };
  }

  function renderWeekly() {
    const w = p3.weekly || weeklyFallback();
    const content = q("#weeklySummaryContent");
    if (!content) return;
    const movers = w.topMovers || [];
    content.innerHTML = `
      <div class="weekly-kpis"><article><strong>${w.newKEVs ?? 0}</strong><span>New KEVs</span></article><article><strong>${w.ransomwareLinkedNewKEVs ?? 0}</strong><span>Ransomware-linked additions</span></article><article><strong>${w.topVendors?.[0]?.vendor ? esc(w.topVendors[0].vendor) : "—"}</strong><span>Most new vendor exposure</span></article><article><strong>${w.topTechnologies?.[0]?.technology ? esc(w.topTechnologies[0].technology) : "—"}</strong><span>Top technology pressure</span></article></div>
      <div class="weekly-grid">
        <section class="panel"><h3>What changed</h3><ul>${(w.observations||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul></section>
        <section class="panel"><h3>Top vendors this week</h3>${(w.topVendors||[]).slice(0,6).map(x=>`<div class="vendor-row"><span>${esc(x.vendor)}</span><b>${x.count}</b></div>`).join("") || '<p class="muted">No new vendor entries.</p>'}</section>
        <section class="panel"><h3>Top technologies this week</h3>${(w.topTechnologies||[]).slice(0,6).map(x=>`<div class="vendor-row"><span>${esc(x.technology)}</span><b>${x.count}</b></div>`).join("") || '<p class="muted">No new technology entries.</p>'}</section>
        <section class="panel"><h3>7-day movers</h3>${movers.length ? movers.slice(0,6).map(v=>`<button class="weekly-cve" data-cve="${esc(v.cveID)}"><span>${esc(v.cveID)}</span><b>▲ ${v.movement7d || 0}</b></button>`).join("") : '<p class="muted">A full seven-day baseline is still accumulating.</p>'}</section>
      </div>`;
    qa("[data-cve]", content).forEach(btn => btn.addEventListener("click",()=>{if(typeof openByCve==="function")openByCve(btn.dataset.cve);}));
    renderExecutivePhase3(w);
  }

  function renderExecutivePhase3(w) {
    const tech = q("#executiveTech"), weekly = q("#executiveWeekly");
    if (tech) tech.innerHTML = (w.topTechnologies||[]).slice(0,6).map(x=>`<div class="vendor-row"><span>${esc(x.technology)}</span><b>${x.count}</b></div>`).join("") || '<p class="muted">No new category concentration this week.</p>';
    if (weekly) weekly.innerHTML = `<p class="executive-summary-text">${esc(w.executiveSummary || (w.observations||[]).join(" "))}</p><div class="executive-watch"><strong>${w.newKEVs ?? 0}</strong><span>new KEVs this week</span><strong>${w.ransomwareLinkedNewKEVs ?? 0}</strong><span>ransomware-linked</span></div>`;
  }

  async function copyWeekly() {
    const w = p3.weekly || weeklyFallback();
    const text = [
      `Cyber Threat Wall Weekly Summary — ${w.periodStart} to ${w.periodEnd}`,
      `${w.newKEVs ?? 0} new CISA KEVs; ${w.ransomwareLinkedNewKEVs ?? 0} ransomware-linked.`,
      ...(w.observations || []),
      `Source: ${location.origin}${location.pathname}`
    ].join("\n");
    try { await navigator.clipboard.writeText(text); flash(q("#copyWeeklyBtn"), "Copied"); } catch (_) {}
  }

  function bindEvents() {
    q("#newSinceBtn")?.addEventListener("click", () => toggleNewMode());
    q("#exportCsvBtn")?.addEventListener("click", exportCsv);
    q("#copyLinkBtn")?.addEventListener("click", copyShareLink);
    q("#weeklyBriefBtn")?.addEventListener("click", () => { syncUrl({panel:"weekly"}); q("#weeklySummaryPanel")?.scrollIntoView({behavior:"smooth",block:"start"}); });
    q("#copyWeeklyBtn")?.addEventListener("click", copyWeekly);

    const controls = ["#search","#vendorFilter","#technologyFilter","#severityFilter","#epssFilter","#ageFilter","#ransomwareFilter","#exploitFilter","#dueFilter","#sortBy"];
    controls.forEach(sel => {
      const el = q(sel); if (!el) return;
      el.addEventListener(el.tagName === "INPUT" ? "input" : "change", () => {
        setTimeout(() => { applyNewModeVisual(); renderVendorPage(); syncUrl(); }, 0);
      });
    });
    q("#clearFilters")?.addEventListener("click", () => setTimeout(() => { p3.newMode=false; q("#newSinceBtn")?.classList.remove("active"); renderVendorPage(); syncUrl(); }, 0));
    q("#analystModeBtn")?.addEventListener("click", () => setTimeout(()=>syncUrl({mode:"analyst"}),0));
    q("#executiveModeBtn")?.addEventListener("click", () => setTimeout(()=>syncUrl({mode:"executive"}),0));
  }

  function updateNewCount() {
    const el = q("#newSinceCount"); if (el) el.textContent = p3.newSince.size.toLocaleString();
  }

  async function init() {
    injectUI();
    await loadPhase3Data();
    updateNewCount();
    renderWeekly();
    bindEvents();

    const waitForApp = setInterval(() => {
      const loaded = typeof state !== "undefined" && Array.isArray(state.data) && state.data.length;
      if (!loaded) return;
      clearInterval(waitForApp);
      if (!p3.data.length) p3.data = state.data;
      restoreUrlState();
      renderVendorPage();
      p3.ready = true;
    }, 100);
    setTimeout(() => clearInterval(waitForApp), 10000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
