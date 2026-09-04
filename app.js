const state = {
  data: [],
  filtered: [],
  meta: {},
  view: "wall",
};

const els = {
  stats: document.querySelector("#stats"),
  search: document.querySelector("#search"),
  vendor: document.querySelector("#vendorFilter"),
  severity: document.querySelector("#severityFilter"),
  age: document.querySelector("#ageFilter"),
  ransomware: document.querySelector("#ransomwareFilter"),
  due: document.querySelector("#dueFilter"),
  sort: document.querySelector("#sortBy"),
  wall: document.querySelector("#wall"),
  tableWrap: document.querySelector("#tableWrap"),
  tableBody: document.querySelector("#tableBody"),
  count: document.querySelector("#resultCount"),
  clear: document.querySelector("#clearFilters"),
  wallBtn: document.querySelector("#wallViewBtn"),
  tableBtn: document.querySelector("#tableViewBtn"),
  dataStatus: document.querySelector("#dataStatus"),
  lastUpdated: document.querySelector("#lastUpdated"),
  dialog: document.querySelector("#detailDialog"),
  detail: document.querySelector("#detailContent"),
  closeDialog: document.querySelector("#closeDialog"),
};

function daysSince(dateString) {
  if (!dateString) return Infinity;
  return Math.floor((Date.now() - new Date(`${dateString}T00:00:00Z`).getTime()) / 86400000);
}
function daysUntil(dateString) {
  if (!dateString) return Infinity;
  return Math.ceil((new Date(`${dateString}T23:59:59Z`).getTime() - Date.now()) / 86400000);
}
function escapeHtml(str = "") {
  return str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtDate(v) {
  if (!v) return "—";
  return new Intl.DateTimeFormat("en-US", { year:"numeric", month:"short", day:"numeric", timeZone:"UTC" }).format(new Date(`${v}T00:00:00Z`));
}
function severity(score) {
  if (score == null) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}
function tileLevel(score) {
  if (score >= 90) return "level-critical";
  if (score >= 75) return "level-high";
  if (score >= 60) return "level-elevated";
  return "level-watch";
}
function tileSize(score, index) {
  if (index < 8 && score >= 88) return "s4";
  if (index < 30 && score >= 78) return "s3";
  if (index < 100 && score >= 65) return "s2";
  return "s1";
}
function ransomwareKnown(v) {
  return String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known";
}
function dueState(v) {
  const d = daysUntil(v.dueDate);
  if (d < 0) return "overdue";
  if (d <= 7) return "soon";
  return "open";
}

async function loadData() {
  try {
    const res = await fetch("data/threat-wall.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    state.data = payload.vulnerabilities || [];
    state.meta = payload.meta || {};
    els.dataStatus.textContent = `${state.data.length.toLocaleString()} KEV entries loaded`;
    if (state.meta.generatedAt) {
      els.lastUpdated.textContent = `Updated ${new Intl.DateTimeFormat("en-US", {dateStyle:"medium", timeStyle:"short"}).format(new Date(state.meta.generatedAt))}`;
    }
    populateVendors();
    renderStats();
    applyFilters();
  } catch (err) {
    els.dataStatus.textContent = "Data unavailable";
    els.wall.innerHTML = `<div class="muted">Could not load data/threat-wall.json. Run the sync workflow once after publishing.</div>`;
    console.error(err);
  }
}

function populateVendors() {
  const vendors = [...new Set(state.data.map(v => v.vendorProject).filter(Boolean))].sort((a,b) => a.localeCompare(b));
  els.vendor.insertAdjacentHTML("beforeend", vendors.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join(""));
}

function renderStats() {
  const total = state.data.length;
  const last30 = state.data.filter(v => daysSince(v.dateAdded) <= 30).length;
  const ransomware = state.data.filter(ransomwareKnown).length;
  const critical = state.data.filter(v => (v.cvssScore ?? 0) >= 9).length;
  const overdue = state.data.filter(v => dueState(v) === "overdue").length;
  const stats = [
    [total.toLocaleString(), "Known exploited"],
    [last30.toLocaleString(), "Added last 30 days"],
    [ransomware.toLocaleString(), "Known ransomware use"],
    [critical.toLocaleString(), "CVSS 9.0+"],
    [overdue.toLocaleString(), "Federal due date passed"],
  ];
  els.stats.innerHTML = stats.map(([value,label]) => `<div class="stat"><div class="value">${value}</div><div class="label">${label}</div></div>`).join("");
}

function applyFilters() {
  const q = els.search.value.trim().toLowerCase();
  const vendor = els.vendor.value;
  const sev = els.severity.value;
  const age = Number(els.age.value || 0);
  const ransom = els.ransomware.value;
  const due = els.due.value;

  state.filtered = state.data.filter(v => {
    const hay = [v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.shortDescription, ...(v.cwes || [])].join(" ").toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (vendor && v.vendorProject !== vendor) return false;
    if (sev && severity(v.cvssScore) !== sev) return false;
    if (age && daysSince(v.dateAdded) > age) return false;
    if (ransom === "known" && !ransomwareKnown(v)) return false;
    if (ransom === "unknown" && ransomwareKnown(v)) return false;
    if (due && dueState(v) !== due) return false;
    return true;
  });

  const sort = els.sort.value;
  state.filtered.sort((a,b) => {
    if (sort === "newest") return (b.dateAdded || "").localeCompare(a.dateAdded || "");
    if (sort === "cvss") return (b.cvssScore ?? -1) - (a.cvssScore ?? -1);
    if (sort === "due") return (a.dueDate || "9999").localeCompare(b.dueDate || "9999");
    if (sort === "vendor") return (a.vendorProject || "").localeCompare(b.vendorProject || "");
    return (b.threatScore || 0) - (a.threatScore || 0) || (b.dateAdded || "").localeCompare(a.dateAdded || "");
  });

  els.count.textContent = state.filtered.length.toLocaleString();
  renderWall();
  renderTable();
}

function tile(v, index) {
  const cvss = v.cvssScore == null ? "—" : Number(v.cvssScore).toFixed(1);
  const ransom = ransomwareKnown(v) ? `<span class="badge">RANSOMWARE</span>` : "";
  const due = dueState(v) === "overdue" ? `<span class="badge">DUE DATE PASSED</span>` : "";
  return `<article class="tile ${tileLevel(v.threatScore)} ${tileSize(v.threatScore, index)}" data-index="${index}" tabindex="0">
    <div class="rank">#${index + 1}</div>
    <div class="cve">${escapeHtml(v.cveID)}</div>
    <div class="vendor">${escapeHtml(v.vendorProject || "Unknown vendor")}</div>
    <div class="product">${escapeHtml(v.product || "")}</div>
    <div class="score-row"><div class="threat-score">${v.threatScore}</div><div class="score-label">Threat<br>score</div></div>
    <div class="badges"><span class="badge">CVSS ${cvss}</span>${ransom}${due}</div>
  </article>`;
}

function renderWall() {
  els.wall.innerHTML = state.filtered.map(tile).join("");
  els.wall.querySelectorAll(".tile").forEach(el => {
    const open = () => showDetail(state.filtered[Number(el.dataset.index)], Number(el.dataset.index) + 1);
    el.addEventListener("click", open);
    el.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") open(); });
  });
}

function renderTable() {
  els.tableBody.innerHTML = state.filtered.map((v,i) => `
    <tr data-index="${i}">
      <td>#${i+1}</td>
      <td><strong>${escapeHtml(v.cveID)}</strong></td>
      <td><strong>${v.threatScore}</strong></td>
      <td>${v.cvssScore == null ? "—" : Number(v.cvssScore).toFixed(1)}</td>
      <td>${escapeHtml(v.vendorProject || "")} / ${escapeHtml(v.product || "")}</td>
      <td>${fmtDate(v.dateAdded)}</td>
      <td>${fmtDate(v.dueDate)}</td>
      <td>${ransomwareKnown(v) ? "Known" : "—"}</td>
    </tr>`).join("");
  els.tableBody.querySelectorAll("tr").forEach(tr => tr.addEventListener("click", () => showDetail(state.filtered[Number(tr.dataset.index)], Number(tr.dataset.index) + 1)));
}

function showDetail(v, rank) {
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cveID)}`;
  const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`;
  const githubKev = `https://github.com/cisagov/kev-data`;
  els.detail.innerHTML = `<div class="detail">
    <div class="eyebrow">Threat rank #${rank}</div>
    <h2>${escapeHtml(v.cveID)}</h2>
    <div class="muted">${escapeHtml(v.vulnerabilityName || "")}</div>
    <div class="detail-grid">
      <div class="detail-stat"><strong>${v.threatScore}</strong><span>Threat score</span></div>
      <div class="detail-stat"><strong>${v.cvssScore == null ? "—" : Number(v.cvssScore).toFixed(1)}</strong><span>CVSS</span></div>
      <div class="detail-stat"><strong>${daysSince(v.dateAdded)}</strong><span>Days in KEV</span></div>
      <div class="detail-stat"><strong>${ransomwareKnown(v) ? "YES" : "—"}</strong><span>Ransomware use</span></div>
    </div>
    <h3>Affected product</h3>
    <p><strong>${escapeHtml(v.vendorProject || "Unknown vendor")}</strong> — ${escapeHtml(v.product || "Unknown product")}</p>
    <h3>Description</h3>
    <p>${escapeHtml(v.shortDescription || "No description available.")}</p>
    <h3>Required action</h3>
    <p>${escapeHtml(v.requiredAction || "See CISA guidance.")}</p>
    <h3>Dates</h3>
    <p>Added to KEV: <strong>${fmtDate(v.dateAdded)}</strong><br>Federal remediation due date: <strong>${fmtDate(v.dueDate)}</strong></p>
    ${v.cwes?.length ? `<h3>Weaknesses</h3><p>${v.cwes.map(escapeHtml).join(", ")}</p>` : ""}
    <div class="detail-links">
      <a href="${nvdUrl}" target="_blank" rel="noopener">Open in NVD ↗</a>
      <a href="${cisaUrl}" target="_blank" rel="noopener">Open in CISA KEV ↗</a>
      <a href="${githubKev}" target="_blank" rel="noopener">CISA KEV data ↗</a>
    </div>
  </div>`;
  els.dialog.showModal();
}

function setView(view) {
  state.view = view;
  const wall = view === "wall";
  els.wall.classList.toggle("hidden", !wall);
  els.tableWrap.classList.toggle("hidden", wall);
  els.wallBtn.classList.toggle("active", wall);
  els.tableBtn.classList.toggle("active", !wall);
}

[els.search, els.vendor, els.severity, els.age, els.ransomware, els.due, els.sort].forEach(el => {
  el.addEventListener(el.tagName === "INPUT" ? "input" : "change", applyFilters);
});
els.clear.addEventListener("click", () => {
  els.search.value = "";
  els.vendor.value = "";
  els.severity.value = "";
  els.age.value = "";
  els.ransomware.value = "";
  els.due.value = "";
  els.sort.value = "threat";
  applyFilters();
});
els.wallBtn.addEventListener("click", () => setView("wall"));
els.tableBtn.addEventListener("click", () => setView("table"));
els.closeDialog.addEventListener("click", () => els.dialog.close());
els.dialog.addEventListener("click", e => { if (e.target === els.dialog) els.dialog.close(); });

loadData();
