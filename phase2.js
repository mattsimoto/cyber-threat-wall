(() => {
  let byCve = new Map();

  function points(history, width = 120, height = 28) {
    const rows = (history || []).filter(x => Number.isFinite(Number(x.rank)));
    if (rows.length < 2) return "";
    const ranks = rows.map(x => Number(x.rank));
    const min = Math.min(...ranks), max = Math.max(...ranks);
    const span = Math.max(1, max - min);
    return rows.map((x, i) => {
      const px = rows.length === 1 ? width / 2 : (i / (rows.length - 1)) * width;
      // A lower numerical rank is better, so it plots higher.
      const py = 3 + ((Number(x.rank) - min) / span) * (height - 6);
      return `${px.toFixed(1)},${py.toFixed(1)}`;
    }).join(" ");
  }

  function sparkMarkup(v) {
    const pts = points(v?.rankHistory);
    if (!pts) return "";
    const first = v.rankHistory[0]?.rank;
    const last = v.rankHistory[v.rankHistory.length - 1]?.rank;
    return `<span class="mini-spark" title="Rank history: #${first} to #${last}"><svg viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}" fill="none" vector-effect="non-scaling-stroke" /></svg></span>`;
  }

  function decorateTiles() {
    document.querySelectorAll(".tile").forEach(tile => {
      if (tile.querySelector(".mini-spark")) return;
      const cve = tile.querySelector(".cve")?.textContent?.trim();
      const v = byCve.get(cve);
      const html = sparkMarkup(v);
      if (html) tile.insertAdjacentHTML("beforeend", html);
    });
  }

  function decorateMovers() {
    document.querySelectorAll(".mover-card[data-cve]").forEach(card => {
      if (card.querySelector(".mover-spark")) return;
      const v = byCve.get(card.dataset.cve);
      const pts = points(v?.rankHistory, 120, 24);
      if (!pts) return;
      card.insertAdjacentHTML("beforeend", `<span class="mover-spark"><svg viewBox="0 0 120 24" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}" fill="none" vector-effect="non-scaling-stroke" /></svg></span>`);
    });
  }

  async function init() {
    try {
      const res = await fetch("data/threat-wall.json", { cache: "no-store" });
      if (!res.ok) return;
      const payload = await res.json();
      byCve = new Map((payload.vulnerabilities || []).map(v => [v.cveID, v]));
      decorateTiles(); decorateMovers();
      const observer = new MutationObserver(() => { decorateTiles(); decorateMovers(); });
      const wall = document.querySelector("#wall");
      const movers = document.querySelector("#movers");
      if (wall) observer.observe(wall, { childList: true });
      if (movers) observer.observe(movers, { childList: true });
    } catch (e) {
      console.debug("Sparklines unavailable", e);
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
