// --- tabs ------------------------------------------------------------
function activateTab(tab) {
  const btn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
  if (!btn) return;
  document.querySelectorAll(".tab-btn").forEach((b) => {
    const active = b === btn;
    b.classList.toggle("is-active", active);
    b.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tabpanel").forEach((p) => {
    p.hidden = p.dataset.tabpanel !== tab;
  });
  document.querySelectorAll(".scan-context").forEach((el) => { el.hidden = tab !== "updates"; });

  // visible proof the switch actually happened (fixes "feels stuck" complaint):
  // scroll the new panel into view and flash the active nav item briefly.
  const panel = document.querySelector(`.tabpanel[data-tabpanel="${tab}"]`) ||
                document.querySelector(".scan-context");
  if (panel) {
    // a .panel inside a just-shown tab was display:none, so IntersectionObserver
    // never fired for it — reveal it now that it has a layout box.
    panel.querySelectorAll(".reveal:not(.is-in)").forEach((el) => el.classList.add("is-in"));
    if (panel.classList.contains("reveal")) panel.classList.add("is-in");
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  btn.classList.remove("flash");
  void btn.offsetWidth; // restart animation
  btn.classList.add("flash");
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => activateTab(btn.dataset.tab));
});

// --- cinematic scroll-reveal (GPU-only blur-fade-up) ---------------------
// Non-destructive: tags major static blocks with .reveal and unveils them as
// they enter the viewport. IntersectionObserver (no scroll listener = no
// reflow storms). CSS handles prefers-reduced-motion by showing instantly.
(function setupReveal() {
  // only blocks WITHOUT an existing keyframe entry animation — avoids a
  // cascade fight between .reveal's opacity:0 and animation:riseIn's fill.
  const targets = document.querySelectorAll(".pipeline, .panel");
  if (!("IntersectionObserver" in window) || !targets.length) {
    targets.forEach((el) => el.classList.add("is-in"));
    return;
  }
  const io = new IntersectionObserver((entries, obs) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("is-in"); obs.unobserve(e.target); }
    });
  }, { threshold: 0.08, rootMargin: "0px 0px -6% 0px" });
  targets.forEach((el, i) => {
    el.classList.add("reveal");
    el.style.transitionDelay = `${Math.min(i * 45, 220)}ms`;
    io.observe(el);
  });
})();

// --- secure session (CSRF token from same-origin /api/config) ------------
let csrfToken = null;

async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();
    csrfToken = cfg.csrfToken;
    if (!localStorage.getItem("lang") && cfg.defaultLang) setLang(cfg.defaultLang);
  } catch (e) {
    /* server not ready yet; polling will retry */
  }
}

async function postJSON(path, body) {
  return fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken || "",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

// --- elements ------------------------------------------------------------
const runBtn = document.getElementById("runBtn");
const btnLabel = runBtn.querySelector(".btn-label");
const spinner = runBtn.querySelector(".spinner");
const logBox = document.getElementById("logBox");
const logCount = document.getElementById("logCount");
const reportBox = document.getElementById("reportBox");
const summaryBox = document.getElementById("summaryBox");
const reportMeta = document.getElementById("reportMeta");
const runStatus = document.getElementById("runStatus");
const runStatusText = document.getElementById("runStatusText");
const runStatusMeta = document.getElementById("runStatusMeta");

function updateSectionToggleLabel(btn) {
  const expanded = btn.getAttribute("aria-expanded") !== "false";
  const label = btn.querySelector(".section-toggle-label");
  if (label) label.textContent = expanded ? t("hideLogReport") : t("showLogReport");
}
document.querySelectorAll(".section-toggle").forEach((btn) => btn.addEventListener("click", () => {
  const target = document.getElementById(btn.dataset.target);
  const hidden = !target.hidden;
  target.hidden = hidden;
  btn.setAttribute("aria-expanded", String(!hidden));
  updateSectionToggleLabel(btn);
  localStorage.setItem(`collapsed:${btn.dataset.target}`, String(hidden));
}));
document.querySelectorAll(".section-toggle").forEach((btn) => {
  if (localStorage.getItem(`collapsed:${btn.dataset.target}`) === "true") btn.click();
  else updateSectionToggleLabel(btn);
});

const STAGE_MAP = {
  Orchestrator: "orchestrator",
  "Threat Hunter": "hunter",
  "Asset Auditor": "auditor",
  Remediation: "remediation",
};

let pollTimer = null;
let lastLogLen = -1;
let lastStatus = { log: [], running: false, done: false };
let lastReportMarkdown = null;
let currentView = "full";
const explainCache = new Map();

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function animateCount(el) {
  const target = parseInt(el.textContent, 10);
  if (!Number.isFinite(target)) return;
  const dur = 650;
  const start = performance.now();
  function step(now) {
    const p = Math.min((now - start) / dur, 1);
    el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// --- live log ------------------------------------------------------------
function agentClassFor(line) {
  if (line.includes("(Orchestrator)")) return "log-line-orchestrator";
  if (line.includes("(Threat Hunter)")) return "log-line-hunter";
  if (line.includes("(Asset Auditor)")) return "log-line-auditor";
  if (line.includes("(Remediation)")) return "log-line-remediation";
  if (line.includes("[ERROR]")) return "log-line-error";
  return "";
}

function updateStagesFromLog(lines) {
  const seen = new Set();
  for (const line of lines) {
    for (const [label, key] of Object.entries(STAGE_MAP)) {
      if (line.includes(`(${label})`)) seen.add(key);
    }
  }
  document.querySelectorAll(".stage").forEach((el) => {
    const done = seen.has(el.dataset.stage);
    el.dataset.active = String(done);
    el.dataset.done = String(done);
    el.querySelector(".stage-status").textContent = done ? t("stageDone") : t("stageReady");
  });
}

function renderLog(lines) {
  if (!lines.length) {
    logBox.textContent = t("logWaiting");
    logCount.textContent = "0";
    return;
  }
  logBox.innerHTML = lines
    .map((l) => `<span class="${agentClassFor(l)}">${escapeHtml(l)}</span>`)
    .join("\n");
  logBox.scrollTop = logBox.scrollHeight;
  logCount.textContent = `${lines.length} ${t("linesUnit")}`;
}

// --- report parsing + rendering -----------------------------------------
function parseReport(markdown) {
  const assets = [];
  let current = null;
  for (const raw of markdown.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("## ")) {
      current = { name: line.slice(3), findings: [] };
      assets.push(current);
    } else if (line.startsWith("- **") && current) {
      const m = line.match(/^- \*\*(.+?)\*\* \((.+?)\) —\s*(.*)$/);
      if (m) current.findings.push({ id: m[1], severity: m[2].toUpperCase(), desc: m[3] });
      else current.findings.push({ id: line.slice(2), severity: "UNKNOWN", desc: "" });
    }
  }
  return assets;
}

function severityCounts(assets) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  let total = 0;
  for (const a of assets)
    for (const f of a.findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      total++;
    }
  return { counts, total };
}

function renderFull(assets) {
  let html = "";
  for (const a of assets) {
    html += `<h2>${escapeHtml(a.name)}</h2><ul>`;
    for (const f of a.findings) {
      const sev = `sev-${f.severity}`;
      html += `<li data-cve="${escapeHtml(f.id)}" data-sev="${escapeHtml(f.severity)}" data-desc="${escapeHtml(f.desc || "")}">
        <span class="${sev}">${escapeHtml(f.id)} · ${escapeHtml(f.severity)}</span>
        <button class="explain-btn" type="button">${icon("sparkles")}<span class="explain-btn-label">${escapeHtml(t("explainBtn"))}</span><span class="mini-spin" hidden></span></button>`;
      if (f.desc) html += `<br>${escapeHtml(f.desc)}`;
      html += `<div class="explain-out" hidden></div></li>`;
    }
    html += `</ul>`;
  }
  reportBox.innerHTML = html || `<p class="empty-hint">${escapeHtml(t("reportNone"))}</p>`;
}

// explain buttons (event delegation) — feature 6
reportBox.addEventListener("click", async (e) => {
  const btn = e.target.closest(".explain-btn");
  if (!btn) return;
  const li = btn.closest("li");
  const out = li.querySelector(".explain-out");
  const btnSpin = btn.querySelector(".mini-spin");
  btn.disabled = true;
  btnSpin.hidden = false;
  out.hidden = false;
  out.classList.add("loading");
  out.textContent = t("explainLoading");
  const cacheKey = `${li.dataset.cve}:${li.dataset.sev}:${li.dataset.desc}`;
  if (explainCache.has(cacheKey)) {
    out.classList.remove("loading");
    out.textContent = explainCache.get(cacheKey);
    btn.disabled = false;
    btnSpin.hidden = true;
    return;
  }
  try {
    const res = await postJSON("/api/ai/explain", {
      id: li.dataset.cve, severity: li.dataset.sev, desc: li.dataset.desc,
    });
    const data = await res.json();
    out.classList.remove("loading");
    out.textContent = data.available ? data.text : t("llmOffline");
    if (data.available && data.text) explainCache.set(cacheKey, data.text);
  } catch {
    out.classList.remove("loading");
    out.textContent = t("llmOffline");
  } finally {
    btn.disabled = false;
    btnSpin.hidden = true;
  }
});

function renderSummary(assets) {
  const { counts, total } = severityCounts(assets);
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const chips = order
    .filter((s) => counts[s] > 0)
    .map((s) => `<span class="sev-chip sev-${s}">${s}: ${counts[s]}</span>`)
    .join("");

  let verdict = t("verdictEmpty");
  if (total > 0) verdict = counts.CRITICAL || counts.HIGH ? t("verdictCritical") : t("verdictClean");

  summaryBox.innerHTML = `
    <div class="summary-verdict">${escapeHtml(verdict)}</div>
    <div class="summary-stats">
      <div class="stat"><span class="stat-num">${assets.length}</span><span class="stat-label">${escapeHtml(t("sumAssets"))}</span></div>
      <div class="stat"><span class="stat-num">${total}</span><span class="stat-label">${escapeHtml(t("sumFindings"))}</span></div>
    </div>
    <div class="summary-sev-label">${escapeHtml(t("sumBySeverity"))}</div>
    <div class="summary-chips">${chips || "—"}</div>`;
  summaryBox.querySelectorAll(".stat-num").forEach(animateCount);
}

function renderReport() {
  if (!lastReportMarkdown) {
    reportBox.innerHTML = `<p class="empty-hint">${escapeHtml(
      lastStatus.running ? t("reportRunning") : t("reportEmpty")
    )}</p>`;
    summaryBox.innerHTML = "";
    reportMeta.textContent = t("metaNone");
    return;
  }
  const assets = parseReport(lastReportMarkdown);
  const { total } = severityCounts(assets);
  renderFull(assets);
  renderSummary(assets);
  reportMeta.textContent = `${total} ${t("findingsUnit")}`;
}

function setView(view) {
  currentView = view;
  document.querySelectorAll("[data-view]").forEach((b) =>
    b.classList.toggle("is-active", b.dataset.view === view)
  );
  reportBox.hidden = view !== "full";
  summaryBox.hidden = view !== "summary";
}

async function fetchReport() {
  const res = await fetch("/api/report");
  const data = await res.json();
  lastReportMarkdown = data.content || null;
  renderReport();
  updateKpisFromReport();
}

// --- orchestrator polling ------------------------------------------------
function renderRunStatus() {
  const state = lastStatus;
  runStatus.dataset.state = state.running ? "running" : state.done ? (state.exit_code === 0 ? "done" : "error") : "ready";
  runStatusText.textContent = state.running ? t("statusRunning") : state.done ? (state.exit_code === 0 ? t("statusDone") : t("statusFailed")) : t("statusReady");
  const inv = state.inventory || {};
  const elapsed = state.running ? ` · ${state.elapsed_secs || 0} ${t("secondsAbbrev")}` : "";
  const excludedTotal = (inv.excluded_games || 0) + (inv.excluded_redist || 0);
  const excludedDetail = inv.excluded_games || inv.excluded_redist
    ? ` (${inv.excluded_games || 0} ${t("excludedGames")} · ${inv.excluded_redist || 0} ${t("excludedRedist")})`
    : "";
  runStatusMeta.textContent = inv.updated_at
    ? `${inv.scanned || 0} ${t("scannedUnit")} · ${excludedTotal} ${t("excludedUnit")}${excludedDetail}${elapsed}`
    : elapsed;
}

async function poll() {
  let state;
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error("status unavailable");
    state = await res.json();
  } catch {
    // A network hiccup or backend restart mid-scan must not leave the UI
    // stuck showing "Running…" forever with a spinning spinner and no way
    // out short of a manual page reload — surface it and stop polling.
    clearInterval(pollTimer);
    pollTimer = null;
    runBtn.disabled = false;
    btnLabel.textContent = t("runScan");
    spinner.hidden = true;
    runStatusText.textContent = t("statusFailed");
    return;
  }
  lastStatus = state;
  renderRunStatus();

  if (state.log.length !== lastLogLen) {
    renderLog(state.log);
    updateStagesFromLog(state.log);
    lastLogLen = state.log.length;
  }

  if (state.running) {
    runBtn.disabled = true;
    btnLabel.textContent = t("running");
    spinner.hidden = false;
  } else {
    runBtn.disabled = false;
    btnLabel.textContent = t("runScan");
    spinner.hidden = true;
    if (state.done) {
      clearInterval(pollTimer);
      pollTimer = null;
      fetchReport();
      fetchHistory();
      fetchDiff();
      fetchDecision();
    }
  }
}

runBtn.addEventListener("click", async () => {
  // Disabled synchronously, before the first await — poll() only disables
  // it after the first /api/status round-trip completes, leaving a window
  // where a fast double-click fires /api/run twice.
  runBtn.disabled = true;
  btnLabel.textContent = t("running");
  spinner.hidden = false;
  lastLogLen = -1;
  lastReportMarkdown = null;
  renderReport();
  await postJSON("/api/run");
  if (!pollTimer) pollTimer = setInterval(poll, 800);
  poll();
});

document.querySelectorAll(".view-opt").forEach((b) =>
  b.addEventListener("click", () => { if (b.dataset.view) setView(b.dataset.view); })
);

// --- updates / winget panel ----------------------------------------------
const scanBtn = document.getElementById("scanBtn");
const applyAllBtn = document.getElementById("applyAllBtn");
const updatesBox = document.getElementById("updatesBox");
const updatesLog = document.getElementById("updatesLog");
const updProgress = document.getElementById("updProgress");

let upgPollTimer = null;
let lastUpg = { items: [], results: [], running: false, log: [] };
const detailsCache = {};

function metaText(d) {
  if (!d) return t("fetchingSize");
  const parts = [];
  if (d.publisher) parts.push(d.publisher);
  parts.push(`${t("sizeLabel")}: ${d.sizeText || t("sizeUnknown")}`);
  return parts.join(" · ");
}

async function fetchRowDetails() {
  if (lastUpg.running) return;
  for (const it of lastUpg.items) {
    if (detailsCache[it.Id] !== undefined) continue;
    detailsCache[it.Id] = null; // mark in-flight
    try {
      const res = await postJSON("/api/upgrades/details", { id: it.Id });
      detailsCache[it.Id] = await res.json();
    } catch (e) {
      detailsCache[it.Id] = { sizeText: null, publisher: null };
    }
    const el = updatesBox.querySelector(`.upd-meta[data-id="${CSS.escape(it.Id)}"]`);
    if (el) el.textContent = metaText(detailsCache[it.Id]);
  }
}

function renderUpgProgress(p) {
  if (!p) {
    updProgress.hidden = true;
    updProgress.innerHTML = "";
    return;
  }
  const phaseKey = {
    downloading: "phaseDownloading",
    installing: "phaseInstalling",
    verifying: "phaseVerifying",
    done: "phaseDone",
  }[p.phase] || "phaseDownloading";
  const item = lastUpg.items.find((i) => i.Id === p.id);
  const name = item ? item.Name || item.Id : p.id;
  const size = p.sizeText ? ` · ${escapeHtml(p.sizeText)}` : "";
  const eta = p.etaSec != null && p.percent < 100 ? `${t("etaLabel")}: ${t("etaSuffix", p.etaSec)}` : "";

  updProgress.hidden = false;
  updProgress.innerHTML = `
    <div class="upd-prog-head">
      <span class="upd-prog-name">${escapeHtml(t("updatingNow", name))}</span>
      <span class="upd-prog-pct">${p.percent}%</span>
    </div>
    <div class="upd-prog-bar"><div class="upd-prog-fill"></div></div>
    <div class="upd-prog-foot">
      <span>${escapeHtml(t(phaseKey))}${size}</span>
      <span>${escapeHtml(eta)}</span>
    </div>`;
  // width set via CSSOM (inline style attributes are blocked by our CSP)
  updProgress.querySelector(".upd-prog-fill").style.width = `${p.percent}%`;
}

function renderUpdateRows() {
  const { items, results } = lastUpg;
  const resultById = Object.fromEntries((results || []).map((r) => [r.id, r]));
  if (!items.length) {
    updatesBox.innerHTML = `<p class="empty-hint">${escapeHtml(
      lastUpg.scanned ? t("updatesNone") : t("updatesEmpty")
    )}</p>`;
    applyAllBtn.hidden = true;
    return;
  }
  updatesBox.innerHTML = items
    .map((it) => {
      const r = resultById[it.Id];
      let statusHtml = '<span class="upd-status"></span>';
      let btnHtml = `<button class="upd-btn" data-id="${escapeHtml(it.Id)}">${icon("download")}<span>${escapeHtml(t("updateBtn"))}</span></button>`;
      let errorHtml = "";
      if (r) {
        statusHtml = `<span class="upd-status ${r.ok ? "ok" : "fail"}">${r.ok ? t("updOk") : t("updFail")}</span>`;
        btnHtml = "";
        if (!r.ok && r.message) errorHtml = `<div class="upd-error" dir="ltr">${escapeHtml(r.message)}</div>`;
      }
      const ignoreHtml = (!r || !r.ok)
        ? `<button class="upd-ignore-btn" data-id="${escapeHtml(it.Id)}" title="${escapeHtml(t("ignoreUpdateHint"))}">${icon("eyeOff")}<span>${escapeHtml(t("ignoreUpdate"))}</span></button>`
        : "";
      const meta = metaText(detailsCache[it.Id] || undefined);
      return `<div class="upd-row" data-id="${escapeHtml(it.Id)}">
        <div class="upd-main">
          <span class="upd-name">${escapeHtml(it.Name || it.Id)}</span>
          <span class="upd-meta" data-id="${escapeHtml(it.Id)}">${escapeHtml(meta)}</span>
        </div>
        <span class="upd-ver" dir="ltr">${escapeHtml(it.Version || "")} → ${escapeHtml(it.Available || "")}</span>
        ${statusHtml}
        ${btnHtml}
        ${ignoreHtml}
        ${errorHtml}
      </div>`;
    })
    .join("");
  applyAllBtn.hidden = false;

  updatesBox.querySelectorAll(".upd-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      if (!confirm(t("confirmOne", id))) return;
      startApply([id]);
    });
  });
  updatesBox.querySelectorAll(".upd-ignore-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      btn.disabled = true;
      const res = await postJSON("/api/upgrades/ignore", { id });
      const data = await res.json();
      if (data.status === "ok") {
        lastUpg.items = (lastUpg.items || []).filter((it) => it.Id !== id);
        renderUpdateRows();
      } else {
        btn.disabled = false;
      }
    });
  });
  fetchRowDetails();
}

function renderUpgLog() {
  const lines = lastUpg.log || [];
  updatesLog.hidden = lines.length === 0;
  updatesLog.textContent = lines.map(translateUpgLog).join("\n");
  updatesLog.scrollTop = updatesLog.scrollHeight;
}

async function fetchUpgradeStatus() {
  const res = await fetch("/api/upgrades/status");
  const state = await res.json();
  lastUpg = state;
  lastUpg.scanned = state.phase === "scanned" || state.phase === "applied";

  renderUpgLog();
  renderUpdateRows();
  renderUpgProgress(state.progress);
  scanBtn.disabled = state.running;
  applyAllBtn.disabled = state.running || state.items.length === 0;

  if (!state.running && upgPollTimer) {
    clearInterval(upgPollTimer);
    upgPollTimer = null;
  }
}

async function startApply(ids) {
  await postJSON("/api/upgrades/apply", { ids });
  if (!upgPollTimer) upgPollTimer = setInterval(fetchUpgradeStatus, 900);
  fetchUpgradeStatus();
}

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  await postJSON("/api/upgrades/scan");
  if (!upgPollTimer) upgPollTimer = setInterval(fetchUpgradeStatus, 900);
  fetchUpgradeStatus();
});

// --- "Go update it" from the urgent banner --------------------------------
function normalizeProductKey(name) {
  return (name || "").replace(/\s+\d[\d.]*$/, "").trim().toLowerCase();
}

function highlightUpdateRow(productName) {
  const key = normalizeProductKey(productName).split(" ")[0];
  if (!key) return false;
  const rows = Array.from(updatesBox.querySelectorAll(".upd-row"));
  const match = rows.find((r) => {
    const nameEl = r.querySelector(".upd-name");
    return nameEl && normalizeProductKey(nameEl.textContent).includes(key);
  });
  if (!match) return false;
  match.scrollIntoView({ behavior: "smooth", block: "center" });
  match.classList.add("highlight");
  setTimeout(() => match.classList.remove("highlight"), 2500);
  return true;
}

async function goToUpdateForProduct(productName) {
  activateTab("updates");
  if (!lastUpg.scanned && !lastUpg.running) {
    await postJSON("/api/upgrades/scan");
    if (!upgPollTimer) upgPollTimer = setInterval(fetchUpgradeStatus, 900);
    fetchUpgradeStatus();
  }
  const tryHighlight = (attemptsLeft) => {
    if (lastUpg.running && attemptsLeft > 0) {
      setTimeout(() => tryHighlight(attemptsLeft - 1), 600);
      return;
    }
    highlightUpdateRow(productName);
  };
  tryHighlight(60); // covers a full winget scan (~tens of seconds)
}

applyAllBtn.addEventListener("click", () => {
  const ids = Array.from(updatesBox.querySelectorAll(".upd-row"))
    .map((row) => row.dataset.id)
    .filter(Boolean);
  if (!ids.length) return;
  if (!confirm(t("confirmAll", ids.length))) return;
  startApply(ids);
});

// --- security tests (Golden Dataset) -------------------------------------
const secRunBtn = document.getElementById("secRunBtn");
const secBtnLabel = secRunBtn.querySelector(".sec-btn-label");
const secSpinner = secRunBtn.querySelector(".sec-spinner");
const secSummary = document.getElementById("secSummary");
const secChips = document.getElementById("secChips");
const secBody = document.getElementById("secBody");
const secSide = document.getElementById("secSide");
const secTableWrap = document.getElementById("secTableWrap");
const secEmpty = document.getElementById("secEmpty");

let lastSec = null;
let securityView = localStorage.getItem("securityView") || "summary";

function setSecurityView(view) {
  securityView = view;
  localStorage.setItem("securityView", view);
  document.querySelectorAll("[data-sec-view]").forEach((b) => b.classList.toggle("is-active", b.dataset.secView === view));
  if (lastSec) {
    secBody.hidden = view !== "full";
    secSide.hidden = view !== "full";
  }
}
document.querySelectorAll("[data-sec-view]").forEach((b) => b.addEventListener("click", () => setSecurityView(b.dataset.secView)));

function renderSecurity() {
  if (!lastSec) return;
  const s = lastSec.summary;
  const allPass = s.failed === 0;

  secEmpty.hidden = true;
  secSummary.hidden = false;
  secChips.hidden = false;
  secBody.hidden = securityView !== "full";

  secSummary.innerHTML = `
    <div class="sec-verdict ${allPass ? "ok" : "bad"}">
      ${allPass ? "✅ " : "⚠️ "}${escapeHtml(allPass ? t("secAllPass") : t("secSomeFail"))}
    </div>
    <div class="sec-stats">
      <div class="stat"><span class="stat-num">${s.total}</span><span class="stat-label">${escapeHtml(t("secTotal"))}</span></div>
      <div class="stat"><span class="stat-num num-pass">${s.passed}</span><span class="stat-label">${escapeHtml(t("secPassed"))}</span></div>
      <div class="stat"><span class="stat-num ${s.failed ? "num-fail" : "num-muted"}">${s.failed}</span><span class="stat-label">${escapeHtml(t("secFailed"))}</span></div>
      <div class="stat"><span class="stat-num">${s.rate}%</span><span class="stat-label">${escapeHtml(t("secRate"))}</span></div>
    </div>`;
  secSummary.querySelectorAll(".stat-num").forEach(animateCount);

  secChips.innerHTML = Object.entries(s.categories)
    .map(([cat, c]) => {
      const ok = c.passed === c.total;
      return `<span class="sec-chip ${ok ? "ok" : "bad"}">${escapeHtml(cat)} ${c.passed}/${c.total}</span>`;
    })
    .join("");

  // side summary: percent ring + headline counts
  const cleanCats = Object.values(s.categories).filter((c) => c.passed === c.total).length;
  const totalCats = Object.keys(s.categories).length;
  const R = 46;
  const CIRC = 2 * Math.PI * R;
  secSide.innerHTML = `
    <div class="sec-side-title">${escapeHtml(t("secSideTitle"))}</div>
    <div class="sec-ring">
      <svg viewBox="0 0 120 120" width="128" height="128">
        <circle cx="60" cy="60" r="${R}" class="ring-track"></circle>
        <circle cx="60" cy="60" r="${R}" class="ring-fill" transform="rotate(-90 60 60)"></circle>
        <text x="60" y="58" class="ring-pct">${s.rate}%</text>
        <text x="60" y="78" class="ring-sub">${s.passed}/${s.total}</text>
      </svg>
    </div>
    <ul class="sec-side-list">
      <li><span class="dot ok"></span>${escapeHtml(t("secPassed"))}<b>${s.passed}</b></li>
      <li><span class="dot ${s.failed ? "bad" : "muted"}"></span>${escapeHtml(t("secFailed"))}<b>${s.failed}</b></li>
      <li><span class="dot ok"></span>${escapeHtml(t("secCatsClean"))}<b>${cleanCats}/${totalCats}</b></li>
    </ul>`;
  const fill = secSide.querySelector(".ring-fill");
  fill.setAttribute("stroke-dasharray", String(CIRC));
  fill.setAttribute("stroke-dashoffset", String(CIRC * (1 - s.rate / 100)));

  const rows = lastSec.results
    .map(
      (r) => `<tr>
      <td>${escapeHtml(r.category)}</td>
      <td>${escapeHtml(r.desc)}</td>
      <td>${escapeHtml(r.expected)}</td>
      <td>${escapeHtml(r.mitigation)}</td>
      <td class="sec-owasp" dir="ltr">${escapeHtml(r.owasp)}</td>
      <td class="${r.passed ? "st-pass" : "st-fail"}">${r.passed ? t("stPass") : t("stFail")}</td>
    </tr>`
    )
    .join("");
  secTableWrap.innerHTML = `<table class="sec-table">
    <thead><tr>
      <th>${escapeHtml(t("colCategory"))}</th>
      <th>${escapeHtml(t("colDesc"))}</th>
      <th>${escapeHtml(t("colExpected"))}</th>
      <th>${escapeHtml(t("colMitig"))}</th>
      <th>OWASP</th>
      <th>${escapeHtml(t("colStatus"))}</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
  setSecurityView(securityView);
}

secRunBtn.addEventListener("click", async () => {
  secRunBtn.disabled = true;
  secBtnLabel.textContent = t("secRunning");
  secSpinner.hidden = false;
  try {
    const res = await postJSON("/api/security/run");
    lastSec = await res.json();
    renderSecurity();
  } finally {
    secRunBtn.disabled = false;
    secBtnLabel.textContent = t("secRun");
    secSpinner.hidden = true;
  }
});

// --- KPI row + health gauge + urgent banner (Decision Agent) -------------
const kpiFindings = document.getElementById("kpiFindings");
const kpiCritical = document.getElementById("kpiCritical");
const kpiAssets = document.getElementById("kpiAssets");
const healthScoreNum = document.getElementById("healthScoreNum");
const healthRing = document.getElementById("healthRing");
const urgentBanner = document.getElementById("urgentBanner");
const kpiCardHealth = document.querySelector('.kpi-card[data-kpi="health"]');
const kpiCardFindings = document.querySelector('.kpi-card[data-kpi="findings"]');
const kpiCardCritical = document.querySelector('.kpi-card[data-kpi="critical"]');
const kpiCardAssets = document.querySelector('.kpi-card[data-kpi="assets"]');

const GAUGE_R = 50;
const GAUGE_CIRC = 2 * Math.PI * GAUGE_R;
healthRing.setAttribute("stroke-dasharray", String(GAUGE_CIRC));

// three-level accent scheme reused for the ring stroke and every card's
// top strip, so the strip color always tracks the number the card shows
// instead of staying a fixed decorative gradient.
const _TIER_COLORS = {
  good: ["var(--green)", "var(--cyan)"],
  warn: ["var(--amber)", "var(--sev-med)"],
  danger: ["var(--blood-bright)", "var(--blood-dim)"],
};

function setKpiAccent(card, level) {
  if (!card) return;
  const [c1, c2] = _TIER_COLORS[level] || _TIER_COLORS.warn;
  card.style.setProperty("--kpi-c1", c1);
  card.style.setProperty("--kpi-c2", c2);
}

function scoreLevel(score) {
  if (score == null) return "warn";
  if (score >= 75) return "good";
  if (score >= 45) return "warn";
  return "danger";
}

function scoreColor(score) {
  if (score >= 75) return "var(--green)";
  if (score >= 45) return "var(--amber)";
  return "var(--blood-bright)";
}

function countLevel(n, dangerAt) {
  if (n <= 0) return "good";
  if (n < dangerAt) return "warn";
  return "danger";
}

function updateKpisFromReport() {
  if (!lastReportMarkdown) return;
  const assets = parseReport(lastReportMarkdown);
  const { counts, total } = severityCounts(assets);
  const critHigh = (counts.CRITICAL || 0) + (counts.HIGH || 0);
  kpiFindings.textContent = total;
  kpiCritical.textContent = critHigh;
  kpiAssets.textContent = assets.length;
  setKpiAccent(kpiCardFindings, countLevel(total, 100));
  setKpiAccent(kpiCardCritical, countLevel(critHigh, 10));
  setKpiAccent(kpiCardAssets, countLevel(assets.length, 30));
  if (kpiDetailKind) renderKpiDetail(kpiDetailKind); // keep an open drawer fresh
}

// --- KPI detail drawer ---------------------------------------------------
const kpiDetail = document.getElementById("kpiDetail");
let kpiDetailKind = null;

// CSP is style-src 'self' with no 'unsafe-inline' — inline style="..."
// attributes are silently dropped by the browser (zero width, no color,
// no console warning visible via devtools-less inspection). Every bar here
// is colored/sized AFTER insertion via .style.setProperty(), which is a
// CSSOM call and exempt from style-src, matching the pattern already used
// for .upd-prog-fill and the KPI card accent strips.
function _bar(labelHtml, count, total, color) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  // kd-track/kd-fill MUST be block-level elements (div), not span: width/
  // height are no-ops on non-replaced inline elements per the CSS spec, so
  // a <span> here silently never shows any fill regardless of what JS sets
  // on it — this is exactly why these bars rendered as flat, colorless
  // lines while the (div-based) history-tab bars worked correctly.
  return `<div class="kd-bar">
    <span class="kd-bar-label"><span class="kd-swatch" data-color="${escapeHtml(color)}"></span>${labelHtml}</span>
    <div class="kd-track"><div class="kd-fill" data-color="${escapeHtml(color)}" data-pct="${pct}"></div></div>
    <span class="kd-count">${count}</span>
  </div>`;
}

// Walks any container just written via innerHTML and applies the
// data-color/data-pct/data-seg-color hints as real inline styles through
// the CSSOM — call this after every innerHTML assignment that used _bar()
// or emits kd-scale-seg/hd-swatch/hd-fill markup.
function _applyBarStyles(container) {
  container.querySelectorAll("[data-color]").forEach((el) => {
    el.style.setProperty("background", el.dataset.color);
  });
  container.querySelectorAll("[data-pct]").forEach((el) => {
    el.style.setProperty("width", `${el.dataset.pct}%`);
  });
  container.querySelectorAll("[data-seg-color]").forEach((el) => {
    el.style.setProperty("--seg-c", el.dataset.segColor);
  });
}

function _decisionBreakdown() {
  // classify only CRITICAL/HIGH decision items into mutually-exclusive
  // plain-language buckets, so the bars sum sensibly against the crit/high
  // headline and directly answer "critical but no update — why?".
  const items = ((lastDecision && lastDecision.items) || [])
    .filter((it) => it.severity === "CRITICAL" || it.severity === "HIGH");
  const b = { total: items.length, urgent: 0, noUpdate: 0, hardExploit: 0, fixedOrReview: 0, other: 0 };
  for (const it of items) {
    const r = it.reason || "";
    if (it.tier === "urgent") b.urgent++;
    else if (/لا يوجد تحديث|no update/i.test(r)) b.noUpdate++;
    else if (/شروط صعبة|hard|محلي|complex|صعب/i.test(r)) b.hardExploit++;
    else if (/مُصلحة|مراجعة|fixed|review|أحدث/i.test(r)) b.fixedOrReview++;
    else b.other++;
  }
  return b;
}

function renderKpiDetail(kind) {
  kpiDetailKind = kind;
  const assets = lastReportMarkdown ? parseReport(lastReportMarkdown) : [];
  const { counts, total } = severityCounts(assets);
  const critHigh = (counts.CRITICAL || 0) + (counts.HIGH || 0);
  const score = lastDecision ? lastDecision.health_score : null;
  const b = _decisionBreakdown();
  const cCrit = "var(--sev-crit)", cHigh = "var(--sev-high)", cMed = "var(--sev-med)",
        cLow = "var(--sev-low)", cViolet = "var(--violet)", cGreen = "var(--green)", cMuted = "var(--muted)";
  let html = "";

  if (kind === "health") {
    const lvl = scoreLevel(score);
    const band = score == null ? "—" : lvl === "good" ? t("kdHealthGood") : lvl === "warn" ? t("kdHealthMid") : t("kdHealthPoor");
    const bandColor = score == null ? cMuted : lvl === "good" ? cGreen : lvl === "warn" ? cMed : cCrit;
    html = `<h4>${escapeHtml(t("kpiHealth"))} — ${score == null ? "—" : score + "/100"}</h4>
      <p class="kd-lead">${escapeHtml(t("kdHealthLead"))}</p>
      <div class="kd-bars">
        ${_bar(escapeHtml(band), score == null ? 0 : score, 100, bandColor)}
      </div>
      <div class="kd-scale">
        <span class="kd-scale-seg${lvl === "danger" ? " is-current" : ""}" data-seg-color="${escapeHtml(cCrit)}">0–44 · ${escapeHtml(t("kdBandPoor"))}</span>
        <span class="kd-scale-seg${lvl === "warn" ? " is-current" : ""}" data-seg-color="${escapeHtml(cMed)}">45–74 · ${escapeHtml(t("kdBandMid"))}</span>
        <span class="kd-scale-seg${lvl === "good" ? " is-current" : ""}" data-seg-color="${escapeHtml(cGreen)}">75–100 · ${escapeHtml(t("kdBandGood"))}</span>
      </div>
      <p class="kd-note">${t("kdHealthNote")}</p>`;
  } else if (kind === "findings") {
    html = `<h4>${escapeHtml(t("kpiFindings"))} — ${total}</h4>
      <p class="kd-lead">${escapeHtml(t("kdFindingsLead"))}</p>
      <div class="kd-bars">
        ${_bar("CRITICAL", counts.CRITICAL || 0, total, cCrit)}
        ${_bar("HIGH", counts.HIGH || 0, total, cHigh)}
        ${_bar("MEDIUM", counts.MEDIUM || 0, total, cMed)}
        ${_bar("LOW", counts.LOW || 0, total, cLow)}
        ${_bar("UNKNOWN", counts.UNKNOWN || 0, total, cMuted)}
      </div>
      <p class="kd-note">${t("kdFindingsNote")}</p>`;
  } else if (kind === "critical") {
    const den = b.total || 1;
    html = `<h4>${escapeHtml(t("kpiCritical"))} — ${critHigh}</h4>
      <p class="kd-lead">${escapeHtml(t("kdCriticalLead"))}</p>
      <div class="kd-bars">
        ${_bar(escapeHtml(t("kdActionable")), b.urgent, den, cCrit)}
        ${_bar(escapeHtml(t("kdNoUpdate")), b.noUpdate, den, cHigh)}
        ${_bar(escapeHtml(t("kdHardExploit")), b.hardExploit, den, cMed)}
        ${_bar(escapeHtml(t("kdFixedReview")), b.fixedOrReview, den, cLow)}
      </div>
      <p class="kd-note">${t("kdCriticalNote")}</p>`;
  } else if (kind === "assets") {
    const inv = lastStatus.inventory || {};
    const scanned = inv.scanned || 0;
    const exG = inv.excluded_games || 0, exR = inv.excluded_redist || 0;
    html = `<h4>${escapeHtml(t("kpiAssets"))} — ${assets.length}</h4>
      <p class="kd-lead">${escapeHtml(t("kdAssetsLead"))}</p>
      <div class="kd-bars">
        ${_bar(escapeHtml(t("kdWithFindings")), assets.length, scanned || assets.length || 1, cViolet)}
        ${_bar(escapeHtml(t("kdScannedClean")), Math.max(scanned - assets.length, 0), scanned || 1, cGreen)}
        ${_bar(escapeHtml(t("kdExcludedGames")), exG, scanned + exG + exR || 1, cMuted)}
        ${_bar(escapeHtml(t("kdExcludedRedist")), exR, scanned + exG + exR || 1, cMuted)}
      </div>
      <p class="kd-note">${t("kdAssetsNote")}</p>`;
  }
  kpiDetail.innerHTML = html;
  kpiDetail.hidden = false;
  _applyBarStyles(kpiDetail);
}

function toggleKpiDetail(card) {
  const kind = card.dataset.kpi;
  const isOpen = card.getAttribute("aria-expanded") === "true" && kpiDetailKind === kind;
  document.querySelectorAll(".kpi-card[data-kpi]").forEach((c) =>
    c.setAttribute("aria-expanded", String(c === card && !isOpen)));
  if (isOpen) {
    kpiDetail.hidden = true;
    kpiDetailKind = null;
  } else {
    renderKpiDetail(kind);
    kpiDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

document.querySelectorAll(".kpi-card[data-kpi]").forEach((card) => {
  card.addEventListener("click", () => toggleKpiDetail(card));
  card.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleKpiDetail(card); }
  });
});

// 3D perspective tilt toward the pointer — set via CSSOM (.style.setProperty,
// CSP-exempt) not inline style="" strings. Disabled under reduced-motion.
const _reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
if (!_reduceMotion) {
  document.querySelectorAll(".kpi-card[data-kpi]").forEach((card) => {
    card.addEventListener("mousemove", (e) => {
      const r = card.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width - 0.5;
      const py = (e.clientY - r.top) / r.height - 0.5;
      card.style.setProperty("--tilt-y", `${(px * 10).toFixed(2)}deg`);
      card.style.setProperty("--tilt-x", `${(-py * 10).toFixed(2)}deg`);
      card.style.setProperty("--lift", "-4px");
    });
    card.addEventListener("mouseleave", () => {
      card.style.setProperty("--tilt-x", "0deg");
      card.style.setProperty("--tilt-y", "0deg");
      card.style.setProperty("--lift", "0px");
    });
  });
}

function renderHealthGauge(score) {
  if (score == null) {
    healthScoreNum.textContent = "—";
    healthRing.setAttribute("stroke-dashoffset", String(GAUGE_CIRC));
    healthRing.style.stroke = "var(--muted)";
    setKpiAccent(kpiCardHealth, "warn");
    if (window.scene3d) {
      window.scene3d.orb && window.scene3d.orb.setScore(null, "warn");
      window.scene3d.ambient && window.scene3d.ambient.setThreatLevel("warn");
    }
    return;
  }
  healthScoreNum.textContent = score;
  healthRing.style.stroke = scoreColor(score);
  healthRing.setAttribute("stroke-dashoffset", String(GAUGE_CIRC * (1 - score / 100)));
  const lvl = scoreLevel(score);
  setKpiAccent(kpiCardHealth, lvl);
  if (window.scene3d) {
    window.scene3d.orb && window.scene3d.orb.setScore(score, lvl);
    window.scene3d.ambient && window.scene3d.ambient.setThreatLevel(lvl);
  }
}

function snoozeOffsetIso(days) {
  const d = new Date(Date.now() + days * 86400000);
  return d.toISOString();
}

async function submitSnooze(ids, iso, rowEl) {
  // one finding = one CVE, but a row can represent several CVEs for the same
  // product (dedupe fix) — snooze every id in the group together.
  const results = await Promise.all(
    ids.map((id) => postJSON("/api/decision/snooze", { id, remindAt: iso }).then((r) => r.json()))
  );
  if (results.every((r) => r.status === "ok")) {
    rowEl.innerHTML = `<span class="u-reason">${escapeHtml(t("snoozedMsg"))}</span>`;
  }
}

function renderUrgentBanner(urgent) {
  if (!urgent || !urgent.length) {
    urgentBanner.hidden = true;
    urgentBanner.innerHTML = "";
    return;
  }
  urgentBanner.hidden = false;

  // group by product so "IntelliJ IDEA" with 3 critical CVEs shows ONE row
  // (fixes the "duplicate entries" complaint) instead of three near-identical ones.
  const groups = new Map();
  for (const it of urgent) {
    const key = it.product || it.id;
    if (!groups.has(key)) groups.set(key, { product: key, ids: [], exploited: false, reasons: [] });
    const g = groups.get(key);
    g.ids.push(it.id);
    g.exploited = g.exploited || !!it.exploited;
    g.reasons.push(it.id);
  }

  const rows = Array.from(groups.values())
    .map((g) => {
      const tag = g.exploited ? ` · <span class="u-exploited-tag">${escapeHtml(t("exploitedTag"))}</span>` : "";
      const cveList = escapeHtml(g.reasons.join(", "));
      const countBadge = g.ids.length > 1 ? ` <span class="badge-muted">${g.ids.length}</span>` : "";
      return `<div class="urgent-row" data-ids="${escapeHtml(g.ids.join(","))}" data-product="${escapeHtml(g.product)}">
        <span class="u-name">${escapeHtml(g.product)}${countBadge}</span>
        <span class="u-reason">${cveList}${tag}</span>
        <div class="u-actions">
          <button class="u-btn go-update">${icon("arrowUpRight")}<span>${escapeHtml(t("urgentGoUpdate"))}</span></button>
          <div class="u-snooze-menu">
            <button data-days="1">${icon("clock")}<span>${escapeHtml(t("snoozeTomorrow"))}</span></button>
            <button data-days="3">${icon("clock")}<span>${escapeHtml(t("snooze3d"))}</span></button>
            <button data-days="7">${icon("clock")}<span>${escapeHtml(t("snooze1w"))}</span></button>
          </div>
        </div>
      </div>`;
    })
    .join("");
  urgentBanner.innerHTML = `<div class="urgent-banner-head">${escapeHtml(t("urgentTitle", groups.size))}</div>${rows}`;

  urgentBanner.querySelectorAll(".go-update").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = btn.closest(".urgent-row");
      goToUpdateForProduct(row.dataset.product || "");
    });
  });
  urgentBanner.querySelectorAll(".u-snooze-menu button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = btn.closest(".urgent-row");
      const ids = (row.dataset.ids || "").split(",").filter(Boolean);
      const iso = snoozeOffsetIso(parseInt(btn.dataset.days, 10));
      submitSnooze(ids, iso, row);
    });
  });
}

let lastDecision = null;

async function fetchDecision() {
  try {
    const res = await fetch("/api/decision");
    lastDecision = await res.json();
    renderHealthGauge(lastDecision.health_score);
    renderUrgentBanner(lastDecision.urgent);
  } catch {}
}

// --- AI analyst: Q&A + reassess (features 7,8) ---------------------------
const askInput = document.getElementById("askInput");
const askBtn = document.getElementById("askBtn");
const reassessBtn = document.getElementById("reassessBtn");
const aiOut = document.getElementById("aiOut");

async function aiCall(path, body, btn) {
  btn.disabled = true;
  aiOut.textContent = t("llmThinking");
  try {
    const res = await postJSON(path, body);
    const data = await res.json();
    aiOut.textContent = data.rate_limited
      ? "…"
      : data.available
      ? data.text || "—"
      : t("llmOffline");
  } catch {
    aiOut.textContent = t("llmOffline");
  } finally {
    btn.disabled = false;
  }
}

askBtn.addEventListener("click", () => {
  const q = askInput.value.trim();
  if (q) aiCall("/api/ai/answer", { question: q }, askBtn);
});
reassessBtn.addEventListener("click", () => aiCall("/api/ai/reassess", {}, reassessBtn));

// --- risk history chart (feature 11) -------------------------------------
const histBox = document.getElementById("histBox");
const histCount = document.getElementById("histCount");
const histDetail = document.getElementById("histDetail");
let lastHistory = [];
let histSelected = -1;

// Same mapping as the KPI drawer's cCrit/cHigh/cMed/cLow (var(--sev-*)) —
// keep these two in sync; a past drift where MEDIUM was cyan here but
// yellow in the KPI drawer (and LOW green here but cyan there) meant the
// same severity showed two different colors depending which panel you had
// open.
const SEV_COLOR = { CRITICAL: "var(--sev-crit)", HIGH: "var(--sev-high)", MEDIUM: "var(--sev-med)", LOW: "var(--sev-low)", UNKNOWN: "var(--muted)" };
const SEV_KEY = { CRITICAL: "sevCritical", HIGH: "sevHigh", MEDIUM: "sevMedium", LOW: "sevLow", UNKNOWN: "sevUnknown" };

function _histCoords() {
  const pts = lastHistory;
  const W = 100, H = 40, pad = 4;
  const max = Math.max(...pts.map((p) => p.total), 1);
  const step = pts.length > 1 ? (W - pad * 2) / (pts.length - 1) : 0;
  return pts.map((p, i) => {
    const x = pts.length > 1 ? pad + i * step : W / 2;
    const y = H - pad - (p.total / max) * (H - pad * 2);
    return [x, y];
  });
}

// Catmull-Rom -> cubic bezier smoothing so the trend line reads as a
// continuous curve instead of a jagged connect-the-dots line.
function _smoothPath(coords) {
  if (coords.length < 2) return coords.length ? `M${coords[0][0]} ${coords[0][1]}` : "";
  let d = `M${coords[0][0].toFixed(2)} ${coords[0][1].toFixed(2)}`;
  for (let i = 0; i < coords.length - 1; i++) {
    const p0 = coords[i - 1] || coords[i];
    const p1 = coords[i];
    const p2 = coords[i + 1];
    const p3 = coords[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x.toFixed(2)} ${c1y.toFixed(2)} ${c2x.toFixed(2)} ${c2y.toFixed(2)} ${p2[0].toFixed(2)} ${p2[1].toFixed(2)}`;
  }
  return d;
}

function renderHistory() {
  const pts = lastHistory;
  histCount.textContent = `${pts.length} ${t("histRuns")}`;
  if (pts.length < 1) {
    histBox.innerHTML = `<p class="empty-hint">${escapeHtml(t("histEmpty"))}</p>`;
    histDetail.hidden = true;
    return;
  }
  const W = 100, H = 40, pad = 4;
  const max = Math.max(...pts.map((p) => p.total), 1);
  const coords = _histCoords();
  const line = _smoothPath(coords);
  const area = coords.length > 1
    ? `${line} L${coords[coords.length - 1][0].toFixed(2)} ${H - pad} L${coords[0][0].toFixed(2)} ${H - pad} Z`
    : "";
  const dots = coords.map(([x, y], i) => {
    const sel = i === histSelected ? " is-selected" : "";
    return `<g class="hist-pt${sel}" data-idx="${i}" tabindex="0" role="button" aria-label="${escapeHtml(pts[i].ts.slice(0, 10))}">
      <circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="4.2" class="hist-hit"/>
      <circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="1.3" class="hist-dot"/>
    </g>`;
  }).join("");
  histBox.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" class="hist-svg" role="img">
      <defs>
        <linearGradient id="histFade" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--violet)" stop-opacity=".28"/>
          <stop offset="100%" stop-color="var(--violet)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${area ? `<path d="${area}" class="hist-area" fill="url(#histFade)"/>` : ""}
      ${line ? `<path d="${line}" class="hist-line"/>` : ""}
      ${dots}
    </svg>
    <div class="hist-legend"><span>${escapeHtml(pts[0].ts.slice(0, 10))}</span><span>${max} ${escapeHtml(t("findingsUnit"))}</span><span>${escapeHtml(pts[pts.length - 1].ts.slice(0, 10))}</span></div>
    <p class="hist-hint">${escapeHtml(t("histHint"))}</p>`;

  histBox.querySelectorAll(".hist-pt").forEach((el) => {
    el.addEventListener("click", () => selectHistPoint(Number(el.dataset.idx)));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectHistPoint(Number(el.dataset.idx)); }
    });
  });

  if (histSelected >= 0 && histSelected < pts.length) renderHistDetail(histSelected);
}

function selectHistPoint(idx) {
  histSelected = histSelected === idx ? -1 : idx;
  renderHistory();
}

function renderHistDetail(idx) {
  const pts = lastHistory;
  const p = pts[idx];
  if (!p) { histDetail.hidden = true; return; }
  const prev = pts[idx - 1];
  const delta = prev ? p.total - prev.total : null;
  const deltaHtml = delta === null
    ? ""
    : `<span class="hd-delta ${delta > 0 ? "up" : delta < 0 ? "down" : "flat"}">${delta > 0 ? "+" : ""}${delta}</span>`;
  const sev = p.sev || {};
  const total = Object.values(sev).reduce((a, b) => a + b, 0) || p.total || 1;
  const bars = Object.keys(SEV_COLOR).map((k) => {
    const n = sev[k] || 0;
    const pct = total ? Math.round((n / total) * 100) : 0;
    return `<div class="hd-row">
      <span class="hd-label"><span class="hd-swatch" data-color="${escapeHtml(SEV_COLOR[k])}"></span>${escapeHtml(t(SEV_KEY[k]))}</span>
      <div class="hd-track"><div class="hd-fill" data-color="${escapeHtml(SEV_COLOR[k])}" data-pct="${pct}"></div></div>
      <span class="hd-count">${n}</span>
    </div>`;
  }).join("");
  histDetail.hidden = false;
  histDetail.innerHTML = `
    <button type="button" class="hd-close" aria-label="${escapeHtml(t("histClose"))}">×</button>
    <div class="hd-top">
      <div><span class="hd-key">${escapeHtml(t("histPointDate"))}</span><strong dir="ltr">${escapeHtml(p.ts.slice(0, 10))}</strong></div>
      <div><span class="hd-key">${escapeHtml(t("histPointTotal"))}</span><strong>${p.total}</strong></div>
      <div><span class="hd-key">${escapeHtml(t("histPointDelta"))}</span>${prev ? deltaHtml : "—"}</div>
    </div>
    <p class="hd-key hd-breakdown-label">${escapeHtml(t("histPointBreakdown"))}</p>
    ${bars}`;
  histDetail.querySelector(".hd-close").addEventListener("click", () => selectHistPoint(-1));
  _applyBarStyles(histDetail);
}

async function fetchHistory() {
  try {
    const res = await fetch("/api/history");
    lastHistory = (await res.json()).series || [];
    renderHistory();
  } catch {}
}

// --- diff since last scan (feature 9) ------------------------------------
const diffBox = document.getElementById("diffBox");
let lastDiff = null;

function renderDiff() {
  const d = lastDiff;
  if (!d) return diffBox.replaceChildren();
  if (!d.has_previous) {
    diffBox.innerHTML = `<div class="diff-head">${escapeHtml(t("diffTitle"))}</div><p class="empty-hint">${escapeHtml(t("diffNoPrev"))}</p>`;
    return;
  }
  const fmt = (x) => {
    const i = x.indexOf("::");
    return i === -1 ? x : `${x.slice(0, i)} · ${x.slice(i + 2)}`;
  };
  const list = (arr, cls) =>
    arr.length
      ? `<ul class="diff-list ${cls}">${arr.map((x) => `<li dir="auto">${escapeHtml(fmt(x))}</li>`).join("")}</ul>`
      : `<p class="empty-hint">${escapeHtml(t("diffNone"))}</p>`;
  diffBox.innerHTML = `
    <div class="diff-head">${escapeHtml(t("diffTitle"))}</div>
    <div class="diff-col"><span class="diff-label new">▲ ${escapeHtml(t("diffNew"))} (${d.new.length})</span>${list(d.new, "new")}</div>
    <div class="diff-col"><span class="diff-label resolved">▼ ${escapeHtml(t("diffResolved"))} (${d.resolved.length})</span>${list(d.resolved, "resolved")}</div>`;
}

async function fetchDiff() {
  try {
    const res = await fetch("/api/diff");
    lastDiff = await res.json();
    renderDiff();
  } catch {}
}

// --- settings + scheduler (feature 10) -----------------------------------
const intervalSel = document.getElementById("intervalSel");
const schedChk = document.getElementById("schedChk");
const nextRunLine = document.getElementById("nextRunLine");
const saveCfgBtn = document.getElementById("saveCfgBtn");
const runNowBtn = document.getElementById("runNowBtn");
const setMsg = document.getElementById("setMsg");
const startupChk = document.getElementById("startupChk");
const notifyTestBtn = document.getElementById("notifyTestBtn");
const nvdApiKey = document.getElementById("nvdApiKey");
const saveNvdKeyBtn = document.getElementById("saveNvdKeyBtn");
const nvdKeyStatus = document.getElementById("nvdKeyStatus");
const ollamaStatus = document.getElementById("ollamaStatus");
const nvdHelpBtn = document.getElementById("nvdHelpBtn");
const nvdHelpBox = document.getElementById("nvdHelpBox");
const ollamaHelpBtn = document.getElementById("ollamaHelpBtn");
const ollamaHelpBox = document.getElementById("ollamaHelpBox");
let lastAppCfg = null;

function _wireHelpToggle(btn, box) {
  btn.addEventListener("click", () => {
    const show = box.hidden;
    box.hidden = !show;
    btn.setAttribute("aria-expanded", String(show));
  });
}
_wireHelpToggle(nvdHelpBtn, nvdHelpBox);
_wireHelpToggle(ollamaHelpBtn, ollamaHelpBox);

function renderSettings() {
  if (!lastAppCfg) return;
  const cfg = lastAppCfg.config;
  const labels = { 3: "int3", 7: "int7", 14: "int14", 30: "int30" };
  intervalSel.innerHTML = (cfg.allowed_intervals || [3, 7, 14, 30])
    .map((d) => `<option value="${d}">${escapeHtml(t(labels[d] || "int7"))}</option>`)
    .join("");
  intervalSel.value = String(cfg.schedule_interval_days || 7);
  schedChk.checked = !!cfg.schedule_enabled;
  nvdKeyStatus.textContent = cfg.nvd_key_configured ? t("nvdKeyReady") : t("nvdKeyNotSet");
  nvdKeyStatus.className = "set-status " + (cfg.nvd_key_configured ? "ok" : "warn");
  // llm_available auto-updates as soon as Ollama comes up — no manual
  // "connect" step, the periodic poll below just reflects live reality.
  ollamaStatus.textContent = lastAppCfg.llm_available ? t("ollamaConnected") : t("ollamaNotConnected");
  ollamaStatus.className = "set-status " + (lastAppCfg.llm_available ? "ok" : "warn");
  startupChk.checked = !!lastAppCfg.startup_enabled;
  const nr = lastAppCfg.schedule && lastAppCfg.schedule.next_run;
  nextRunLine.textContent = nr ? `${t("nextRun")}: ${nr.slice(0, 16).replace("T", " ")}` : "";
}

async function fetchAppConfig() {
  try {
    const res = await fetch("/api/appconfig");
    lastAppCfg = await res.json();
    renderSettings();
  } catch {}
}

// live auto-detect: Ollama becoming reachable updates the badge on its own,
// no button to click — this is the "auto-connect" mechanism.
setInterval(fetchAppConfig, 6000);

saveCfgBtn.addEventListener("click", async () => {
  setMsg.textContent = "";
  const res = await postJSON("/api/config/save", {
    schedule_interval_days: parseInt(intervalSel.value, 10),
    schedule_enabled: schedChk.checked,
  });
  const data = await res.json();
  lastAppCfg = { config: data.config, schedule: data.schedule };
  renderSettings();
  setMsg.textContent = t("saved");
});

runNowBtn.addEventListener("click", async () => {
  if (!confirm(t("runNowBtn") + " ?")) return;
  await postJSON("/api/schedule/run-now");
  setMsg.textContent = t("started");
});

startupChk.addEventListener("change", async () => {
  const res = await postJSON("/api/startup/toggle", { enabled: startupChk.checked });
  const data = await res.json();
  startupChk.checked = !!data.enabled;
  setMsg.textContent = data.enabled ? t("startupOn") : t("startupOff");
});

notifyTestBtn.addEventListener("click", async () => {
  notifyTestBtn.disabled = true;
  setMsg.textContent = t("llmThinking");
  try {
    const res = await postJSON("/api/notify/test");
    const data = await res.json();
    setMsg.textContent = data.ok ? t("notifySent") : t("notifyFail");
  } finally {
    notifyTestBtn.disabled = false;
  }
});

saveNvdKeyBtn.addEventListener("click", async () => {
  if (!nvdApiKey.value.trim()) return;
  const res = await postJSON("/api/nvd/key", { nvd_api_key: nvdApiKey.value.trim() });
  const data = await res.json();
  if (data.ok) {
    nvdApiKey.value = "";
    await fetchAppConfig();
    setMsg.textContent = t("saved");
  } else {
    setMsg.textContent = t("genericSaveFail");
  }
});

// --- language wiring -----------------------------------------------------
document.querySelectorAll(".lang-opt").forEach((b) =>
  b.addEventListener("click", () => setLang(b.dataset.lang))
);

window.onLangChange = function () {
  document.querySelectorAll(".section-toggle").forEach(updateSectionToggleLabel);
  renderRunStatus();
  renderLog(lastStatus.log || []);
  updateStagesFromLog(lastStatus.log || []);
  btnLabel.textContent = lastStatus.running ? t("running") : t("runScan");
  renderReport();
  renderUpgLog();
  renderUpdateRows();
  renderUpgProgress(lastUpg.progress);
  secBtnLabel.textContent = t("secRun");
  renderSecurity();
  renderHistory();
  renderDiff();
  renderSettings();
  updateKpisFromReport();
  if (lastDecision) {
    renderHealthGauge(lastDecision.health_score);
    renderUrgentBanner(lastDecision.urgent);
  }
};

// --- init ----------------------------------------------------------------
setLang(currentLang);
setView("full");
loadConfig();
poll();
fetchReport();
fetchUpgradeStatus();
fetchHistory();
fetchDiff();
fetchAppConfig();
fetchDecision();
