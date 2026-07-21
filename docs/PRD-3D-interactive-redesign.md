# PRD — Full UI/UX Redesign: 3D Dynamic Interactive Interface

Status: DRAFT — awaiting decision on Section 4 (tier A vs B) before implementation starts.
Scope: `app/static/` only (index.html, app.js, i18n.js, icons.js, style.css). No backend/agent changes beyond what's already fixed (Section 1).

---

## 1. Audit results (completed this pass)

Two independent full-codebase audits (backend + frontend, run in parallel, plus a third independent frontend pass) were run before any redesign work. Findings, and what was actually fixed:

### Fixed
| # | Severity | Bug | Fix |
|---|----------|-----|-----|
| 1 | **CRITICAL** | Every colored/sized bar in the app (KPI health/findings/critical/assets breakdown bars, history-detail severity bars) was rendered via `style="background:...;width:...%"` inside `innerHTML` strings. The app's own CSP is `style-src 'self'` (no `unsafe-inline`) — the browser silently drops all inline `style=` attributes. Every bar has been rendering at **zero width, no color** since the feature shipped earlier this session. | Rewrote `_bar()` and the history-detail renderer to emit `data-color`/`data-pct` attributes, then apply them via `.style.setProperty()` (a CSSOM call, CSP-exempt — same pattern already used correctly for `.upd-prog-fill` and the KPI card accent strips). Verified live: bars now render real color and real width. |
| 2 | HIGH | `server.py::_has_available_update()` used raw substring matching (`it_key in key or key in it_key`) to cross-reference a CVE-finding's product name against the winget update scan. `"git" in "github desktop"` → `True`. A package whose name is a short substring of an unrelated package's name got falsely marked `has_update=True`, which can promote an unrelated CRITICAL finding to the URGENT decision tier. | Switched to word-boundary regex matching (`\bkey\b`). Verified: "Git" no longer matches "GitHub Desktop"; legitimate matches ("Docker Desktop" vs "Docker Desktop 4.82.0") still work. |
| 3 | HIGH | `#runStatus`'s status dot never changed color. CSS styled `[data-state="running/done/error"]`; JS only ever toggled `.is-running`/`.is-error` classes that no CSS rule targets. The amber-pulse/green/red visual cue for scan state has never worked. | JS now sets `runStatus.dataset.state` directly to `"ready"/"running"/"done"/"error"`, matching the existing CSS. |
| 4 | MEDIUM | `appconfig.save_public_config()` had zero type validation on `llm_model`/`llm_enabled`/`schedule_enabled` before writing to disk — a malformed POST body corrupts `config.local.json` and surfaces later as an opaque Ollama failure instead of a clean rejection at the trust boundary. | Added type checks (bool for the two `_enabled` flags, non-empty string ≤100 chars for `llm_model`); malformed values are now silently dropped instead of persisted. |
| 5 | MEDIUM | `update_ignore.unignore()` existed and was unit-tested but had no HTTP route — a user who dismissed an update by mistake had no way back except hand-editing `ignored_updates.json`. | Added `POST /api/upgrades/unignore`. (Frontend UI to browse/restore the ignored list is a redesign-phase item — see Section 6.) |
| 6 | MEDIUM | `runBtn`/`scanBtn` click handlers didn't disable synchronously — only `poll()`'s first response (≥800ms later) disabled them, leaving a real double-click window that fires two overlapping scans. | Both buttons now disable in the same synchronous tick as the click. |
| 7 | MEDIUM | `poll()` had no error handling. A network hiccup or backend restart mid-scan left the UI permanently stuck on "Running…" with a spinning spinner and no recovery short of a manual reload. | Added try/catch: on failure, polling stops, the button re-enables, and the status text switches to the existing "failed" string. |
| 8 | LOW | `renderHealthGauge(null)` reset the ring's fill/offset but not its stroke *color* — after a red/danger-colored run, a subsequent null state showed a full grey-track ring still tinted from the last real score. | Explicit `stroke = var(--muted)` reset added. |
| 9 | LOW | 6 dead i18n keys (`byPublisher`, `urgentSnooze`, `snoozeCustom`, `langName`, `summaryHeading`, `tokenLoading`) defined in both locales, referenced nowhere. | Removed from `i18n.js`. |

### Reported, deliberately deferred to the redesign (not "bugs," design debt that the redesign supersedes anyway)
- Native `confirm()` dialogs on the updates tab are visually inconsistent with the rest of the app's custom-styled surfaces.
- No retry affordance on a failed individual update row (only "Ignore").
- Several `fetch()` calls elsewhere (`fetchReport`, `fetchUpgradeStatus`, settings-save handlers) still lack try/catch. Lower urgency than `poll()` since they don't leave the UI in a stuck-spinner state, but should be swept during the redesign since most of this code is being rewritten anyway.
- KPI info-dot (`؟`) is `aria-hidden`, so screen readers get "button, collapsed" with no hint that expandable detail exists.
- Dead CSS rules (`.inv-status-line`, `.inv-excluded-toggle`, `.inv-excluded-list`) — harmless, will be deleted naturally when `style.css` is rewritten.

### Fake/mocked/hardcoded data audit — RESULT: NONE FOUND
Three independent audit passes traced every number displayed anywhere in the UI back to a real `fetch()` response or a computation over one (`parseReport`, `severityCounts`, `_histCoords`, `_decisionBreakdown`). No hardcoded KPI values, no canned report content, no stubbed API responses, no synthetic chart data. `inventory.example.txt` is correctly isolated from `inventory.txt` and only used as a documentation template, never loaded. `/api/security/run` runs the real 126-test suite live, not canned output. **Confirmed: the program does not display or read fake data anywhere.**

Post-fix verification: `python app/tests/golden_dataset.py` → 126/126, 100%, twice in a row (including inside the same long-lived process, the exact scenario a prior session bug broke — still clean).

---

## 2. Why this document exists

You asked for the whole UI redesigned to be "3D dynamic interactive," using "any tool or library needed." Before writing code, one real constraint has to be resolved with you, because it changes the entire technical approach:

**This app is a local security scanner with a deliberately locked-down CSP** (`default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; ...` — no external origins allowed anywhere, established and load-bearing since early in this project). That's not a style choice — it's the actual security posture of a tool whose entire job is auditing what's installed on your machine offline.

"Use any library" from the open web (Three.js/GSAP/etc. via CDN `<script src="https://...">`) would violate that CSP and get blocked outright — or would require weakening the CSP, which is a real security regression for a security tool.

**The resolvable version of this**: any JS library can still be used if it's downloaded once and vendored as a local file under `app/static/`, served from `'self'`. That's fully CSP-compliant and works 100% offline (no install-time internet dependency for end users — the file ships inside the .exe). The only costs are the packaged .exe's size (currently ~14MB) and one more file to keep updated for security patches.

This is a real tradeoff, not a technical blocker, so Section 4 below gives you both options concretely instead of me picking silently.

---

## 3. Design language (applies to either tier)

Keep everything that already works well and is distinctive to this app — don't throw out the identity, evolve it:

- **Palette**: dark purple/near-black base (`#0a0612`→`#150d22`) + blood-red danger accent (`#c0121f`/`#ff4d5e`) + violet primary (`#a855f7`) + cyan/amber/green semantic complements. This "HTB CyberDefender" identity is good and should carry into the 3D redesign, not be replaced by a generic dark theme.
- **Typography**: `Segoe UI` for UI chrome, `Cascadia Mono` for data/CVE/version strings (terminal feel for security data) — no external fonts (CSP `font-src` isn't even in the allowlist; adding one means loading local font files, still zero network).
- **RTL/LTR**: Arabic is the default language, fully RTL, and this cannot regress. Every 3D/motion element must mirror correctly in RTL and stay legible with Arabic text (no text distorted by 3D perspective transforms — 3D effects apply to *containers/backgrounds*, never to typographic content itself).
- **Motion philosophy**: purposeful, not decorative. Every animation should communicate state (scanning in progress, severity level, data changing) — not spin for its own sake. `prefers-reduced-motion` must be respected everywhere (already the pattern in the current CSS).
- **Density**: this is a SOC dashboard, not a marketing site. 3D flourishes go on hero/summary elements (KPI cards, health gauge, background) — the dense data tables (report list, security test table, update rows) stay flat, fast, and scannable. 3D-everywhere hurts a tool people use to make real decisions quickly.

---

## 4. Two implementation tiers — pick one

### Tier A — CSS 3D + Canvas/SVG, zero new dependencies
Real 3D using only what ships with every browser: CSS `perspective`/`transform-style: preserve-3d`/`rotateX/Y/Z`/`translateZ`, plus hand-written Canvas2D for particle/background effects, plus SVG for data viz (already the pattern for the health gauge and risk-history chart).

**What this buys you:**
- KPI cards get real depth: perspective tilt on hover/focus (card leans toward cursor, layered inner elements at different Z-depths — number "floats" above the card face), animated flip-to-reveal for the detail drawer instead of the current slide-down.
- Health gauge becomes a genuinely 3D rotating dial (SVG + CSS 3D transform on a `<canvas>` or layered SVG rings) instead of a flat 2D ring.
- Ambient background: a lightweight Canvas2D particle field (representing network/scan activity) with depth-of-field via size/opacity falloff — fully custom, tunable to exactly the SOC aesthetic, ~150 lines of vanilla JS, no library weight at all.
- Sidebar icon rail: 3D depth-press effect on click (translateZ + shadow), tab transitions as a 3D card-flip between panels.
- Risk-history chart: extrude the existing line chart into a 3D ribbon (perspective + layered paths) instead of flat SVG.

**Cost**: zero KB added to the exe. More hand-written code (I'm writing the 3D math/easing myself instead of calling a library API), but it's all code I have full control over and can make CSP/RTL/perf-correct from scratch.

**Ceiling**: this won't produce true lit/shaded 3D geometry (no real lighting model, no depth-tested overlapping meshes) — it's convincing layered-perspective 3D, the same technique used in most "3D card" web UIs, not a 3D game engine's output.

### Tier B — Vendored Three.js (local file, not CDN), real WebGL
Download Three.js once (`three.min.js`, ~180KB minified+gzipped for a slim build), commit it to `app/static/vendor/three.min.js`, reference it as `<script src="vendor/three.min.js">` — fully local, fully CSP-compliant, zero network calls at runtime.

**What this buys you beyond Tier A:**
- A genuine lit, textured, depth-tested 3D scene is possible — e.g., a real rotating 3D "risk sphere" with individual glowing nodes per finding (position = severity/age, color = tier), true camera controls, real shadows/bloom.
- Reusable for future features (a literal 3D network map of scanned assets, if ever wanted).

**Cost**:
- Adds ~180-600KB to the shipped .exe depending on which Three.js modules are bundled (postprocessing/bloom effects add more).
- A real WebGL context has real GPU/battery cost — on a background security-scanning tool that's meant to feel lightweight and trustworthy, a spinning WebGL scene competing for GPU with the actual scan work is a real tradeoff to weigh.
- More moving parts to keep CSP-compliant (WebGL itself doesn't violate CSP, but any texture/shader loaded from a URL would need to also be local — need to audit this at implementation time).
- Larger attack surface in the literal sense: Three.js is ~50k lines of code now living inside a security tool's trust boundary; needs to be kept patched.

### Recommendation
**Tier A.** This app's whole value proposition is "runs 100% locally, doesn't need internet, small trustworthy footprint, security tool." Bundling a 3rd-party WebGL library — even locally vendored — cuts against that identity for a visual upgrade Tier A can deliver 80% of at 0% of the cost. Tier A's ceiling is genuinely high for a dashboard (perspective-tilt cards + Canvas particle fields + 3D gauges look excellent in practice, this is a well-worn pattern in premium SaaS dashboards).

I'll implement Tier A unless you tell me otherwise.

---

## 5. Concrete redesign spec (Tier A)

| Area | Current | Redesign |
|---|---|---|
| KPI row | Flat cards, colored top-strip (今 fixed this session) | 3D perspective container (`perspective: 1200px` on `.kpi-row`); each card tilts toward pointer on hover (`rotateX/rotateY` driven by mouse position, clamped ±8°), number sits on a `translateZ(24px)` layer so it visually "lifts" off the card face on hover, spring-eased back to flat on mouseleave. Click-to-expand becomes a 3D flip (card rotates on Y-axis to reveal the detail drawer as its "back face") instead of the current slide-down panel, OR the drawer stays as-is if a flip proves disorienting for RTL — validate in-browser before committing. |
| Health gauge | Flat 2D SVG ring | Layered SVG rings at different `translateZ` depths inside a `perspective` container, subtle continuous slow rotation (pauses on `prefers-reduced-motion`), depth-based blur on background rings for a real focal-depth read. |
| Background | Flat CSS gradient mesh (existing `body::before`) | Canvas2D particle field: sparse nodes drifting slowly, size/opacity by simulated depth, subtle connective lines between nearby nodes (classic "network" look, fits a security tool's theme literally). Must stay under ~2% CPU idle — cap particle count, use `requestAnimationFrame` throttling, pause when tab is hidden (`document.visibilitychange`). |
| Sidebar / tab switching | Flat icon rail, CSS class toggle + scrollIntoView flash (added earlier this session) | Icons get a pressed-3D depth effect (`translateZ` + shadow contraction) on click; tab content transition becomes a 3D card-swap (outgoing panel rotates away on Y-axis while incoming rotates in) replacing the current flash-highlight. |
| Risk-history chart | Flat SVG line + gradient fill (built this session) | Same data, rendered as a 3D ribbon: extrude the line along a shallow Z-axis using layered SVG paths at incremental depths + perspective on the container, so the trend reads as a physical ribbon rather than a flat line. Click-to-inspect point behavior unchanged. |
| Urgent banner | Flat red panel | Adds a subtle pulsing depth (translateZ breathing animation, ties into existing pulse keyframe) to reinforce urgency without being a new animation language. |
| Report/update lists, security test table | Flat | **Unchanged** — dense data tables stay flat and fast per the density principle in Section 3. |

All of the above respect `prefers-reduced-motion: reduce` by disabling perspective/rotation/particle-motion and falling back to the current flat presentation instantly (no JS branching needed beyond what the existing CSS media query pattern already does).

---

## 6. Explicitly out of scope for this pass
- Retry button for failed individual updates, ignored-updates management panel, native-`confirm()`→custom-dialog replacement — real UX gaps found in the audit, but net-new interaction design, not "redesign the existing thing." Will be naturally addressed as those components get rebuilt during the redesign, but not treated as launch-blocking for it.
- Any backend/agent logic change beyond the fixes already applied in Section 1.
- Three.js/WebGL (Tier B) unless you override the recommendation.

---

## 7. Rollout plan
1. Rebuild `style.css` incrementally per-section (KPI row → gauge → background → sidebar/tabs → history chart → banner), verifying each in the live preview (screenshot + console/network check) before moving to the next, in both AR and EN, both light desktop and the app's actual window size.
2. Re-run `golden_dataset.py` after each section (pure CSS/JS changes shouldn't touch backend tests, but cheap to verify nothing broke).
3. Rebuild `.exe` + share package once the full redesign is verified end-to-end.

## 8. Success criteria
- Visually distinctive, "expensive-feeling" 3D-interactive dashboard that a bootcamp reviewer or portfolio visitor immediately reads as more polished than a typical AI-generated admin panel.
- Zero CSP violations, zero new console errors, zero regressions in the 126-test Golden Dataset suite.
- RTL Arabic remains fully correct and equally polished — not an afterthought retrofit.
- No perceptible performance cost: idle CPU stays low, animations respect `prefers-reduced-motion`, app still feels like a lightweight local tool, not a laggy web demo.
