"""Local-only dashboard for the multi-agent orchestrator.

Security posture (mapped to OWASP Top 10:2021):

  A01 Broken Access Control / CSRF
    - Binds to 127.0.0.1 only, never 0.0.0.0.
    - Host-header allowlist defeats DNS-rebinding: a malicious page that
      rebinds its DNS to 127.0.0.1 still sends its own Host header, which we
      reject.
    - Every state-changing POST requires a same-origin Origin/Referer AND a
      per-process CSRF token minted at startup. A cross-site page cannot read
      the token (we grant no CORS), so it cannot forge these calls. This is
      load-bearing because /api/upgrades/apply installs software.

  A03 Injection
    - winget and the orchestrator run as fixed argv lists — never shell=True,
      never a command built from request data (enforced in the agents too).

  A05 Security Misconfiguration
    - Strict security headers on every response (CSP, nosniff, DENY framing,
      no-referrer, no-store).
    - Request bodies are size-capped and Content-Length is parsed defensively.
"""
import json
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import FROZEN, BASE_DIR as _PROJECT_ROOT, RUNTIME_DIR
from agents import package_manager
from agents import asset_auditor
from agents import analyst
from agents import kev_checker
from agents import decision as decision_agent
import history
import appconfig
import scheduler
import snooze
import update_ignore
import audit
import notify
import startup_shortcut

# APP_DIR: the source "app/" folder in dev, or the frozen-exe's own folder
# (no separate app/ subfolder exists once bundled). STATIC_DIR always comes
# from RUNTIME_DIR — bundled read-only assets in a frozen build (MEIPASS),
# the real app/static in dev. BASE_DIR (persistent user data — report,
# findings JSON, etc.) always sits next to the exe / at the project root.
APP_DIR = _PROJECT_ROOT if FROZEN else RUNTIME_DIR
STATIC_DIR = RUNTIME_DIR / "static"
BASE_DIR = _PROJECT_ROOT
REPORT_PATH = BASE_DIR / "threat_intel_report.md"
FINDINGS_JSON_PATH = BASE_DIR / "threat_intel_findings.json"
# Frozen builds have no standalone main.py to spawn — the exe IS the
# interpreter, so re-invoke it with --run-scan (desktop_app.py's dispatcher
# runs the scan pipeline headlessly for that flag and exits).
_SCAN_CMD = [sys.executable, "--run-scan"] if FROZEN else [sys.executable, "main.py"]
BIND_HOST = "127.0.0.1"
BIND_PORT = 8765

ALLOWED_HOSTS = {f"127.0.0.1:{BIND_PORT}", f"localhost:{BIND_PORT}"}
ALLOWED_ORIGINS = {f"http://127.0.0.1:{BIND_PORT}", f"http://localhost:{BIND_PORT}"}
CSRF_TOKEN = secrets.token_urlsafe(32)
MAX_BODY_BYTES = 64 * 1024

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

STATIC_FILES = {
    "/style.css": "text/css; charset=utf-8",
    "/app.js": "application/javascript; charset=utf-8",
    "/i18n.js": "application/javascript; charset=utf-8",
    "/icons.js": "application/javascript; charset=utf-8",
    "/scene3d.js": "application/javascript; charset=utf-8",
    "/vendor/three.min.js": "application/javascript; charset=utf-8",
    "/favicon.ico": "image/x-icon",
    "/icon.png": "image/png",
}

_state_lock = threading.Lock()
_state = {"running": False, "done": False, "log": [], "exit_code": None, "started_at": None}

_decision_lock = threading.Lock()
_decision_state = {"health_score": None, "items": []}


_VERSION_TAIL_RE = re.compile(r"\s+\d[\w.\-]*$")


def _normalize_product_key(name: str) -> str:
    return _VERSION_TAIL_RE.sub("", name or "").strip().lower()


def _has_available_update(product: str) -> bool:
    """Best-effort cross-reference against the last winget update scan —
    lets the decision tier reflect whether there's actually an update to
    apply, instead of nagging about something with no fix available yet.

    Word-boundary matching, not raw substring: plain `in` containment made
    "Git" match inside "GitHub Desktop" (and "Edge" inside "Microsoft Edge
    WebView2 Runtime"), silently promoting unrelated findings to the urgent
    tier because an unrelated package happened to share a name fragment."""
    key = _normalize_product_key(product)
    if not key:
        return False
    with _upg_lock:
        items = list(_upg_state["items"])
    for it in items:
        it_key = _normalize_product_key(it.get("Name", ""))
        if not it_key:
            continue
        if re.search(rf"\b{re.escape(it_key)}\b", key) or re.search(rf"\b{re.escape(key)}\b", it_key):
            return True
    return False


def _recompute_decision():
    """Run KEV Checker + Decision Agent over the latest findings. Reads the
    structured JSON sidecar (not the markdown report — that's for humans;
    re-parsing it for decision-making broke twice on edge cases markdown
    can't represent safely, like embedded newlines and CVSS attack-vector
    fields)."""
    if not FINDINGS_JSON_PATH.is_file():
        return
    try:
        data = json.loads(FINDINGS_JSON_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    findings = data.get("findings", [])
    for f in findings:
        f["has_update"] = _has_available_update(f.get("product", ""))
    kev_checker.annotate(findings)
    result = decision_agent.decide(findings)
    with _decision_lock:
        _decision_state["health_score"] = result["health_score"]
        _decision_state["items"] = result["items"]


def _urgent_count_and_score() -> tuple[int, int | None]:
    """decision_provider callback for scheduler.py — recomputes fresh off the
    just-written report, then reports (urgent_count, health_score)."""
    _recompute_decision()
    with _decision_lock:
        snoozed = snooze.active_snoozes()
        urgent = [i for i in _decision_state["items"] if i["tier"] == "urgent" and i["id"] not in snoozed]
        return len(urgent), _decision_state["health_score"]


_upg_lock = threading.Lock()
_upg_state = {"running": False, "phase": None, "items": [], "log": [], "results": [], "progress": None}


def _try_start_orchestrator() -> bool:
    """Atomically claim the 'scan running' flag and start the pipeline
    thread. Returns False if a scan is already running (the claim failed),
    so two near-simultaneous triggers can never spawn two subprocesses that
    would clobber threat_intel_findings.json / _report.md concurrently."""
    with _state_lock:
        if _state["running"]:
            return False
        _state["running"] = True
        _state["done"] = False
        _state["log"] = []
        _state["exit_code"] = None
        _state["started_at"] = time.time()
    threading.Thread(target=_run_orchestrator, daemon=True).start()
    return True


def _run_orchestrator():
    # state was claimed + initialized by _try_start_orchestrator() under the
    # lock before this thread started — do NOT re-init here.
    proc = subprocess.Popen(
        _SCAN_CMD,
        cwd=str(APP_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    for line in proc.stdout:
        with _state_lock:
            _state["log"].append(line.rstrip("\n"))
    proc.wait()

    try:
        history.record_current_report()  # feed the risk-history chart + diff
    except Exception:
        pass
    try:
        _recompute_decision()
    except Exception:
        pass

    with _state_lock:
        _state["running"] = False
        _state["done"] = True
        _state["exit_code"] = proc.returncode


def _run_scan():
    with _upg_lock:
        _upg_state.update(running=True, phase="scanning", results=[], log=["scan:start"])
    items = package_manager.scan_upgradable()
    items = [it for it in items if not update_ignore.is_ignored(it.get("Id", ""), it.get("Available", ""))]
    with _upg_lock:
        _upg_state["items"] = items
        _upg_state["running"] = False
        _upg_state["phase"] = "scanned"
        _upg_state["log"].append(f"scan:done:{len(items)}")


_PCT_RE = re.compile(r"(\d{1,3})\s*%")
_ASSUMED_SPEED_BPS = 8 * 1024 * 1024  # 8 MB/s assumption for the ETA estimate

_ai_lock = threading.Lock()
_ai_last_call = {"t": 0.0}
_AI_MIN_INTERVAL = 3.0  # seconds between LLM calls (cost/DoS guard)

_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = {}
RATE_WINDOW_SECS = 10
RATE_MAX_REQUESTS = 20  # generic per-IP ceiling on all state-changing calls


def _rate_limit_ok(addr: str) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(addr, [])
        bucket[:] = [t for t in bucket if now - t < RATE_WINDOW_SECS]
        if len(bucket) >= RATE_MAX_REQUESTS:
            return False
        bucket.append(now)
        return True


def _ai_rate_ok() -> bool:
    with _ai_lock:
        now = time.time()
        if now - _ai_last_call["t"] < _AI_MIN_INTERVAL:
            return False
        _ai_last_call["t"] = now
        return True


def _scan_blocking():
    """Synchronous scan for the scheduler: run the orchestrator once, then
    record history. No shared streaming state (that's the interactive path)."""
    subprocess.run(_SCAN_CMD, cwd=str(APP_DIR),
                   capture_output=True, text=True, timeout=1800)
    try:
        history.record_current_report()
    except Exception:
        pass
    try:
        _recompute_decision()
    except Exception:
        pass


def _set_progress(**kw):
    with _upg_lock:
        cur = _upg_state.get("progress") or {}
        cur.update(kw)
        _upg_state["progress"] = cur


def _run_apply(ids: list[str]):
    with _upg_lock:
        _upg_state.update(running=True, phase="applying", results=[],
                          log=[f"apply:start:{len(ids)}"], progress=None)

    for pkg_id in ids:
        with _upg_lock:
            _upg_state["log"].append(f"apply:running:{pkg_id}")

        details = package_manager.get_details(pkg_id)
        total = details.get("sizeBytes")
        # expected wall-clock: download-at-assumed-speed + fixed install overhead
        expected = (total / _ASSUMED_SPEED_BPS if total else 22) + 8

        shared = {"phase": "downloading", "real_pct": None}

        def on_line(line, _s=shared):
            low = line.lower()
            if "installing" in low or "starting package install" in low:
                _s["phase"] = "installing"
            elif "verif" in low:
                _s["phase"] = "verifying"
            elif "downloading" in low:
                _s["phase"] = "downloading"
            m = _PCT_RE.search(line)
            if m:
                _s["real_pct"] = max(0, min(100, int(m.group(1))))

        holder = {}

        def worker():
            holder["res"] = package_manager.apply_update(pkg_id, on_line=on_line)

        _set_progress(id=pkg_id, percent=0, phase="downloading",
                      sizeText=details.get("sizeText"), publisher=details.get("publisher"),
                      etaSec=round(expected))
        th = threading.Thread(target=worker, daemon=True)
        start = time.time()
        th.start()
        while th.is_alive():
            elapsed = time.time() - start
            if shared["real_pct"] is not None:
                pct = shared["real_pct"]
            else:
                pct = min(int(elapsed / expected * 100), 97)  # estimate, capped
            eta = max(round(expected - elapsed), 0) if pct < 99 else 0
            _set_progress(id=pkg_id, percent=pct, phase=shared["phase"],
                          sizeText=details.get("sizeText"), publisher=details.get("publisher"),
                          etaSec=eta)
            time.sleep(0.4)
        th.join()

        result = holder.get("res", {"id": pkg_id, "ok": False, "message": "no result"})
        _set_progress(id=pkg_id, percent=100, phase="done", etaSec=0,
                      sizeText=details.get("sizeText"), publisher=details.get("publisher"))
        with _upg_lock:
            _upg_state["results"].append(result)
            _upg_state["log"].append(f"apply:{'ok' if result['ok'] else 'fail'}:{pkg_id}:{result['message']}")

    with _upg_lock:
        _upg_state["running"] = False
        _upg_state["phase"] = "applied"
        _upg_state["progress"] = None
        any_ok = any(r.get("ok") for r in _upg_state["results"])

    if any_ok:
        # a package version just changed under us — the urgent list still
        # reflects CVEs matched against the OLD version until a fresh full
        # scan runs. Auto-trigger one (atomic claim; no-op if one is
        # already running) so "already updated" software stops showing as
        # still-urgent without the user manually re-scanning.
        _try_start_orchestrator()


class Handler(BaseHTTPRequestHandler):
    # ---- security helpers -------------------------------------------------

    def _secure_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def _csrf_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return False
        referer = self.headers.get("Referer")
        if origin is None and referer is not None:
            if not any(referer == o or referer.startswith(o + "/") for o in ALLOWED_ORIGINS):
                return False
        token = self.headers.get("X-CSRF-Token", "")
        return secrets.compare_digest(token, CSRF_TOKEN)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        return self.rfile.read(length) if length else b""

    # ---- response helpers -------------------------------------------------

    def _json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._secure_headers()
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel_path: str, content_type: str):
        target = (STATIC_DIR / rel_path).resolve()
        if STATIC_DIR not in target.parents and target != STATIC_DIR:
            self.send_error(403)
            return
        if not target.is_file():
            self.send_error(404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._secure_headers()
        self.end_headers()
        self.wfile.write(body)

    # ---- routing ----------------------------------------------------------

    def do_GET(self):
        if not self._host_ok():
            self.send_error(421, "Misdirected Request")
            return

        if self.path in ("/", "/index.html"):
            self._static("index.html", "text/html; charset=utf-8")
        elif self.path in STATIC_FILES:
            self._static(self.path.lstrip("/"), STATIC_FILES[self.path])
        elif self.path == "/api/config":
            self._json({"csrfToken": CSRF_TOKEN, "defaultLang": "ar"})
        elif self.path == "/api/status":
            with _state_lock:
                state = dict(_state)
            state["inventory"] = asset_auditor.inventory_status()
            state["elapsed_secs"] = round(time.time() - state["started_at"]) if state.get("running") and state.get("started_at") else 0
            self._json(state)
        elif self.path == "/api/inventory":
            self._json(asset_auditor.inventory_status())
        elif self.path == "/api/report":
            if REPORT_PATH.is_file():
                self._json({"content": REPORT_PATH.read_text(encoding="utf-8")})
            else:
                self._json({"content": None})
        elif self.path == "/api/upgrades/status":
            with _upg_lock:
                self._json(dict(_upg_state))
        elif self.path == "/api/history":
            self._json({"series": history.series()})
        elif self.path == "/api/diff":
            self._json(history.diff_last_two())
        elif self.path == "/api/decision":
            with _decision_lock:
                items = list(_decision_state["items"])
                score = _decision_state["health_score"]
            snooze.clear_expired()  # expiry alone re-surfaces the item next poll; nothing executes
            snoozed = snooze.active_snoozes()
            urgent = [i for i in items if i["tier"] == "urgent" and i["id"] not in snoozed]
            self._json({"health_score": score, "items": items, "urgent": urgent})

        elif self.path == "/api/audit/verify":
            self._json(audit.verify_chain())

        elif self.path == "/api/inventory/status":
            self._json(asset_auditor.inventory_status())

        elif self.path == "/api/appconfig":
            self._json({
                "config": appconfig.public_config(),
                "schedule": scheduler.status(),
                "llm_available": analyst.is_available(),
                "startup_enabled": startup_shortcut.is_enabled(),
            })
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._host_ok():
            self.send_error(421, "Misdirected Request")
            return
        if not _rate_limit_ok(self.client_address[0]):
            self._json({"status": "rate_limited"}, 429)
            return
        if not self._csrf_ok():
            self._json({"status": "forbidden"}, 403)
            return

        if self.path == "/api/run":
            if _try_start_orchestrator():
                self._json({"status": "started"})
            else:
                self._json({"status": "already_running"})

        elif self.path == "/api/security/run":
            # lazy import breaks the server<->golden_dataset import cycle
            from tests import golden_dataset
            results = golden_dataset.run_all()
            summary = golden_dataset.summarize(results)
            golden_dataset.build_reports(results, summary)
            self._json({"summary": summary, "results": results})

        elif self.path in ("/api/ai/explain", "/api/ai/answer", "/api/ai/reassess"):
            if not _ai_rate_ok():
                self._json({"available": True, "text": "", "rate_limited": True}, 429)
                return
            raw = self._read_body()
            try:
                body = json.loads(raw or b"{}") if raw is not None else {}
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            if self.path == "/api/ai/explain":
                self._json(analyst.explain(str(body.get("id", ""))[:60],
                                           str(body.get("severity", ""))[:20],
                                           str(body.get("desc", ""))[:2000]))
            elif self.path == "/api/ai/answer":
                report = REPORT_PATH.read_text(encoding="utf-8") if REPORT_PATH.is_file() else ""
                self._json(analyst.answer(str(body.get("question", "")), report))
            else:  # reassess
                text = REPORT_PATH.read_text(encoding="utf-8") if REPORT_PATH.is_file() else ""
                self._json(analyst.reassess(history.parse_findings(text)))

        elif self.path == "/api/decision/snooze":
            raw = self._read_body()
            try:
                body = json.loads(raw or b"{}") if raw is not None else {}
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            finding_id = body.get("id")
            remind_at = body.get("remindAt")
            if not isinstance(finding_id, str) or not isinstance(remind_at, str):
                self._json({"status": "bad_request"}, 400)
                return
            with _decision_lock:
                known_ids = {i["id"] for i in _decision_state["items"]}
            if finding_id not in known_ids:
                self._json({"status": "unknown_finding"}, 400)
                return
            ok = snooze.snooze_until(finding_id, remind_at)
            self._json({"status": "ok" if ok else "invalid_date"})

        elif self.path == "/api/startup/toggle":
            raw = self._read_body()
            try:
                body = json.loads(raw or b"{}") if raw is not None else {}
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            want_enabled = bool(body.get("enabled"))
            ok = startup_shortcut.enable() if want_enabled else startup_shortcut.disable()
            self._json({"ok": ok, "enabled": startup_shortcut.is_enabled()})

        elif self.path == "/api/notify/test":
            ok = notify.send("Threat Intel Agent", "هذا إشعار اختبار — الإشعارات تعمل بنجاح.")
            self._json({"ok": ok})

        elif self.path == "/api/nvd/key":
            raw = self._read_body()
            try:
                body = json.loads(raw or b"{}") if raw is not None else {}
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            self._json({"ok": appconfig.save_nvd_api_key(body.get("nvd_api_key", ""))})

        elif self.path == "/api/config/save":
            raw = self._read_body()
            try:
                body = json.loads(raw or b"{}") if raw is not None else {}
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            if not isinstance(body, dict):
                self._json({"status": "bad_request"}, 400)
                return
            self._json({"config": appconfig.save_public_config(body),
                        "schedule": scheduler.status()})

        elif self.path == "/api/schedule/run-now":
            threading.Thread(target=lambda: scheduler.run_cycle_now(_scan_blocking, _urgent_count_and_score),
                             daemon=True).start()
            self._json({"status": "started"})

        elif self.path == "/api/upgrades/details":
            raw = self._read_body()
            if raw is None:
                self._json({"status": "bad_request"}, 400)
                return
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            pkg_id = body.get("id")
            if not isinstance(pkg_id, str):
                self._json({"status": "bad_request"}, 400)
                return
            self._json(package_manager.get_details(pkg_id))

        elif self.path == "/api/upgrades/scan":
            with _upg_lock:
                already = _upg_state["running"]
            if already:
                self._json({"status": "already_running"})
                return
            threading.Thread(target=_run_scan, daemon=True).start()
            self._json({"status": "started"})

        elif self.path == "/api/upgrades/apply":
            raw = self._read_body()
            if raw is None:
                self._json({"status": "bad_request"}, 400)
                return
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            ids = body.get("ids")
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                self._json({"status": "bad_request"}, 400)
                return
            with _upg_lock:
                already = _upg_state["running"]
                known_ids = {it["Id"] for it in _upg_state["items"]}
            if already:
                self._json({"status": "already_running"})
                return
            requested = [i for i in ids if i in known_ids]
            if not requested:
                self._json({"status": "no_valid_ids"}, 400)
                return
            threading.Thread(target=_run_apply, args=(requested,), daemon=True).start()
            self._json({"status": "started", "count": len(requested)})

        elif self.path == "/api/upgrades/ignore":
            raw = self._read_body()
            if raw is None:
                self._json({"status": "bad_request"}, 400)
                return
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            pkg_id = body.get("id")
            if not isinstance(pkg_id, str):
                self._json({"status": "bad_request"}, 400)
                return
            with _upg_lock:
                match = next((it for it in _upg_state["items"] if it.get("Id") == pkg_id), None)
            if not match:
                self._json({"status": "not_found"}, 404)
                return
            update_ignore.ignore(pkg_id, match.get("Available", ""))
            with _upg_lock:
                _upg_state["items"] = [it for it in _upg_state["items"] if it.get("Id") != pkg_id]
            self._json({"status": "ok"})

        elif self.path == "/api/upgrades/unignore":
            # unignore() existed and was tested but had no route — a user
            # who dismissed an update by mistake had no way back short of
            # editing ignored_updates.json by hand.
            raw = self._read_body()
            if raw is None:
                self._json({"status": "bad_request"}, 400)
                return
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json({"status": "bad_request"}, 400)
                return
            pkg_id = body.get("id")
            if not isinstance(pkg_id, str):
                self._json({"status": "bad_request"}, 400)
                return
            update_ignore.unignore(pkg_id)
            self._json({"status": "ok"})

        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass  # keep the console clean; audit.log already covers this


def main() -> None:
    appconfig.lock_secrets_file()  # best-effort ACL restriction to current user
    # rebuild the decision/urgent state from the last scan's findings on disk,
    # so the urgent banner + KPI breakdowns are populated immediately on
    # restart instead of staying empty until the user runs a fresh scan.
    try:
        _recompute_decision()
    except Exception:
        pass
    scheduler.start(_scan_blocking, _urgent_count_and_score)  # periodic auto-scan + toast notification
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print(f"Dashboard running at http://{BIND_HOST}:{BIND_PORT}  (local only)")
    server.serve_forever()


if __name__ == "__main__":
    main()
