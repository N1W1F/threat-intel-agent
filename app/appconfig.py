"""Config + secrets loading, kept strictly separate.

  config.local.json   — non-secret settings (interval, model name, feature
                        toggles). Safe to read into API.
  secrets.local.json  — NVD API key, optional LLM base url override. NEVER
                        returned by any API, never logged, never packaged.

Both files are optional; sensible defaults apply so the app runs with zero
config (AI features simply stay disabled until configured).
"""
import json
from pathlib import Path

import secure_secrets
from security import FROZEN, BASE_DIR as _PROJECT_ROOT, RUNTIME_DIR

# In a frozen build there's no separate "app/" folder distinct from the
# project root (everything is bundled into the .exe) — config/secrets sit
# next to the exe. In dev mode this stays exactly app/config.local.json,
# unchanged from before.
APP_DIR = _PROJECT_ROOT if FROZEN else RUNTIME_DIR
CONFIG_PATH = APP_DIR / "config.local.json"
SECRETS_PATH = APP_DIR / "secrets.local.json"

_DEFAULT_CONFIG = {
    "llm_enabled": True,
    "llm_model": "llama3.2",
    "llm_host": "http://localhost:11434",
    "schedule_enabled": False,
    "schedule_interval_days": 7,
}

# only these keys may ever be exposed through the API (no secrets)
PUBLIC_CONFIG_KEYS = {
    "llm_enabled", "llm_model", "schedule_enabled", "schedule_interval_days",
}

ALLOWED_INTERVALS = (3, 7, 14, 30)


def _load(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def load_config() -> dict:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update({k: v for k, v in _load(CONFIG_PATH).items() if k in _DEFAULT_CONFIG})
    # clamp interval to an allowed value
    if cfg.get("schedule_interval_days") not in ALLOWED_INTERVALS:
        cfg["schedule_interval_days"] = 7
    return cfg


def load_secrets() -> dict:
    """The NVD API key is transparently DPAPI-decrypted if it was stored
    encrypted (see secure_secrets.py / encrypt_secrets.py). Plaintext values
    still work, so a fresh secrets.local.json continues to function until
    the user runs the one-time encryption helper."""
    secrets = _load(SECRETS_PATH)
    value = secrets.get("nvd_api_key")
    if isinstance(value, str) and secure_secrets.is_encrypted(value):
        secrets["nvd_api_key"] = secure_secrets.decrypt(value)
    return secrets


def public_config() -> dict:
    """Config safe to hand to the frontend — secrets excluded by construction."""
    cfg = load_config()
    out = {k: cfg[k] for k in PUBLIC_CONFIG_KEYS if k in cfg}
    out["allowed_intervals"] = list(ALLOWED_INTERVALS)
    secrets = load_secrets()
    out["nvd_key_configured"] = bool(secrets.get("nvd_api_key"))
    return out


def lock_secrets_file() -> None:
    """Best-effort ACL restriction to the current user, run automatically at
    server startup so protection doesn't depend on remembering to run the
    manual encrypt_secrets.py migration."""
    import os
    import subprocess
    import sys as _sys
    if _sys.platform != "win32" or not SECRETS_PATH.is_file():
        return
    try:
        subprocess.run(
            ["icacls", str(SECRETS_PATH), "/inheritance:r", "/grant:r", f"{os.getlogin()}:F"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def save_public_config(updates: dict) -> dict:
    """Persist only whitelisted non-secret keys from a client update.

    Every key is type-checked before it touches disk — a malformed value
    (e.g. llm_model as an object, llm_enabled as a string) would otherwise
    get written verbatim and only surface later as an opaque failure when
    analyst.py hands it to Ollama's JSON payload."""
    cfg = _load(CONFIG_PATH)
    for k, v in updates.items():
        if k not in PUBLIC_CONFIG_KEYS:
            continue
        if k == "schedule_interval_days":
            v = v if v in ALLOWED_INTERVALS else 7
        elif k in ("llm_enabled", "schedule_enabled"):
            if not isinstance(v, bool):
                continue
        elif k == "llm_model":
            if not isinstance(v, str) or not v.strip() or len(v) > 100:
                continue
            v = v.strip()
        cfg[k] = v
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return public_config()


def save_nvd_api_key(api_key: str) -> bool:
    """NVD API keys are UUID-shaped, free, tied only to an email sign-up —
    lower sensitivity than a mail password, but still DPAPI-protected at
    rest and never returned by any API for consistency."""
    if not isinstance(api_key, str) or not api_key.strip() or len(api_key) > 200:
        return False
    secrets = _load(SECRETS_PATH)
    secrets["nvd_api_key"] = secure_secrets.encrypt(api_key.strip())
    SECRETS_PATH.write_text(json.dumps(secrets, ensure_ascii=False, indent=2), encoding="utf-8")
    lock_secrets_file()
    return True
