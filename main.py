import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()
UI_CONFIG_FILE = Path(os.getenv("UI_CONFIG_FILE", "./data/ui-config.json"))


def load_startup_ui_config() -> Dict[str, Any]:
    if not UI_CONFIG_FILE.exists():
        return {}
    try:
        with UI_CONFIG_FILE.open("r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Unable to load UI configuration") from exc
    if not isinstance(config, dict):
        raise RuntimeError("UI configuration must be a JSON object")
    return config


STARTUP_UI_CONFIG = load_startup_ui_config()

# ---------------------------------------------------------------------------
# Setup logs folder
# ---------------------------------------------------------------------------

AUDIT_LOG_FILE = os.getenv(
    "AUDIT_LOG_FILE",
    "/tmp/pii-guardrail-logs/redactions.jsonl"
)

# Ensure the log directory exists
log_path = Path(AUDIT_LOG_FILE)
log_path.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
configured_vllm_base_url = STARTUP_UI_CONFIG.get(
    "VLLM_BASE_URL", os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1")
)
if not isinstance(configured_vllm_base_url, str) or not configured_vllm_base_url.strip():
    raise RuntimeError("VLLM_BASE_URL must be a non-empty URL string in ui-config.json or the environment.")
VLLM_BASE_URL = configured_vllm_base_url.strip().rstrip("/")
VLLM_API_KEY = STARTUP_UI_CONFIG.get("VLLM_API_KEY", os.getenv("VLLM_API_KEY", ""))
if not isinstance(VLLM_API_KEY, str):
    raise RuntimeError("VLLM_API_KEY must be a string in ui-config.json or the environment.")
configured_proxy_api_key = STARTUP_UI_CONFIG.get("PROXY_API_KEY", os.getenv("PROXY_API_KEY", ""))
if not isinstance(configured_proxy_api_key, str):
    raise RuntimeError("PROXY_API_KEY must be a string in ui-config.json or the environment.")
PROXY_API_KEY = configured_proxy_api_key.strip()
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "/tmp/pii-guardrail-logs/redactions.jsonl")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "300"))
STREAM_HOLD_BACK = int(os.getenv("STREAM_HOLD_BACK", "512"))
UI_ACCESS_KEY = os.getenv("UI_ACCESS_KEY", "")
UI_SESSION_SECONDS = 12 * 60 * 60

print(VLLM_BASE_URL)
logging.info(VLLM_BASE_URL)

startup_config = {
    "VLLM_BASE_URL": VLLM_BASE_URL,
    "VLLM_API_KEY": VLLM_API_KEY,
    "PROXY_API_KEY": PROXY_API_KEY,
    "AUDIT_LOG_FILE": AUDIT_LOG_FILE,
    "UPSTREAM_TIMEOUT": UPSTREAM_TIMEOUT,
    "STREAM_HOLD_BACK": STREAM_HOLD_BACK,
}
startup_config_hash = hashlib.sha256(
    json.dumps(startup_config, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
print(f"Startup configuration SHA-256: {startup_config_hash}")

if not PROXY_API_KEY or PROXY_API_KEY == "change-me":
    raise RuntimeError("Set a strong PROXY_API_KEY in ui-config.json or the environment.")
if not VLLM_API_KEY:
    raise RuntimeError("Set VLLM_API_KEY in ui-config.json or the environment.")


# ---------------------------------------------------------------------------
# Audit log: deliberately records metadata only, never matched values.
# ---------------------------------------------------------------------------
audit_path = Path(AUDIT_LOG_FILE)
audit_path.parent.mkdir(parents=True, exist_ok=True)

audit_logger = logging.getLogger("pii_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False
if not audit_logger.handlers:
    handler = logging.FileHandler(audit_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)


def audit_redactions(direction: str, counts: Counter) -> None:
    for reason, count in counts.items():
        if count:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "direction": direction,
                "reason": reason,
                "count": count,
            }
            audit_logger.info(json.dumps(record, separators=(",", ":")))


# ---------------------------------------------------------------------------
# Configured PII recognizers. This is a practical baseline, not a guarantee
# of detection.
# ---------------------------------------------------------------------------
def compile_redaction_checks(config: Dict[str, Any]) -> list[Tuple[str, str, re.Pattern[str]]]:
    checks = config.get("checks")
    if not isinstance(checks, dict):
        return []

    compiled_checks = []
    for key, settings in checks.items():
        if not isinstance(settings, dict):
            continue
        if settings.get("enabled") is not True or str(settings.get("action", "")).lower() != "redact":
            continue

        regex_value = settings.get("regex")
        if not isinstance(regex_value, str) or not regex_value.strip():
            continue
        try:
            pattern = re.compile(regex_value)
        except re.error as exc:
            raise ValueError(f"Invalid regex for PII check '{key}'") from exc

        display_name = settings.get("display_name")
        label = display_name.strip().upper() if isinstance(display_name, str) and display_name.strip() else str(key).upper()
        compiled_checks.append((str(key), label, pattern))

    return compiled_checks


ACTIVE_REDACTION_CHECKS = compile_redaction_checks(STARTUP_UI_CONFIG)


def redact_text(value: str) -> Tuple[str, Counter]:
    counts = Counter()

    for check_key, display_name, pattern in ACTIVE_REDACTION_CHECKS:
        def sub(_match, reason=check_key):
            counts[reason] += 1
            return f"[REDACTED:{display_name}]"
        value = pattern.sub(sub, value)

    return value, counts


def redact_json(value: Any) -> Tuple[Any, Counter]:
    """Recursively redact every string in a JSON-compatible object."""
    total = Counter()
    if isinstance(value, str):
        redacted, counts = redact_text(value)
        total.update(counts)
        return redacted, total
    if isinstance(value, list):
        output = []
        for item in value:
            redacted, counts = redact_json(item)
            output.append(redacted)
            total.update(counts)
        return output, total
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            # Keys are also user-controlled in tool/function payloads.
            safe_key, key_counts = redact_text(str(key))
            safe_value, value_counts = redact_json(item)
            output[safe_key] = safe_value
            total.update(key_counts)
            total.update(value_counts)
        return output, total
    return value, total


# ---------------------------------------------------------------------------
# App and authentication
# ---------------------------------------------------------------------------
app = FastAPI(title="PII Guardrail Proxy", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def check_proxy_auth(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    supplied = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(supplied, PROXY_API_KEY):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token",
                            headers={"WWW-Authenticate": "Bearer"})


def make_ui_session(expires_at: int) -> str:
    message = f"ui-session:{expires_at}".encode("utf-8")
    signature = hmac.new(UI_ACCESS_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{expires_at}.{signature}"


def check_ui_auth(request: Request) -> None:
    if not UI_ACCESS_KEY:
        raise HTTPException(status_code=503, detail="UI_ACCESS_KEY is not configured")
    session = request.cookies.get("pii_ui_session", "")
    try:
        expires_text, supplied_signature = session.split(".", 1)
        expires_at = int(expires_text)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="UI authentication required")

    expected_signature = make_ui_session(expires_at).split(".", 1)[1]
    if expires_at <= int(time.time()) or not hmac.compare_digest(
        supplied_signature, expected_signature
    ):
        raise HTTPException(status_code=401, detail="UI authentication required")


def read_ui_config() -> Dict[str, Any]:
    if not UI_CONFIG_FILE.exists():
        config = {}
    else:
        try:
            with UI_CONFIG_FILE.open("r", encoding="utf-8") as config_file:
                config = json.load(config_file)
        except (OSError, json.JSONDecodeError) as exc:
            logging.exception("Unable to read UI configuration")
            raise HTTPException(status_code=500, detail="Saved UI configuration is invalid") from exc
        if not isinstance(config, dict):
            raise HTTPException(status_code=500, detail="Saved UI configuration must be a JSON object")
    config.setdefault("VLLM_BASE_URL", VLLM_BASE_URL)
    config.setdefault("VLLM_API_KEY", VLLM_API_KEY)
    config.setdefault("PROXY_API_KEY", PROXY_API_KEY)
    return config


def proxy_api_key_preview(api_key: str) -> str:
    return f"{api_key[:8]}..." if api_key else "Not configured"


def save_ui_config(config: Dict[str, Any]) -> None:
    UI_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_path = UI_CONFIG_FILE.with_name(
        f".{UI_CONFIG_FILE.name}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with temp_path.open("w", encoding="utf-8") as config_file:
            json.dump(config, config_file, ensure_ascii=False, indent=2)
            config_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, UI_CONFIG_FILE)
    finally:
        temp_path.unlink(missing_ok=True)


def validate_vllm_base_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=400, detail="VLLM_BASE_URL must be a non-empty URL")
    try:
        parsed_url = httpx.URL(value.strip())
    except httpx.InvalidURL as exc:
        raise HTTPException(status_code=400, detail="VLLM_BASE_URL is invalid") from exc
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.host
        or parsed_url.query
        or parsed_url.fragment
        or parsed_url.username
        or parsed_url.password
    ):
        raise HTTPException(
            status_code=400,
            detail="VLLM_BASE_URL must be an HTTP(S) URL without credentials, query, or fragment",
        )
    if re.search(r"/(?:openai/)?v1/?$", parsed_url.path, re.IGNORECASE) is None:
        raise HTTPException(
            status_code=400,
            detail="VLLM_BASE_URL must end with /v1 or /openai/v1",
        )
    return str(parsed_url).rstrip("/")


async def read_request_body_limited(request: Request, max_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise HTTPException(status_code=413, detail="Request body is too large")
        body.extend(chunk)
    return bytes(body)


def upstream_headers(incoming_headers) -> Dict[str, str]:
    # Do not forward the client's Authorization header or hop-by-hop headers.
    excluded = {
        "authorization", "host", "content-length", "connection",
        "transfer-encoding", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers", "upgrade",
        "accept-encoding",
    }
    headers = {k: v for k, v in incoming_headers.items() if k.lower() not in excluded}
    headers["Authorization"] = f"Bearer {VLLM_API_KEY}"
    headers["Accept-Encoding"] = "identity" 
    return headers


def client_response_headers(upstream_headers) -> Dict[str, str]:
    allowed = {"content-type", "cache-control", "x-request-id"}
    return {k: v for k, v in upstream_headers.items() if k.lower() in allowed}


UI_PAGE = r"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f3f5f2">
    <title>PII Guardrail | Operations</title>
    <script>
        try {
            document.documentElement.dataset.theme = localStorage.getItem("pii-theme") === "dark"
                ? "dark"
                : "light";
        } catch {}
    </script>
    <style>
        :root {
            color-scheme: light;
            --paper: #f3f5f2;
            --surface: #ffffff;
            --page-start: #f8faf7;
            --page-end: #edf1ed;
            --ink: #17231f;
            --muted: #64716b;
            --line: #dce3dd;
            --line-strong: #cbd6ce;
            --green: #17684d;
            --green-dark: #104c39;
            --lime: #d9ef9c;
            --orange: #e8794f;
            --field: #fbfcfa;
            --row: #fcfdfb;
            --tag-text: #355449;
            --tag-bg: #eaf2eb;
            --tag-line: #d6e4d8;
            --divider: #edf0ed;
            --error: #a63c27;
            --panel-shadow: rgba(28, 54, 41, .07);
            --focus-ring: rgba(23, 104, 77, .12);
            font-family: "Avenir Next", Avenir, "Segoe UI", sans-serif;
        }
        :root[data-theme="dark"] {
            color-scheme: dark;
            --paper: #151d1a;
            --surface: #202b26;
            --page-start: #1d2923;
            --page-end: #111815;
            --ink: #e8eee9;
            --muted: #a7b5ac;
            --line: #3a4940;
            --line-strong: #53645a;
            --green: #62bb91;
            --green-dark: #4aa77b;
            --lime: #d8ef9b;
            --orange: #f1936c;
            --field: #18221d;
            --row: #1c2721;
            --tag-text: #c4e4ce;
            --tag-bg: #293d32;
            --tag-line: #3d5a49;
            --divider: #344139;
            --error: #ff9a83;
            --panel-shadow: rgba(0, 0, 0, .22);
            --focus-ring: rgba(98, 187, 145, .2);
        }
        * { box-sizing: border-box; }
        body {
            min-height: 100vh;
            margin: 0;
            color: var(--ink);
            background:
                radial-gradient(ellipse at 92% 6%, color-mix(in srgb, var(--lime) 12%, transparent), transparent 28rem),
                linear-gradient(135deg, var(--page-start) 0%, var(--paper) 50%, var(--page-end) 100%);
        }
        button, input, textarea { font: inherit; }
        button { cursor: pointer; }
        .topbar {
            min-height: 72px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 clamp(20px, 5vw, 72px);
            border-bottom: 1px solid var(--line);
        }
        .topbar-actions { display: flex; align-items: center; gap: 20px; }
        .theme-control { display: inline-flex; align-items: center; gap: 9px; margin: 0; color: var(--muted); font-size: 13px; font-weight: 650; cursor: pointer; }
        .theme-control input { position: absolute; width: 1px; height: 1px; padding: 0; opacity: 0; }
        .switch-track { position: relative; width: 38px; height: 22px; flex: 0 0 auto; background: var(--line-strong); border: 1px solid var(--line-strong); border-radius: 20px; transition: background .18s ease, border-color .18s ease; }
        .switch-track::after { position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; content: ""; background: var(--surface); border-radius: 50%; transition: transform .18s ease; }
        .theme-control input:checked + .switch-track { background: var(--green); border-color: var(--green); }
        .theme-control input:checked + .switch-track::after { transform: translateX(16px); }
        .theme-control input:focus-visible + .switch-track { outline: 3px solid var(--focus-ring); outline-offset: 2px; }
        .brand { display: flex; align-items: center; gap: 12px; font-weight: 750; }
        .brand-mark {
            display: grid;
            width: 34px;
            aspect-ratio: 1;
            place-items: center;
            color: var(--lime);
            background: var(--green);
            border-radius: 9px;
            font-size: 15px;
        }
        .top-label { color: var(--muted); font-size: 13px; }
        main { width: min(1050px, calc(100% - 40px)); margin: 58px auto 80px; }
        .eyebrow { color: var(--green); font-size: 11px; font-weight: 800; letter-spacing: 1.4px; text-transform: uppercase; }
        h1 { margin: 9px 0 8px; font-size: clamp(28px, 4vw, 40px); line-height: 1.1; }
        .subhead { margin: 0; color: var(--muted); font-size: 15px; }
        .lock-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(270px, .7fr); gap: 54px; align-items: center; }
        .lock-panel { padding: 30px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 18px 50px var(--panel-shadow); }
        label { display: block; margin-bottom: 8px; font-size: 13px; font-weight: 700; }
        input, textarea {
            width: 100%;
            padding: 12px 13px;
            color: var(--ink);
            background: var(--field);
            border: 1px solid var(--line-strong);
            border-radius: 5px;
            outline: none;
        }
        input:focus, textarea:focus, select:focus { border-color: var(--green); box-shadow: 0 0 0 3px var(--focus-ring); }
        .primary, .secondary {
            min-height: 42px;
            padding: 0 16px;
            border-radius: 5px;
            font-weight: 700;
        }
        .primary { color: #fff; background: var(--green); border: 1px solid var(--green); }
        .primary:hover { background: var(--green-dark); }
        .secondary { color: var(--ink); background: var(--surface); border: 1px solid var(--line); }
        .secondary:hover { border-color: var(--green); }
        .login-submit { width: 100%; margin-top: 14px; }
        .login-note { min-height: 20px; margin: 12px 0 0; color: var(--error); font-size: 13px; }
        .lock-aside { padding: 22px 0; border-top: 3px solid var(--orange); }
        .lock-aside strong { display: block; margin-bottom: 8px; font-size: 17px; }
        .lock-aside p { margin: 0; color: var(--muted); font-size: 14px; line-height: 1.6; }
        .hidden { display: none !important; }
        .dashboard-head { display: flex; justify-content: space-between; align-items: end; gap: 20px; margin-bottom: 28px; }
        .head-actions { display: flex; gap: 8px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 30px; }
        .stat { min-height: 122px; padding: 19px; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
        .stat-label { color: var(--muted); font-size: 13px; }
        .stat-value { display: block; margin-top: 12px; font-size: 31px; font-weight: 750; letter-spacing: 0; }
        .content-grid { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(230px, .6fr); gap: 16px; }
        .settings-stack { display: grid; align-content: start; gap: 16px; }
        .connection-fields { display: grid; gap: 14px; max-width: 640px; }
        .connection-fields input { min-height: 41px; font-size: 13px; }
        .connection-url-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px; }
        .connection-url-row input { min-width: 0; }
        .models-check-status { display: flex; align-items: center; min-height: 20px; margin: 7px 0 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
        .models-check-status[data-state="success"] { color: var(--green); }
        .models-check-status[data-state="error"] { color: var(--error); }
        .progress-dots { display: inline-flex; gap: 3px; margin-left: 6px; }
        .progress-dots[hidden] { display: none; }
        .progress-dots i { width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: model-check-pulse 1s infinite ease-in-out; opacity: .25; }
        .progress-dots i:nth-child(2) { animation-delay: .15s; }
        .progress-dots i:nth-child(3) { animation-delay: .3s; }
        @keyframes model-check-pulse { 50% { opacity: 1; } }
        @media (prefers-reduced-motion: reduce) { .progress-dots i { animation: none; opacity: 1; } }
        .settings-group + .settings-group { margin-top: 20px; padding-top: 18px; border-top: 1px solid var(--line); }
        .settings-group-title { margin: 0 0 12px; color: var(--muted); font-size: 12px; font-weight: 750; }
        .proxy-key-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 12px; max-width: 640px; }
        .proxy-key-preview { overflow: hidden; color: var(--ink); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; text-overflow: ellipsis; }
        .proxy-url-value { display: block; overflow-wrap: anywhere; color: var(--ink); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; line-height: 1.5; }
        .key-dialog { width: min(480px, calc(100vw - 32px)); padding: 22px; color: var(--ink); background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
        .key-dialog::backdrop { background: rgb(0 0 0 / 55%); }
        .key-dialog h2 { margin: 0 0 8px; }
        .key-dialog p { margin: 0 0 16px; color: var(--muted); font-size: 13px; line-height: 1.5; }
        .generated-key-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; }
        .generated-key-row input { min-width: 0; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; }
        .key-dialog-note { min-height: 20px; margin: 10px 0 0 !important; color: var(--muted) !important; }
        .key-dialog-note[data-error="true"] { color: var(--error) !important; }
        .key-dialog-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
        .section { padding: 22px; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
        .section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 14px; }
        h2 { margin: 0; font-size: 17px; }
        .section-note { margin: 0; color: var(--muted); font-size: 12px; }
        .pii-list { display: grid; gap: 10px; }
        .pii-row { padding: 17px; border: 1px solid var(--line); border-radius: 6px; background: var(--row); }
        .pii-row-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
        .pii-title { min-width: 0; }
        .pii-title h3 { margin: 0; font-size: 16px; }
        .pii-key { display: block; margin-top: 3px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; }
        .enabled-toggle { display: flex; align-items: center; gap: 8px; flex: 0 0 auto; margin: 0; font-size: 13px; }
        .enabled-toggle input { width: 17px; height: 17px; margin: 0; accent-color: var(--green); }
        .pii-fields { display: grid; grid-template-columns: minmax(150px, .7fr) minmax(0, 1.7fr); gap: 13px 16px; }
        .setting-field { min-width: 0; }
        .setting-field label { margin-bottom: 6px; font-size: 12px; }
        .setting-field select { width: 100%; min-height: 41px; padding: 8px 10px; color: var(--ink); background: var(--field); border: 1px solid var(--line-strong); border-radius: 5px; }
        .setting-field textarea { min-height: 72px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; line-height: 1.5; }
        .framework-field { grid-column: 1 / -1; }
        .framework-tags { display: flex; flex-wrap: wrap; gap: 6px; min-height: 27px; }
        .framework-tag { padding: 5px 8px; color: var(--tag-text); background: var(--tag-bg); border: 1px solid var(--tag-line); border-radius: 4px; font-size: 11px; font-weight: 700; }
        .empty-settings { margin: 4px 0; color: var(--muted); font-size: 13px; }
        .save-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-top: 12px; }
        .save-note { color: var(--muted); font-size: 13px; }
        .reason-list { display: grid; gap: 11px; margin: 0; padding: 0; list-style: none; }
        .reason-list li { display: flex; justify-content: space-between; gap: 12px; padding-bottom: 9px; border-bottom: 1px solid var(--divider); font-size: 13px; }
        .reason-list li:last-child { border-bottom: 0; }
        .reason-count { font-weight: 750; }
        .latest { margin-top: 19px; padding-top: 15px; border-top: 1px solid var(--line); }
        .latest .stat-label { display: block; margin-bottom: 5px; }
        .latest time { font-size: 12px; }
        @media (max-width: 720px) {
            main { margin-top: 36px; }
            .lock-layout, .content-grid { grid-template-columns: 1fr; gap: 24px; }
            .lock-panel { padding: 22px; }
            .dashboard-head { align-items: start; flex-direction: column; }
            .stats { gap: 8px; }
            .stat { min-height: 105px; padding: 14px; }
            .stat-value { font-size: 25px; }
            .top-label { font-size: 11px; }
        }
        @media (max-width: 420px) {
            .stats { grid-template-columns: 1fr; }
            .stat { min-height: 88px; }
            .stat-value { margin-top: 6px; }
            .save-row { align-items: stretch; flex-direction: column; }
            .save-row button { width: 100%; }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="brand"><span class="brand-mark" aria-hidden="true">PG</span><span>PII Guardrail</span></div>
        <div class="topbar-actions">
            <span class="top-label">PROXY OPERATIONS</span>
            <label class="theme-control" for="theme-toggle">
                <input id="theme-toggle" type="checkbox" role="switch" aria-label="Dark mode">
                <span class="switch-track" aria-hidden="true"></span>
                <span>Dark mode</span>
            </label>
        </div>
    </header>
    <main>
        <section id="login-view" class="lock-layout" aria-labelledby="login-title">
            <div>
                <div class="eyebrow">Restricted console</div>
                <h1 id="login-title">Operations access</h1>
                <p class="subhead">Enter the UI access key to view proxy activity and manage saved configuration.</p>
            </div>
            <form id="login-form" class="lock-panel">
                <label for="access-key">UI access key</label>
                <input id="access-key" name="key" type="password" autocomplete="current-password" required>
                <button class="primary login-submit" type="submit">Unlock console</button>
                <p id="login-note" class="login-note" role="status" aria-live="polite"></p>
            </form>
            <aside class="lock-aside">
                <strong>Protected by your environment key</strong>
                <p>The console does not expose the access key to the browser after sign-in. Sessions expire after 12 hours.</p>
            </aside>
        </section>

        <section id="dashboard" class="hidden" aria-labelledby="dashboard-title">
            <div class="dashboard-head">
                <div>
                    <div class="eyebrow">Proxy overview</div>
                    <h1 id="dashboard-title">Operations</h1>
                    <p class="subhead">Redaction activity and persisted application settings.</p>
                </div>
                <div class="head-actions">
                    <button id="refresh-button" class="secondary" type="button">Refresh</button>
                    <button id="logout-button" class="secondary" type="button">Lock console</button>
                </div>
            </div>
            <div class="stats" aria-label="Redaction totals">
                <div class="stat"><span class="stat-label">Total redactions</span><strong id="total-stat" class="stat-value">0</strong></div>
                <div class="stat"><span class="stat-label">Inbound</span><strong id="inbound-stat" class="stat-value">0</strong></div>
                <div class="stat"><span class="stat-label">Outbound</span><strong id="outbound-stat" class="stat-value">0</strong></div>
            </div>
            <div class="content-grid">
                <div class="settings-stack">
                    <section class="section" aria-labelledby="settings-title">
                        <div class="section-head">
                            <h2 id="settings-title">Application settings</h2>
                        </div>
                        <div class="settings-group">
                            <h3 class="settings-group-title">Upstream connection</h3>
                            <div class="connection-fields">
                                <div class="setting-field">
                                    <label for="vllm-base-url">vLLM Base URL</label>
                                    <div class="connection-url-row">
                                        <input id="vllm-base-url" type="url" autocomplete="url" required>
                                        <button id="check-models-button" class="secondary" type="button">Check Models</button>
                                    </div>
                                    <p id="models-check-status" class="models-check-status" role="status" aria-live="polite"><span id="models-check-message"></span><span id="models-check-dots" class="progress-dots" hidden aria-hidden="true"><i></i><i></i><i></i></span></p>
                                </div>
                                <div class="setting-field">
                                    <label for="vllm-api-key">vLLM API Key</label>
                                    <input id="vllm-api-key" type="password" autocomplete="new-password" required>
                                </div>
                            </div>
                        </div>
                        <div class="settings-group">
                            <h3 class="settings-group-title">Proxy authentication</h3>
                            <div class="connection-fields">
                                <div class="setting-field">
                                    <span class="stat-label">Proxy URL</span>
                                    <code id="proxy-url" class="proxy-url-value"></code>
                                </div>
                                <div class="setting-field">
                                    <span class="stat-label">Proxy API Key</span>
                                    <div class="proxy-key-row">
                                        <code id="proxy-api-key-preview" class="proxy-key-preview">Loading...</code>
                                        <button id="generate-proxy-key" class="secondary" type="button">Generate new key</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>
                    <section class="section" aria-labelledby="checks-title">
                        <div class="section-head">
                            <h2 id="checks-title">PII Checks</h2>
                        </div>
                        <div id="pii-settings" class="pii-list" aria-label="PII detection settings"></div>
                        <div class="save-row">
                            <span id="config-note" class="save-note" role="status" aria-live="polite">Application and check settings are saved together.</span>
                            <button id="save-button" class="primary" type="button">Save Settings</button>
                        </div>
                    </section>
                </div>
                <section class="section" aria-labelledby="reasons-title">
                    <div class="section-head">
                        <h2 id="reasons-title">Redactions by type</h2>
                    </div>
                    <ul id="reason-list" class="reason-list"></ul>
                    <div class="latest">
                        <span class="stat-label">Latest audit entry</span>
                        <time id="latest-stat">No activity recorded</time>
                    </div>
                </section>
            </div>
        </section>
        <dialog id="proxy-key-dialog" class="key-dialog" aria-labelledby="proxy-key-dialog-title" aria-describedby="proxy-key-dialog-description">
            <h2 id="proxy-key-dialog-title">New Proxy API Key</h2>
            <p id="proxy-key-dialog-description">This key is shown only once. Copy it now; after saving or closing this dialog, it cannot be viewed again.</p>
            <label for="generated-proxy-key">Generated key</label>
            <div class="generated-key-row">
                    <input id="generated-proxy-key" type="text" autocomplete="off" readonly spellcheck="false">
                <button id="copy-proxy-key" class="secondary" type="button">Copy</button>
            </div>
            <p id="proxy-key-dialog-note" class="key-dialog-note" role="status" aria-live="polite"></p>
            <div class="key-dialog-actions">
                <button id="cancel-proxy-key" class="secondary" type="button">Cancel</button>
                <button id="save-proxy-key" class="primary" type="button">Save key</button>
            </div>
        </dialog>
    </main>
    <script>
        const loginView = document.querySelector("#login-view");
        const dashboard = document.querySelector("#dashboard");
        const loginNote = document.querySelector("#login-note");
        const settingsContainer = document.querySelector("#pii-settings");
        const configNote = document.querySelector("#config-note");
        const themeToggle = document.querySelector("#theme-toggle");
        const modelsCheckStatus = document.querySelector("#models-check-status");
        const modelsCheckMessage = document.querySelector("#models-check-message");
        const modelsCheckDots = document.querySelector("#models-check-dots");
        const proxyUrl = new URL(window.location.href);
        proxyUrl.pathname = proxyUrl.pathname.replace(/\/+$/, "") + "/v1";
        proxyUrl.search = "";
        proxyUrl.hash = "";
        document.querySelector("#proxy-url").textContent = proxyUrl.toString();
        const proxyKeyDialog = document.querySelector("#proxy-key-dialog");
        const generatedProxyKey = document.querySelector("#generated-proxy-key");
        const proxyKeyDialogNote = document.querySelector("#proxy-key-dialog-note");
        let loadedConfig = {};
        let pendingProxyApiKey = "";

        themeToggle.checked = document.documentElement.dataset.theme === "dark";
        themeToggle.addEventListener("change", () => {
            const theme = themeToggle.checked ? "dark" : "light";
            document.documentElement.dataset.theme = theme;
            document.querySelector('meta[name="theme-color"]').content = theme === "dark"
                ? "#151d1a"
                : "#f3f5f2";
            try {
                localStorage.setItem("pii-theme", theme);
            } catch {}
        });

        async function requestJson(url, options = {}) {
            const response = await fetch(url, { cache: "no-store", ...options });
            const data = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(data.detail || "Request failed");
            return data;
        }

        function normalizeVllmBaseUrl(value) {
            let parsed;
            try {
                parsed = new URL(value.trim());
            } catch {
                throw new Error("Enter a valid vLLM Base URL.");
            }
            if (!['http:', 'https:'].includes(parsed.protocol)
                || parsed.username || parsed.password || parsed.search || parsed.hash) {
                throw new Error("Use an HTTP(S) URL without credentials, query, or fragment.");
            }
            if (!/(?:\/openai)?\/v1\/$/.test(parsed.pathname.replace(/\/+$/, "") + "/")) {
                throw new Error("The URL must end with /v1 or /openai/v1.");
            }
            return parsed.href.replace(/\/+$/, "");
        }

        function showLogin(message = "") {
            dashboard.classList.add("hidden");
            loginView.classList.remove("hidden");
            loginNote.textContent = message;
        }

        function appendSettingField(parent, labelText, control, id) {
            const field = document.createElement("div");
            field.className = "setting-field";
            const label = document.createElement("label");
            label.htmlFor = id;
            label.textContent = labelText;
            control.id = id;
            field.append(label, control);
            parent.append(field);
            return field;
        }

        function renderSettings(config) {
            settingsContainer.replaceChildren();
            let renderedCount = 0;
            const checks = config.checks && typeof config.checks === "object"
                && !Array.isArray(config.checks)
                ? config.checks
                : {};

            for (const [key, entry] of Object.entries(checks)) {
                if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
                renderedCount += 1;
                const row = document.createElement("article");
                row.className = "pii-row";
                row.dataset.configKey = key;

                const header = document.createElement("div");
                header.className = "pii-row-head";
                const title = document.createElement("div");
                title.className = "pii-title";
                const heading = document.createElement("h3");
                heading.textContent = typeof entry.display_name === "string" && entry.display_name
                    ? entry.display_name
                    : key;
                title.append(heading);
                //const keyLabel = document.createElement("span");
                //keyLabel.className = "pii-key";
                //keyLabel.textContent = key;
                //title.append(heading, keyLabel);               

                const enabledLabel = document.createElement("label");
                enabledLabel.className = "enabled-toggle";
                const enabled = document.createElement("input");
                enabled.type = "checkbox";
                enabled.checked = entry.enabled === true;
                enabled.dataset.setting = "enabled";
                enabledLabel.append(enabled, document.createTextNode("Enabled"));
                header.append(title, enabledLabel);

                const fields = document.createElement("div");
                fields.className = "pii-fields";
                const action = document.createElement("select");
                action.dataset.setting = "action";
                const actionValue = typeof entry.action === "string"
                    ? entry.action.toLowerCase()
                    : "redact";
                const actions = [
                    ["redact", "Redact"],
                    ["mask", "Mask"],
                    ["hash", "Hash"]
                ];
                for (const [value, label] of actions) {
                    const option = document.createElement("option");
                    option.value = value;
                    option.textContent = label;
                    action.append(option);
                }
                if (!actions.some(([value]) => value === actionValue) && typeof entry.action === "string") {
                    const option = document.createElement("option");
                    option.value = entry.action;
                    option.textContent = "Existing: " + entry.action;
                    action.append(option);
                }
                action.value = actions.some(([value]) => value === actionValue)
                    ? actionValue
                    : (typeof entry.action === "string" ? entry.action : "redact");
                appendSettingField(fields, "Action", action, "action-" + renderedCount);

                const regex = document.createElement("textarea");
                regex.rows = 3;
                regex.spellcheck = false;
                regex.value = entry.regex == null ? "" : String(entry.regex);
                regex.dataset.setting = "regex";
                appendSettingField(fields, "Regex pattern", regex, "regex-" + renderedCount);

                const frameworkField = document.createElement("div");
                frameworkField.className = "setting-field framework-field";
                const frameworkLabel = document.createElement("span");
                frameworkLabel.className = "stat-label";
                frameworkLabel.textContent = "Regulatory frameworks";
                const frameworks = document.createElement("div");
                frameworks.className = "framework-tags";
                const frameworkValues = Array.isArray(entry.regulatory_frameworks)
                    ? entry.regulatory_frameworks
                    : [];
                if (frameworkValues.length) {
                    for (const framework of frameworkValues) {
                        const tag = document.createElement("span");
                        tag.className = "framework-tag";
                        tag.textContent = String(framework).toUpperCase();
                        frameworks.append(tag);
                    }
                } else {
                    const none = document.createElement("span");
                    none.className = "section-note";
                    none.textContent = "None specified";
                    frameworks.append(none);
                }
                frameworkField.append(frameworkLabel, frameworks);
                fields.append(frameworkField);
                row.append(header, fields);
                settingsContainer.append(row);
            }

            if (!renderedCount) {
                const empty = document.createElement("p");
                empty.className = "empty-settings";
                empty.textContent = "No PII settings are configured.";
                settingsContainer.append(empty);
            }
        }

        async function showDashboard() {
            try {
                const [config, stats] = await Promise.all([
                    requestJson("/api/ui/config"),
                    requestJson("/api/ui/stats")
                ]);
                loadedConfig = config;
                renderSettings(loadedConfig);
                document.querySelector("#vllm-base-url").value = config.VLLM_BASE_URL || "";
                document.querySelector("#vllm-api-key").value = config.VLLM_API_KEY || "";
                document.querySelector("#proxy-api-key-preview").textContent = config.PROXY_API_KEY_PREVIEW || "Not configured";
                document.querySelector("#total-stat").textContent = stats.redactions.toLocaleString();
                document.querySelector("#inbound-stat").textContent = stats.inbound.toLocaleString();
                document.querySelector("#outbound-stat").textContent = stats.outbound.toLocaleString();
                const reasonList = document.querySelector("#reason-list");
                reasonList.replaceChildren();
                const entries = Object.entries(stats.reasons).sort((a, b) => b[1] - a[1]);
                if (!entries.length) {
                    const item = document.createElement("li");
                    item.textContent = "No redactions recorded";
                    reasonList.append(item);
                }
                for (const [reason, count] of entries) {
                    const item = document.createElement("li");
                    const name = document.createElement("span");
                    const value = document.createElement("span");
                    name.textContent = reason.replaceAll("_", " ");
                    value.className = "reason-count";
                    value.textContent = count.toLocaleString();
                    item.append(name, value);
                    reasonList.append(item);
                }
                const latest = document.querySelector("#latest-stat");
                if (stats.latest) {
                    latest.dateTime = stats.latest;
                    latest.textContent = new Date(stats.latest).toLocaleString();
                } else {
                    latest.removeAttribute("datetime");
                    latest.textContent = "No activity recorded";
                }
                loginView.classList.add("hidden");
                dashboard.classList.remove("hidden");
            } catch (error) {
                if (error.message === "UI authentication required") showLogin("Your session expired. Enter the key again.");
                else if (error.message === "UI_ACCESS_KEY is not configured") showLogin("Set UI_ACCESS_KEY in the process environment to enable console access.");
                else configNote.textContent = error.message;
            }
        }

        document.querySelector("#login-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            loginNote.textContent = "";
            const key = document.querySelector("#access-key").value;
            try {
                await requestJson("/ui/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ key })
                });
                document.querySelector("#access-key").value = "";
                await showDashboard();
            } catch (error) {
                loginNote.textContent = error.message;
            }
        });

        document.querySelector("#save-button").addEventListener("click", async () => {
            configNote.textContent = "";
            try {
                const config = structuredClone(loadedConfig);
                if (!config.checks || typeof config.checks !== "object" || Array.isArray(config.checks)) {
                    throw new Error("Configuration is missing a checks object.");
                }
                const baseUrlValue = normalizeVllmBaseUrl(document.querySelector("#vllm-base-url").value);
                const apiKeyValue = document.querySelector("#vllm-api-key").value.trim();
                if (!apiKeyValue) throw new Error("vLLM API Key cannot be empty.");
                config.VLLM_BASE_URL = baseUrlValue;
                config.VLLM_API_KEY = apiKeyValue;
                for (const row of settingsContainer.querySelectorAll(".pii-row")) {
                    const entry = config.checks[row.dataset.configKey];
                    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
                    entry.enabled = row.querySelector('[data-setting="enabled"]').checked;
                    entry.action = row.querySelector('[data-setting="action"]').value;
                    const regexValue = row.querySelector('[data-setting="regex"]').value;
                    entry.regex = regexValue === "" ? null : regexValue;
                }
                await requestJson("/api/ui/config", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(config)
                });
                configNote.textContent = "Settings saved.";
            } catch (error) {
                configNote.textContent = error instanceof SyntaxError ? "Invalid JSON: " + error.message : error.message;
            }
        });

        document.querySelector("#check-models-button").addEventListener("click", async (event) => {
            const button = event.currentTarget;
            const baseUrlInput = document.querySelector("#vllm-base-url");
            const apiKeyInput = document.querySelector("#vllm-api-key");
            const saveSettingsButton = document.querySelector("#save-button");
            const apiKey = apiKeyInput.value.trim();
            modelsCheckStatus.dataset.state = "";
            modelsCheckMessage.textContent = "";
            modelsCheckDots.hidden = true;
            button.disabled = true;
            baseUrlInput.disabled = true;
            apiKeyInput.disabled = true;
            saveSettingsButton.disabled = true;
            try {
                const baseUrl = normalizeVllmBaseUrl(baseUrlInput.value);
                if (!apiKey) throw new Error("vLLM API Key cannot be empty.");
                modelsCheckStatus.dataset.state = "checking";
                modelsCheckMessage.textContent = "Checking models. The endpoint worker may take a few minutes to initialize";
                modelsCheckDots.hidden = false;
                const result = await requestJson("/api/ui/check-models", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ VLLM_BASE_URL: baseUrl, VLLM_API_KEY: apiKey })
                });
                document.querySelector("#vllm-base-url").value = result.VLLM_BASE_URL;
                document.querySelector("#vllm-api-key").value = apiKey;
                loadedConfig.VLLM_BASE_URL = result.VLLM_BASE_URL;
                loadedConfig.VLLM_API_KEY = apiKey;
                modelsCheckStatus.dataset.state = "success";
                modelsCheckMessage.textContent = `Models found: ${result.models.join(", ")}. Connection settings saved.`;
            } catch (error) {
                modelsCheckStatus.dataset.state = "error";
                modelsCheckMessage.textContent = error.message;
            } finally {
                modelsCheckDots.hidden = true;
                button.disabled = false;
                baseUrlInput.disabled = false;
                apiKeyInput.disabled = false;
                saveSettingsButton.disabled = false;
            }
        });

        document.querySelector("#generate-proxy-key").addEventListener("click", () => {
            try {
                const bytes = crypto.getRandomValues(new Uint8Array(32));
                pendingProxyApiKey = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
                generatedProxyKey.value = pendingProxyApiKey;
                proxyKeyDialogNote.textContent = "";
                proxyKeyDialogNote.removeAttribute("data-error");
                proxyKeyDialog.showModal();
            } catch {
                configNote.textContent = "Secure key generation is unavailable in this browser.";
            }
        });

        document.querySelector("#copy-proxy-key").addEventListener("click", async () => {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(pendingProxyApiKey);
                } else {
                    generatedProxyKey.focus();
                    generatedProxyKey.select();
                    if (!document.execCommand("copy")) throw new Error("Copy failed");
                }
                proxyKeyDialogNote.textContent = "Key copied to clipboard.";
                proxyKeyDialogNote.removeAttribute("data-error");
            } catch {
                proxyKeyDialogNote.textContent = "Copy failed. Select and copy the key manually.";
                proxyKeyDialogNote.dataset.error = "true";
            }
        });

        document.querySelector("#cancel-proxy-key").addEventListener("click", () => proxyKeyDialog.close());
        proxyKeyDialog.addEventListener("close", () => {
            pendingProxyApiKey = "";
            generatedProxyKey.value = "";
            proxyKeyDialogNote.textContent = "";
            proxyKeyDialogNote.removeAttribute("data-error");
        });

        document.querySelector("#save-proxy-key").addEventListener("click", async (event) => {
            const saveButton = event.currentTarget;
            saveButton.disabled = true;
            proxyKeyDialogNote.textContent = "";
            proxyKeyDialogNote.removeAttribute("data-error");
            try {
                const result = await requestJson("/api/ui/proxy-key", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ PROXY_API_KEY: pendingProxyApiKey })
                });
                document.querySelector("#proxy-api-key-preview").textContent = result.PROXY_API_KEY_PREVIEW;
                loadedConfig.PROXY_API_KEY_PREVIEW = result.PROXY_API_KEY_PREVIEW;
                configNote.textContent = "New Proxy API Key saved. Update clients to use it.";
                proxyKeyDialog.close();
            } catch (error) {
                proxyKeyDialogNote.textContent = error.message;
                proxyKeyDialogNote.dataset.error = "true";
            } finally {
                saveButton.disabled = false;
            }
        });

        document.querySelector("#refresh-button").addEventListener("click", showDashboard);
        document.querySelector("#logout-button").addEventListener("click", async () => {
            await requestJson("/ui/logout", { method: "POST" });
            showLogin();
        });

        showDashboard();
    </script>
</body>
</html>"""


@app.get("/")
async def root():
    return HTMLResponse(UI_PAGE, headers={"Cache-Control": "no-store"})


@app.post("/ui/login")
async def ui_login(request: Request):
    if not UI_ACCESS_KEY:
        raise HTTPException(status_code=503, detail="UI_ACCESS_KEY is not configured")
    try:
        body = await read_request_body_limited(request, 4096)
        payload = json.loads(body)
        supplied_key = payload.get("key", "") if isinstance(payload, dict) else ""
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Expected a JSON request")
    if not isinstance(supplied_key, str) or not secrets.compare_digest(
        supplied_key, UI_ACCESS_KEY
    ):
        raise HTTPException(status_code=401, detail="Invalid access key")

    expires_at = int(time.time()) + UI_SESSION_SECONDS
    response = JSONResponse({"ok": True})
    response.set_cookie(
        "pii_ui_session",
        make_ui_session(expires_at),
        max_age=UI_SESSION_SECONDS,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/ui/logout")
async def ui_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("pii_ui_session", httponly=True, samesite="strict", path="/")
    return response


@app.get("/api/ui/config")
async def get_ui_config(request: Request):
    check_ui_auth(request)
    config = read_ui_config()
    config["PROXY_API_KEY_PREVIEW"] = proxy_api_key_preview(config.pop("PROXY_API_KEY", ""))
    return JSONResponse(config, headers={"Cache-Control": "no-store"})


@app.post("/api/ui/check-models")
async def check_vllm_models(request: Request):
    global VLLM_BASE_URL, VLLM_API_KEY

    check_ui_auth(request)
    body = await read_request_body_limited(request, 16 * 1024)
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Model check request must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Model check request must be a JSON object")

    base_url = validate_vllm_base_url(payload.get("VLLM_BASE_URL"))
    api_key = payload.get("VLLM_API_KEY")
    if not isinstance(api_key, str) or not api_key.strip():
        raise HTTPException(status_code=400, detail="VLLM_API_KEY must be a non-empty string")
    api_key = api_key.strip()

    timeout = httpx.Timeout(UPSTREAM_TIMEOUT, connect=15.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"{base_url}/models",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Model check timed out. The endpoint worker may still be initializing; try again.",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach models endpoint: {exc}") from exc

    if response.status_code != 200:
        reason = response.reason_phrase or "Upstream error"
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Models endpoint returned HTTP {response.status_code} {reason}",
        )
    try:
        model_payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Models endpoint returned invalid JSON") from exc
    model_data = model_payload.get("data") if isinstance(model_payload, dict) else None
    model_ids = [
        model["id"] for model in model_data
        if isinstance(model, dict) and isinstance(model.get("id"), str) and model["id"].strip()
    ] if isinstance(model_data, list) else []
    if not model_ids:
        raise HTTPException(status_code=502, detail="Models endpoint returned no model entries")

    config = read_ui_config()
    config["VLLM_BASE_URL"] = base_url
    config["VLLM_API_KEY"] = api_key
    save_ui_config(config)
    VLLM_BASE_URL = base_url
    VLLM_API_KEY = api_key
    return JSONResponse(
        {"ok": True, "VLLM_BASE_URL": base_url, "models": model_ids},
        headers={"Cache-Control": "no-store"},
    )


@app.put("/api/ui/config")
async def put_ui_config(request: Request):
    global VLLM_BASE_URL, VLLM_API_KEY, ACTIVE_REDACTION_CHECKS

    check_ui_auth(request)
    body = await read_request_body_limited(request, 256 * 1024)
    try:
        config = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Configuration must be valid JSON")
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="Configuration must be a JSON object")
    if not isinstance(config.get("checks"), dict):
        raise HTTPException(status_code=400, detail="Configuration must include a checks object")

    base_url = config.get("VLLM_BASE_URL")
    api_key = config.get("VLLM_API_KEY")
    base_url = validate_vllm_base_url(base_url)
    if not isinstance(api_key, str) or not api_key.strip():
        raise HTTPException(status_code=400, detail="VLLM_API_KEY must be a non-empty string")

    api_key = api_key.strip()
    config.pop("PROXY_API_KEY", None)
    config.pop("PROXY_API_KEY_PREVIEW", None)
    config["VLLM_BASE_URL"] = base_url
    config["VLLM_API_KEY"] = api_key
    config["PROXY_API_KEY"] = PROXY_API_KEY
    try:
        redaction_checks = compile_redaction_checks(config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    save_ui_config(config)
    VLLM_BASE_URL = base_url
    VLLM_API_KEY = api_key
    ACTIVE_REDACTION_CHECKS = redaction_checks
    return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})


@app.put("/api/ui/proxy-key")
async def put_ui_proxy_key(request: Request):
    global PROXY_API_KEY

    check_ui_auth(request)
    body = await read_request_body_limited(request, 1024)
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Proxy key must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Proxy key request must be a JSON object")
    proxy_api_key = payload.get("PROXY_API_KEY")
    if not isinstance(proxy_api_key, str) or re.fullmatch(r"[0-9a-f]{64}", proxy_api_key) is None:
        raise HTTPException(status_code=400, detail="PROXY_API_KEY must be 64 lowercase hexadecimal characters")

    config = read_ui_config()
    config["PROXY_API_KEY"] = proxy_api_key
    save_ui_config(config)
    PROXY_API_KEY = proxy_api_key
    return JSONResponse(
        {"ok": True, "PROXY_API_KEY_PREVIEW": proxy_api_key_preview(proxy_api_key)},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/ui/stats")
async def get_ui_stats(request: Request):
    check_ui_auth(request)
    totals = Counter()
    reasons = Counter()
    latest = None
    try:
        with Path(AUDIT_LOG_FILE).open("r", encoding="utf-8") as audit_file:
            for line in audit_file:
                try:
                    record = json.loads(line)
                    count = int(record.get("count", 0))
                    totals[record.get("direction", "unknown")] += count
                    reasons[record.get("reason", "unknown")] += count
                    latest = record.get("timestamp") or latest
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    return JSONResponse(
        {
            "redactions": sum(totals.values()),
            "inbound": totals["inbound"],
            "outbound": totals["outbound"],
            "reasons": dict(reasons),
            "latest": latest,
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------
def sse_encode(event: dict) -> bytes:
    return (
        "data: "
        + json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        + "\n\n"
    ).encode("utf-8")


async def stream_chat_completion(upstream: httpx.Response):
    """
    Redact text incrementally while preserving OpenAI-style SSE chunks.

    Text is held back so a PII value split across upstream chunks can be
    detected. Tool arguments are buffered per choice/tool and redacted as a
    complete string before being emitted. Pending data is flushed on [DONE]
    and also if the upstream connection closes without [DONE].
    """
    pending_text: Dict[Tuple[int, str], str] = {}
    pending_tool_args: Dict[Tuple[int, int], str] = {}
    stream_counts = Counter()
    carry = b""
    metadata: Dict[str, Any] = {}
    done_seen = False

    def make_chunk(choice_index: int, delta: dict) -> dict:
        chunk = dict(metadata)
        chunk.setdefault("object", "chat.completion.chunk")
        chunk["choices"] = [{
            "index": choice_index,
            "delta": delta,
            "finish_reason": None,
        }]
        return chunk

    async def flush_choice(choice_index: int):
        # Emit buffered text for this choice.
        for (idx, field), tail in list(pending_text.items()):
            if idx == choice_index and tail:
                safe, counts = redact_text(tail)
                stream_counts.update(counts)
                pending_text[(idx, field)] = ""
                if safe:
                    yield sse_encode(make_chunk(idx, {field: safe}))

        # Emit complete, redacted tool arguments before the finish_reason chunk.
        for (idx, tool_index), arguments in list(pending_tool_args.items()):
            if idx == choice_index and arguments:
                safe, counts = redact_text(arguments)
                stream_counts.update(counts)
                pending_tool_args[(idx, tool_index)] = ""
                yield sse_encode(make_chunk(idx, {
                    "tool_calls": [{
                        "index": tool_index,
                        "function": {"arguments": safe},
                    }]
                }))

    async def flush_all():
        choice_indexes = sorted(
            {idx for idx, _field in pending_text}
            | {idx for idx, _tool in pending_tool_args}
        )
        for idx in choice_indexes:
            async for output in flush_choice(idx):
                yield output

    async def handle_raw_event(raw_event: bytes):
        nonlocal metadata, done_seen

        lines = raw_event.splitlines()
        data_lines = [
            line[5:].lstrip(b" ")
            for line in lines
            if line.startswith(b"data:")
        ]

        if not data_lines:
            # Preserve SSE comments and other non-data records.
            yield raw_event + b"\n\n"
            return

        data = b"\n".join(data_lines).decode("utf-8", errors="replace")
        if data.strip() == "[DONE]":
            async for output in flush_all():
                yield output
            audit_redactions("outbound", stream_counts)
            stream_counts.clear()
            done_seen = True
            yield b"data: [DONE]\n\n"
            return

        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            # Do not pass unparseable upstream data without inspection.
            safe, counts = redact_text(data)
            stream_counts.update(counts)
            yield (
                b"data: "
                + json.dumps(safe, ensure_ascii=False).encode("utf-8")
                + b"\n\n"
            )
            return

        if not isinstance(event, dict):
            safe, counts = redact_json(event)
            stream_counts.update(counts)
            yield sse_encode({"data": safe})
            return

        # Retain standard chunk metadata for any final synthetic deltas.
        metadata = {
            key: value
            for key, value in event.items()
            if key != "choices"
        }
        metadata.setdefault("object", "chat.completion.chunk")

        choices = event.get("choices") or []
        for choice in choices:
            if not isinstance(choice, dict):
                continue

            choice_index = int(choice.get("index", 0))
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                delta = {}
                choice["delta"] = delta

            # Hold back the trailing portion of text to catch PII split
            # across adjacent upstream events.
            for field in ("content", "reasoning_content"):
                fragment = delta.get(field)
                if isinstance(fragment, str) and fragment:
                    key = (choice_index, field)
                    combined = pending_text.get(key, "") + fragment
                    cutoff = max(0, len(combined) - max(512, STREAM_HOLD_BACK))

                    if cutoff:
                        boundary = max(
                            combined.rfind(" ", 0, cutoff),
                            combined.rfind("\n", 0, cutoff),
                            combined.rfind("\t", 0, cutoff),
                        )
                        cutoff = boundary + 1 if boundary >= 0 else 0

                    stable, tail = combined[:cutoff], combined[cutoff:]
                    safe, counts = redact_text(stable)
                    stream_counts.update(counts)
                    pending_text[key] = tail

                    if safe:
                        delta[field] = safe
                    else:
                        delta.pop(field, None)

            # Buffer tool arguments, but preserve the other tool-call fields
            # (id, type, function name, etc.) in their original chunks.
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                visible_tool_calls = []
                for tool in tool_calls:
                    if not isinstance(tool, dict):
                        continue
                    tool_copy = dict(tool)
                    tool_index = int(tool_copy.get("index", 0))
                    function = tool_copy.get("function")
                    if isinstance(function, dict):
                        function_copy = dict(function)
                        fragment = function_copy.pop("arguments", None)
                        if isinstance(fragment, str) and fragment:
                            key = (choice_index, tool_index)
                            pending_tool_args[key] = (
                                pending_tool_args.get(key, "") + fragment
                            )
                        if function_copy:
                            tool_copy["function"] = function_copy
                        else:
                            tool_copy.pop("function", None)

                    # Keep identity/metadata chunks, but don't send an
                    # arguments-only fragment before it has been redacted.
                    meaningful = any(
                        key != "index" for key in tool_copy
                    )
                    if meaningful:
                        visible_tool_calls.append(tool_copy)

                if visible_tool_calls:
                    delta["tool_calls"] = visible_tool_calls
                else:
                    delta.pop("tool_calls", None)

            # Flush buffered data before forwarding the finish_reason event.
            if choice.get("finish_reason") is not None:
                async for output in flush_choice(choice_index):
                    yield output

        # Forward the upstream event, with text fragments replaced by their
        # redacted stable portions and tool arguments withheld until complete.
        yield sse_encode(event)

    async for chunk in upstream.aiter_bytes():
        carry += chunk.replace(b"\r\n", b"\n")
        while b"\n\n" in carry:
            raw_event, carry = carry.split(b"\n\n", 1)
            async for output in handle_raw_event(raw_event):
                yield output

    # Some servers close without terminating the last event with a blank line.
    if carry.strip():
        async for output in handle_raw_event(carry):
            yield output

    # Flush remaining text/tool arguments if upstream closed without [DONE].
    if not done_seen:
        async for output in flush_all():
            yield output
        audit_redactions("outbound", stream_counts)


# ---------------------------------------------------------------------------
# OpenAI-compatible proxy route
# ---------------------------------------------------------------------------

def redact_upstream_url_for_logging(url: httpx.URL) -> str:
    has_query = bool(url.query)
    safe_url = url.copy_with(
        username="",
        password="",
        query=b"",
        fragment=""
    )
    safe_url_text = str(safe_url).removesuffix("#").removesuffix("?")
    return f"{safe_url_text}?[redacted]" if has_query else safe_url_text


@app.api_route(
    "/v1/{api_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
)
async def proxy_v1(
    api_path: str,
    request: Request,
    authorization: str | None = Header(default=None)
):
    check_proxy_auth(authorization)

    body_bytes = await request.body()
    outgoing_body = body_bytes
    inbound_counts = Counter()

    if body_bytes:
        try:
            payload = json.loads(body_bytes)
            payload, inbound_counts = redact_json(payload)
            outgoing_body = json.dumps(
                payload, ensure_ascii=False
            ).encode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(
                status_code=400,
                detail="Request body must be valid JSON"
            )

    audit_redactions("inbound", inbound_counts)

    target_url = f"{VLLM_BASE_URL}/{api_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    headers = upstream_headers(request.headers)
    timeout = httpx.Timeout(UPSTREAM_TIMEOUT, connect=15.0)

    # Determine whether this is an SSE streaming request.
    is_stream = False
    if body_bytes:
        try:
            is_stream = bool(json.loads(body_bytes).get("stream", False))
        except Exception:
            pass

    client = httpx.AsyncClient(timeout=timeout)
    upstream_url_for_log = "<unavailable>"

    try:
        # Build the request without sending it yet.
        upstream_request = client.build_request(
            request.method,
            target_url,
            headers=headers,
            content=outgoing_body
        )
        upstream_url_for_log = redact_upstream_url_for_logging(
            upstream_request.url
        )

        # CRITICAL: stream=True prevents httpx from buffering the
        # complete response before returning it.
        upstream = await client.send(
            upstream_request,
            stream=is_stream
        )

        logging.info(
            "Upstream response: method=%s url=%s status=%s streaming=%s content_type=%s",
            request.method,
            upstream_url_for_log,
            upstream.status_code,
            is_stream,
            upstream.headers.get("content-type", "")
        )

        # Handle upstream errors, including errors that might contain PII.
        if upstream.status_code >= 400:
            error_body = await upstream.aread()
            await upstream.aclose()
            await client.aclose()

            try:
                error_payload = json.loads(error_body)
                safe_payload, counts = redact_json(error_payload)
                audit_redactions("outbound", counts)

                return JSONResponse(
                    status_code=upstream.status_code,
                    content=safe_payload
                )
            except Exception:
                # Unknown error payload; don't corrupt bytes by decoding+replace.
                # Return raw bytes as text/plain only if it decodes cleanly; otherwise return bytes.
                try:
                    text = error_body.decode("utf-8")  # no replace
                    safe_text, counts = redact_text(text)
                    audit_redactions("outbound", counts)
                    return Response(
                        content=safe_text,
                        status_code=upstream.status_code,
                        media_type="text/plain",
                    )
                except UnicodeDecodeError:
                    return Response(
                        content=error_body,
                        status_code=upstream.status_code,
                        media_type="application/octet-stream",
                    )

        # Handle SSE streaming.
        if (
            is_stream
            and "text/event-stream" in upstream.headers.get(
                "content-type", ""
            )
        ):

            async def event_generator():
                try:
                    async for item in stream_chat_completion(upstream):
                        yield item
                except httpx.TimeoutException:
                    logging.exception("Upstream timed out during SSE streaming")
                    yield (
                        b'data: {"error":{"message":"Upstream timed out during streaming",'
                        b'"type":"proxy_stream_timeout"}}\\n\\n'
                    )
                except Exception:
                    logging.exception("Error while processing SSE stream")
                    # Do not forward uninspected upstream content.
                    yield (
                        b'data: {"error":{"message":"Proxy failed while processing the stream",'
                        b'"type":"proxy_stream_error"}}\\n\\n'
                    )
                finally:
                    await upstream.aclose()
                    await client.aclose()

            return StreamingResponse(
                event_generator(),
                status_code=upstream.status_code,
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive"
                }
            )

        # If the upstream didn't return SSE, read its normal response.
        response_body = await upstream.aread()
        response_status = upstream.status_code
        response_content_type = upstream.headers.get(
            "content-type", "application/json"
        )
        response_headers = client_response_headers(upstream.headers)

        await upstream.aclose()
        await client.aclose()

        try:
            response_payload = json.loads(response_body)
            safe_payload, counts = redact_json(response_payload)
            audit_redactions("outbound", counts)

            return JSONResponse(
                status_code=response_status,
                content=safe_payload,
                headers=response_headers
            )

        except Exception:
            # Not JSON. Do NOT decode bytes with errors="replace" (it corrupts compressed/binary payloads).
            # Return raw bytes and keep headers minimal/safe.
            return Response(
                content=response_body,
                status_code=response_status,
                media_type=response_content_type,
                headers=response_headers,
            )

    except httpx.TimeoutException:
        await client.aclose()
        logging.error(
            "Upstream request timed out: method=%s url=%s",
            request.method,
            upstream_url_for_log
        )
        raise HTTPException(
            status_code=504,
            detail="Upstream model server timed out"
        )

    except httpx.RequestError as exc:
        await client.aclose()

        logging.error(
            "Upstream request failed: method=%s url=%s error=%s",
            request.method,
            upstream_url_for_log,
            type(exc).__name__
        )

        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream model server"
        )
