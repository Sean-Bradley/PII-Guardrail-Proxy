import json
import logging
import os
import re
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

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
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1").rstrip("/")
VLLM_API_KEY = os.getenv("VLLM_API_KEY", "")
PROXY_API_KEY = os.getenv("PROXY_API_KEY", "")
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "/tmp/pii-guardrail-logs/redactions.jsonl")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "300"))
STREAM_HOLD_BACK = int(os.getenv("STREAM_HOLD_BACK", "512"))

if not PROXY_API_KEY or PROXY_API_KEY == "change-me":
    raise RuntimeError("Set a strong PROXY_API_KEY in your environment.")
if not VLLM_API_KEY:
    raise RuntimeError("Set VLLM_API_KEY in your environment.")

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
# PII recognizers. This is a practical baseline, not a guarantee of detection.
# Credit cards are additionally checked with the Luhn checksum.
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9_-])"
)
SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[ .()-]?)?(?:\(?\d{2,4}\)?[ .-]?)"
    r"\d{3,4}[ .-]?\d{3,4}(?!\w)"
)


def luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def redact_text(value: str) -> Tuple[str, Counter]:
    counts = Counter()

    def replace(pattern, reason, replacement, text):
        def sub(_match):
            counts[reason] += 1
            return replacement
        return pattern.sub(sub, text)

    value = replace(EMAIL_RE, "email", "[REDACTED:EMAIL]", value)
    value = replace(SSN_RE, "ssn", "[REDACTED:SSN]", value)

    def card_sub(match):
        if luhn_valid(match.group(0)):
            counts["credit_card"] += 1
            return "[REDACTED:CREDIT_CARD]"
        return match.group(0)

    value = CARD_RE.sub(card_sub, value)
    value = replace(PHONE_RE, "phone", "[REDACTED:PHONE]", value)
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
app = FastAPI(title="vLLM PII Guardrail Proxy", version="1.0.0")
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


def upstream_headers(incoming_headers) -> Dict[str, str]:
    # Do not forward the client's Authorization header or hop-by-hop headers.
    excluded = {
        "authorization", "host", "content-length", "connection",
        "transfer-encoding", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers", "upgrade",
    }
    headers = {k: v for k, v in incoming_headers.items() if k.lower() not in excluded}
    headers["Authorization"] = f"Bearer {VLLM_API_KEY}"
    return headers


def client_response_headers(upstream_headers) -> Dict[str, str]:
    allowed = {"content-type", "cache-control", "x-request-id"}
    return {k: v for k, v in upstream_headers.items() if k.lower() in allowed}


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

    try:
        # Build the request without sending it yet.
        upstream_request = client.build_request(
            request.method,
            target_url,
            headers=headers,
            content=outgoing_body
        )

        # CRITICAL: stream=True prevents httpx from buffering the
        # complete response before returning it.
        upstream = await client.send(
            upstream_request,
            stream=is_stream
        )

        logging.info(
            "Upstream response: method=%s path=%s status=%s streaming=%s content_type=%s",
            request.method,
            request.url.path,
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
                safe_text, counts = redact_text(
                    error_body.decode("utf-8", errors="replace")
                )
                audit_redactions("outbound", counts)

                return Response(
                    content=safe_text,
                    status_code=upstream.status_code,
                    media_type="text/plain"
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
            safe_text, counts = redact_text(
                response_body.decode("utf-8", errors="replace")
            )
            audit_redactions("outbound", counts)

            return Response(
                content=safe_text,
                status_code=response_status,
                media_type=response_content_type,
                headers=response_headers
            )

    except httpx.TimeoutException:
        await client.aclose()
        raise HTTPException(
            status_code=504,
            detail="Upstream model server timed out"
        )

    except httpx.RequestError as exc:
        await client.aclose()

        logging.error(
            "Upstream request failed: %s",
            type(exc).__name__
        )

        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream model server"
        )
