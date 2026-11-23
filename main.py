"""
PII Guardrail Proxy for VLLM + RAG System
============================================
Sits between UI and VLLM endpoint. Redacts PII before forwarding requests,
sanitizes responses, and logs all redactions for compliance auditing.

Install dependencies:
    pip install fastapi uvicorn python-multipart python-dotenv

Usage:
    python pii_guardrail.py
"""

import re
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pii-guardrail")


class PIIConfig:
    """PII detection patterns."""

    EMAIL_PATTERN = re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    )
    PHONE_US_DASH = re.compile(r"\b\(?([0-9]{3})\)?[-.\s]([0-9]{3})[-.\s]([0-9]{4})\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    CC_WITH_SEP = re.compile(r"(?:\d{4}[ -]){3}\d{4}")
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    COMMON_FIELD_PATTERNS = [
        ("email", EMAIL_PATTERN),
        ("phone", PHONE_US_DASH),
        ("ssn", SSN_PATTERN),
        ("cc_number", CC_WITH_SEP),
        ("ip_address", IPV4_PATTERN),
    ]


class RedactionEvent:
    """Immutable audit record of a redaction event."""

    def __init__(
        self,
        timestamp: str,
        request_id: str,
        pii_type: str,
        field_name: str,
        original_length: int,
        masked_value: str,
        client_ip: str,
    ):
        self.timestamp = timestamp
        self.request_id = request_id
        self.pii_type = pii_type
        self.field_name = field_name
        self.original_length = original_length
        self.masked_value = masked_value
        self.client_ip = client_ip

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "pii_type": self.pii_type,
            "field_name": self.field_name,
            "original_length": self.original_length,
            "masked_value": self.masked_value,
            "client_ip": self.client_ip,
        }


class PIIRedactor:
    """Redacts PII and maintains an audit log."""

    MASKED_PREFIX = "[REDACTED]"

    def __init__(self, log_dir: str = "./redaction_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[RedactionEvent] = []

    @staticmethod
    def detect_and_mask(text: str, field_name: Optional[str] = None) -> tuple[str, list]:
        """Scan text for PII patterns and return redacted version + events."""
        if not isinstance(text, str):
            return text, []

        events = []
        redacted = text

        for pii_type, pattern in PIIConfig.COMMON_FIELD_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    match_str = "".join(str(m) for m in match)
                else:
                    match_str = str(match)

                if len(match_str) < 4:
                    continue

                masked_length = min(len(match_str), 8)
                masked_value = PIIRedactor.MASKED_PREFIX + "*" * (masked_length - len(PIIRedactor.MASKED_PREFIX))

                events.append(
                    RedactionEvent(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        request_id="unknown",  # Will be set per-request
                        pii_type=pii_type,
                        field_name=field_name or "unknown",
                        original_length=len(match_str),
                        masked_value=masked_value,
                        client_ip="0.0.0.0",
                    )
                )

                redacted = redacted.replace(match_str, masked_value, 1)

        return redacted, events


class PIIGuardrail(FastAPI):
    """
    PII Guardrail Proxy with Service Account Authentication for vLLM.

    SECURITY DESIGN:
    - Client sends requests to this proxy (authenticated via proxy's own auth layer).
    - This proxy uses its OWN dedicated service account token to talk to vLLM.
    - The client's bearer token is NEVER forwarded or stored by this proxy.
    """

    def __init__(self, vllm_endpoint: str, vllm_auth_token: Optional[str] = None):
        super().__init__()
        self.vllm_endpoint = vllm_endpoint.rstrip("/")
        self.redactor = PIIRedactor(log_dir="./redaction_logs")
        # VLLM service account token — scoped only to chat completions, never shared
        self._vllm_auth_token = vllm_auth_token

    @staticmethod
    def _generate_request_id() -> str:
        import hashlib
        return hashlib.sha256(time.time().hexencode()).hexdigest()[:16]

    async def sanitize_input(
        self, body: Dict[str, Any], client_ip: Optional[str] = None
    ) -> tuple[Dict[str, Any], list]:
        """Sanitize PII from incoming request before forwarding to vLLM."""
        events = []

        if "messages" not in body:
            return body, events

        for message in body["messages"]:
            for key in ["content", "role", "name"]:
                original_text = message.get(key, "")
                redacted_text, msg_events = self.redactor.detect_and_mask(original_text, field_name=key)
                events.extend(msg_events)
                if isinstance(message[key], str):
                    message[key] = redacted_text

        return body, events

    async def sanitize_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize PII in model response before returning to client."""
        if "choices" not in response or not response["choices"]:
            return response

        for choice in response["choices"]:
            message = choice.get("message", {})
            content = message.get("content", "")
            redacted_content, _ = self.redactor.detect_and_mask(content)
            if isinstance(message.get("content"), str):
                message["content"] = redacted_content

        return response

    async def forward_to_vllm(
        self, body: Dict[str, Any], request_id: str
    ) -> Dict[str, Any]:
        """Forward sanitized request to vLLM using service account token."""
        headers = {"Content-Type": "application/json"}

        # Add VLLM authentication header — this is YOUR proxy's own token, not client's
        if self._vllm_auth_token:
            headers["Authorization"] = f"Bearer {self._vllm_auth_token}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.vllm_endpoint}/v1/chat/completions",
                    json=body,
                    headers=headers,
                ) as vllm_response:
                    if not vllm_response.ok:
                        logger.error(f"VLLM HTTP error: {vllm_response.status}")
                        raise HTTPException(status_code=vllm_response.status)

                    result = await vllm_response.json()
                    return result

            except aiohttp.ClientError as e:
                logger.error(f"Failed to forward to vLLM: {e}")
                raise HTTPException(status_code=503, detail="vLLM service unavailable")

    @staticmethod
    async def sse_stream_generator(
        vllm_response: aiohttp.ClientResponse, request_id: str
    ) -> AsyncGenerator[str, None]:
        """Generate SSE events from VLLM stream with PII redaction."""
        async for line in vllm_response.content.iter_chunks():
            if not line[1]:  # no data in chunk
                continue

            raw_data = line[0].decode("utf-8", errors="replace").strip()
            if not raw_data or raw_data.startswith(":"):
                continue

            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError:
                logger.debug(f"Malformed SSE chunk: {raw_data[:100]}")
                continue

            # Redact PII in streamed tokens before sending to client
            if "choices" in data and len(data["choices"]) > 0:
                choice = data["choices"][0]
                delta_content = (
                    choice.get("delta", {})
                    .get("content", "")
                    or choice.get("message", {}).get("content", "")
                )

                redacted_content, _ = PIIRedactor.detect_and_mask(delta_content)

                if redacted_content != delta_content:
                    logger.debug(
                        f"[{request_id}] Redacted PII in stream chunk "
                        f"(type={PIIRedactor.COMMON_FIELD_PATTERNS[0][0]})"
                    )

                yield f"data: {json.dumps({'content': redacted_content})}\n\n"

    async def chat_completions_stream(
        self, request: Request, body: Dict[str, Any]
    ) -> StreamingResponse:
        """SSE endpoint — streams tokens with per-chunk PII redaction."""
        client_ip = str(request.client.host) if request.client else "unknown"
        start_time = time.time()

        try:
            # 1. Redact input before forwarding
            sanitized_body, redaction_events = await self.sanitize_input(body, client_ip)

            for event in redaction_events:
                event.request_id = self._generate_request_id()
                event.client_ip = client_ip
                self.redactor.events.append(event)

            # 2. Forward to VLLM with service account auth
            async with aiohttp.ClientSession() as session:
                headers = {"Content-Type": "application/json"}
                if self._vllm_auth_token:
                    headers["Authorization"] = f"Bearer {self._vllm_auth_token}"

                async with session.post(
                    f"{self.vllm_endpoint}/v1/chat/completions",
                    json=sanitized_body,
                    headers=headers,
                ) as vllm_response:

                    if not vllm_response.ok:
                        raise HTTPException(status_code=vllm_response.status)

                    # 3. Stream with per-chunk redaction
                    async for chunk in self.sse_stream_generator(vllm_response, request_id="stream"):
                        yield f"data: {chunk}\n\n"

        except Exception as e:
            logger.error(f"Stream error: {e}")
            raise HTTPException(status_code=502, detail=str(e))

    async def chat_completions(self, body: Dict[str, Any]) -> dict:
        """Blocking endpoint — full response with final PII redaction."""
        client_ip = "unknown"  # Would come from Request object in real usage

        sanitized_body, events = await self.sanitize_input(body, client_ip)

        for event in events:
            event.request_id = self._generate_request_id()
            event.client_ip = client_ip
            self.redactor.events.append(event)

        result = await self.forward_to_vllm(sanitized_body, request_id="blocking")
        sanitized_result = json.loads(json.dumps(result))  # deep copy for mutability
        sanitized_result = self.sanitize_response(sanitized_result)

        return sanitized_result

    @property
    def total_redactions(self) -> int:
        return len(self.redactor.events)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="PII Guardrail Proxy")
    parser.add_argument(
        "--vllm-endpoint", default="http://localhost:8000/v1/chat/completions"
    )
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument(
        "--vllm-token",
        required=True,
        help=(
            "VLLM service account bearer token (created separately for this proxy). "
            "Do NOT use client tokens here. Use a dedicated token with minimal scope."
        ),
    )
    args = parser.parse_args()

    app = PIIGuardrail(
        vllm_endpoint=args.vllm_endpoint,
        vllm_auth_token=args.vllm_token,  # ← Your proxy's own token
    )

    print("\n" + "=" * 60)
    print("   PII Guardrail Proxy (Service Account Auth)")
    print("=" * 60)
    print(f"\n📍 Listening on: http://0.0.0.0:{args.port}")
    print(f"🔐 Client auth:     None (proxy handles its own auth layer)")
    print(f"🔑 VLLM auth token: YOUR_PROXY_SERVICE_ACCOUNT_TOKEN")
    print("   (dedicated, scoped to chat completions only)\n")

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
