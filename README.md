# PII Guardrail Proxy for vLLM + RAG System

A FastAPI proxy for OpenAI-compatible vLLM APIs. It has a client-facing bearer token,
a separate upstream bearer token, inbound/outbound PII redaction, metadata-only
redaction audit logs, and SSE support for chat completions.

## Files

- `main.py` — proxy implementation
- `requirements.txt` — Python dependencies
- `.env` — local configuration (replace the example secrets)
- `Dockerfile` — container build

## Run with Docker

```bash
cp .env .env.local  # optional; edit .env directly if preferred
docker build -t pii-guardrail-proxy .
docker run -d --name pii-guardrail-proxy --env-file .env -p 8080:8080 pii-guardrail-proxy
```

If vLLM is running on the Docker host, `host.docker.internal` works on Docker Desktop.
On Linux, add `--add-host=host.docker.internal:host-gateway` to `docker run`, or set
`VLLM_BASE_URL` in `data/ui-config.json` to a reachable address on your Docker network.

## Configure the client UI

Set its OpenAI-compatible base URL to:

`http://<proxy-host>:8080/v1`

Set its API key / bearer token to the Proxy API Key configured in the Operations UI.

The proxy authenticates that token, then replaces the Authorization header with the
`VLLM_API_KEY` from `data/ui-config.json` for upstream requests. The proxy key is also
stored in `data/ui-config.json`; `PROXY_API_KEY` from the process environment is used
only as a startup fallback when the JSON value is absent, to support migration.

## Operations UI

Open `http://<proxy-host>:8080/` to access the proxy operations console. Set a
separate, strong `UI_ACCESS_KEY` in `.env` or the process environment to unlock it.
The console uses an HttpOnly session cookie that expires after 12 hours. If the key
is unset, UI API access is disabled.

On first startup, provide a strong `PROXY_API_KEY` in `data/ui-config.json` or keep
the existing environment variable as a migration fallback. After opening the console,
save the Proxy API Key from Application settings to persist it in the JSON file.

The console shows aggregate redaction counts from the audit log and provides controls
for the upstream URL/key, client-facing Proxy API Key, and PII checks. Settings are persisted to `UI_CONFIG_FILE`,
which defaults to `./data/ui-config.json` relative to the process working directory.
The file contains the upstream and proxy API keys, so keep it private. In Docker, mount
`/app/data` to persist settings across container replacement, for example:

```bash
docker run -d --name pii-guardrail-proxy --env-file .env \
   -p 8080:8080 -v pii-guardrail-data:/app/data \
   pii-guardrail-proxy
```

The vLLM Base URL must end in `/v1` or `/openai/v1` (for example, RunPod's
`https://api.runpod.ai/v2/<endpoint-id>/openai/v1`). **Check Models** tests the
`/models` endpoint using the entered bearer token. A cold provider worker may take
several minutes to respond; a successful check saves the tested URL and key
automatically.

Saving settings applies the upstream URL and API keys immediately and persists them
for future starts. PII check settings take effect immediately and persist for future
starts. The API accepts a JSON object up to 256 KB.

## Example request

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer replace-this-with-a-long-random-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "your-model",
    "messages": [
      {"role": "user", "content": "Email me at alice@example.com"}
    ],
    "stream": true
  }'
```

## Audit log

Each redaction creates a JSONL record like:

```json
{"timestamp":"2026-11-23T12:00:00+00:00","direction":"inbound","reason":"email","count":1}
```

The matched text is never included. The log file is `/app/logs/redactions.jsonl`
inside the container; mount `/app/logs` to persist it.

## Important security and production notes

1. **Detection is not perfect.** Enabled checks with a non-empty `regex` and
   `action: "redact"` in `data/ui-config.json` are applied to text. Other actions such
   as `mask` and `hash` are not currently implemented. Regex rules do not identify
   every kind of PII or obfuscated text; test them against your data and consider
   Microsoft Presidio plus suitable recognizers for a production deployment.
2. **RAG must be covered.** This proxy redacts JSON request fields recursively, including
   messages and tool payloads. If your RAG system retrieves documents outside this
   request path (for example, a separate vector database or direct retrieval service),
   put equivalent controls on that path too. Retrieved content returned by vLLM is
   inspected on the way back.
3. **Streaming behavior.** Text and reasoning deltas are held back by a rolling window to catch PII
   split across SSE chunks. Tool-call arguments are buffered until the choice finishes.
   This adds latency and can delay tool-call argument delivery. Tune
   `STREAM_HOLD_BACK` after testing. Do not reduce it below the maximum length of
   sensitive tokens you need to detect.
4. The proxy handles OpenAI-compatible JSON endpoints under `/v1/`. It does not proxy
   multipart uploads or arbitrary binary request bodies.
5. Use TLS between the client and proxy, restrict network access, rotate both tokens,
   and protect the audit log. Consider log rotation and centralized access controls.
6. For stronger assurance, add rate limiting, request-size limits, structured metrics,
   automated tests, and a fail-closed policy for upstream/inspection errors.
7. Ensure reverse proxies do not buffer SSE responses. The response includes
   `X-Accel-Buffering: no`.
