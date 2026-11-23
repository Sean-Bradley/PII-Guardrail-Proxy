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
`VLLM_BASE_URL` to a reachable address on your Docker network.

## Configure the client UI

Set its OpenAI-compatible base URL to:

`http://<proxy-host>:8080/v1`

Set its API key / bearer token to the value of `PROXY_API_KEY`.

The proxy authenticates that token, then replaces the Authorization header with
`Bearer $VLLM_API_KEY` for upstream requests.

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

1. **Detection is not perfect.** These regular expressions cover common email, phone,
   US SSN and Luhn-valid payment-card formats. They do not identify every kind of PII,
   names, addresses, dates of birth, account numbers, or obfuscated text. Test against
   your own data and consider Microsoft Presidio plus suitable recognizers for a
   production deployment.
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
