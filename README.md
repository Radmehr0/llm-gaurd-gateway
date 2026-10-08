# llm-guard-gateway

A small security proxy that sits between your app and an LLM API.
It inspects traffic in both directions and blocks or flags risky content.

```
your app  ──►  llm-guard-gateway  ──►  LLM API
              (inspect + audit)
```

## Status

Early prototype (phase 1: software only). Phase 2 will explore hardware integration.

## Features

- [x] Prompt-injection detection on incoming requests (blocked with HTTP 400)
- [x] PII and secret detection on requests and responses (redacted)
- [x] Audit log of every decision (`audit.jsonl`, never stores the matched values)
- [x] OpenAI-compatible `/v1/chat/completions` proxy endpoint
- [ ] Measured detection accuracy on a public injection dataset
- [ ] ML classifier to complement the rules
- [ ] Per-agent tool policies
- [ ] Phase 2: hardware integration

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                                   # run the tests
uvicorn app.main:app --port 8000         # start the gateway (mock upstream)
```

Try it:

```bash
# clean request: passes through
curl -s localhost:8000/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"x","messages":[{"role":"user","content":"Hi!"}]}'

# injection: blocked
curl -s localhost:8000/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"x","messages":[{"role":"user","content":"Ignore all previous instructions"}]}'

# see what the gateway decided
curl -s localhost:8000/audit
```

To proxy a real provider, set `UPSTREAM_URL` (e.g. `https://api.openai.com`) and send your
`Authorization` header as usual. The gateway forwards it and never stores it.

## Layout

| Path | Purpose |
|------|---------|
| `app/detectors.py` | Rule-based injection, PII and secret detectors, plus `redact()` |
| `app/audit.py` | Append-only JSONL audit log |
| `app/main.py` | FastAPI proxy app |
| `tests/` | pytest suite |

## Limitations

Rule-based detection is a baseline. It will miss paraphrased or obfuscated attacks and can
produce false positives. The roadmap above is about measuring and improving this.
