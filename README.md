# llm-guard-gateway

A small security proxy that sits between your app and an LLM API.
It inspects traffic in both directions and blocks or flags risky content.

## Status

Early prototype (phase 1: software only).

## Planned features

- [ ] Prompt-injection detection on incoming requests
- [ ] PII and secret detection on requests and responses
- [ ] Audit log of every decision
- [ ] OpenAI-compatible `/v1/chat/completions` proxy endpoint
- [ ] Phase 2: hardware integration

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```
