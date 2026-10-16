"""LLM security gateway: an OpenAI-compatible proxy that inspects traffic.

Request path:
  * injection findings  -> blocked (HTTP 400)
  * PII / secret found  -> redacted before forwarding
Response path:
  * PII / secret found  -> redacted before returning to the caller

Set UPSTREAM_URL to a real OpenAI-compatible base URL (e.g.
https://api.openai.com). If unset, a built-in mock upstream echoes the
last user message, so you can try the gateway without an API key.

Set GATEWAY_API_KEY to require callers to send it in the X-Gateway-Key
header (on every route except /health). If unset, the gateway is open:
fine on localhost, unsafe anywhere reachable from outside.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Awaitable, Callable, Iterator

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .audit import AuditLog
from .detectors import detect_injection, detect_pii, detect_secrets, redact

Upstream = Callable[[dict, dict], Awaitable[dict]]


async def mock_upstream(payload: dict, headers: dict) -> dict:
    """Echoes the last user message. Handy for demos and tests."""
    last = next(
        (m.get("content", "") for m in reversed(payload.get("messages", [])) if m.get("role") == "user"),
        "",
    )
    return {
        "id": "mock-1",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": f"echo: {last}"}, "finish_reason": "stop"}],
    }


def http_upstream(base_url: str) -> Upstream:
    async def call(payload: dict, headers: dict) -> dict:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(f"{base_url.rstrip('/')}/v1/chat/completions", json=payload, headers=headers)
            r.raise_for_status()
            return r.json()

    return call


def _error(status: int, message: str, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"message": message, "type": "gateway_policy", "code": code}})


def _text_slots(msg: dict) -> Iterator[tuple[dict, str]]:
    """Yield (container, key) for every text field in a message.

    Covers both content shapes OpenAI accepts: a plain string, and a list
    of parts like [{"type": "text", "text": "..."}]. Non-text parts
    (images, audio) are skipped.
    """
    content = msg.get("content")
    if isinstance(content, str):
        yield msg, "content"
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                yield part, "text"


def create_app(
    upstream: Upstream | None = None,
    audit: AuditLog | None = None,
    gateway_key: str | None = None,
) -> FastAPI:
    app = FastAPI(title="llm-guard-gateway")
    audit = audit or AuditLog(os.getenv("AUDIT_LOG", "audit.jsonl"))
    if upstream is None:
        url = os.getenv("UPSTREAM_URL")
        upstream = http_upstream(url) if url else mock_upstream
    gateway_key = gateway_key or os.getenv("GATEWAY_API_KEY")
    if not gateway_key:
        logging.getLogger(__name__).warning(
            "GATEWAY_API_KEY is not set: the gateway and /audit are open to anyone who can reach this port."
        )
    app.state.audit = audit

    async def require_key(request: Request) -> None:
        if not gateway_key:
            return
        given = request.headers.get("x-gateway-key", "")
        if not secrets.compare_digest(given.encode(), gateway_key.encode()):
            raise HTTPException(status_code=401, detail="Missing or invalid X-Gateway-Key")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/audit", dependencies=[Depends(require_key)])
    async def get_audit():
        return audit.read_all()

    @app.post("/v1/chat/completions", dependencies=[Depends(require_key)])
    async def chat(request: Request):
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "Request body must be valid JSON", "bad_request")
        if not isinstance(payload, dict):
            return _error(400, "Request body must be a JSON object", "bad_request")
        messages = payload.get("messages")
        if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
            return _error(400, "'messages' must be a list of objects", "bad_request")

        # ---- inspect request ----
        req_findings = []
        for msg in messages:
            for container, key in _text_slots(msg):
                text = container[key]
                inj = detect_injection(text)
                sens = detect_pii(text) + detect_secrets(text)
                req_findings += inj + sens
                if not inj and sens:
                    container[key] = redact(text)

        if any(f.category == "injection" for f in req_findings):
            audit.record("request", "blocked", req_findings)
            return _error(400, "Request blocked: possible prompt injection.", "prompt_injection")
        audit.record("request", "redacted" if req_findings else "allowed", req_findings)

        # ---- forward ----
        fwd_headers = {}
        if "authorization" in request.headers:
            fwd_headers["Authorization"] = request.headers["authorization"]
        try:
            result = await upstream(payload, fwd_headers)
        except httpx.HTTPError as exc:
            return _error(502, f"Upstream error: {exc.__class__.__name__}", "upstream_error")

        # ---- inspect response ----
        resp_findings = []
        for choice in result.get("choices", []):
            msg = choice.get("message", {})
            for container, key in _text_slots(msg):
                text = container[key]
                found = detect_pii(text) + detect_secrets(text)
                if found:
                    container[key] = redact(text)
                    resp_findings += found
        audit.record("response", "redacted" if resp_findings else "allowed", resp_findings)
        return result

    return app


app = create_app()
