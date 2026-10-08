"""LLM security gateway: an OpenAI-compatible proxy that inspects traffic.

Request path:
  * injection findings  -> blocked (HTTP 400)
  * PII / secret found  -> redacted before forwarding
Response path:
  * PII / secret found  -> redacted before returning to the caller

Set UPSTREAM_URL to a real OpenAI-compatible base URL (e.g.
https://api.openai.com). If unset, a built-in mock upstream echoes the
last user message, so you can try the gateway without an API key.
"""
from __future__ import annotations

import os
from typing import Awaitable, Callable

import httpx
from fastapi import FastAPI, Request
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


def create_app(upstream: Upstream | None = None, audit: AuditLog | None = None) -> FastAPI:
    app = FastAPI(title="llm-guard-gateway")
    audit = audit or AuditLog(os.getenv("AUDIT_LOG", "audit.jsonl"))
    if upstream is None:
        url = os.getenv("UPSTREAM_URL")
        upstream = http_upstream(url) if url else mock_upstream
    app.state.audit = audit

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/audit")
    async def get_audit():
        return audit.read_all()

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        payload = await request.json()
        messages = payload.get("messages")
        if not isinstance(messages, list):
            return _error(400, "'messages' must be a list", "bad_request")

        # ---- inspect request ----
        req_findings = []
        for msg in messages:
            content = msg.get("content")
            if not isinstance(content, str):
                continue
            inj = detect_injection(content)
            sens = detect_pii(content) + detect_secrets(content)
            req_findings += inj + sens
            if not inj and sens:
                msg["content"] = redact(content)

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
            content = msg.get("content")
            if isinstance(content, str):
                found = detect_pii(content) + detect_secrets(content)
                if found:
                    msg["content"] = redact(content)
                    resp_findings += found
        audit.record("response", "redacted" if resp_findings else "allowed", resp_findings)
        return result

    return app


app = create_app()
