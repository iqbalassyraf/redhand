"""
A fake Anthropic Messages endpoint for the model-proxy benchmark and demos (Phase 4.5 B5). It answers `POST /v1/messages` with a canned reply and the token usage
the real API reports, as JSON or as a server-sent stream, after a configurable delay. It checks nothing and calls nothing: never expose it.

  FAKE_PROVIDER_LATENCY_MS   delay before the (non-stream) answer or the first stream event, default 0
  FAKE_PROVIDER_CHUNKS       number of text deltas in a stream, default 50
  FAKE_PROVIDER_CHUNK_MS     delay between stream events, default 20
  uv run uvicorn examples.fake_model_provider:app --port 9300
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="Fake model provider")
LATENCY = float(os.environ.get("FAKE_PROVIDER_LATENCY_MS", "0")) / 1000
CHUNKS = int(os.environ.get("FAKE_PROVIDER_CHUNKS", "50"))
CHUNK_DELAY = float(os.environ.get("FAKE_PROVIDER_CHUNK_MS", "20")) / 1000


def event(name: str, data: dict[str, Any]) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/messages")
async def messages(request: Request) -> Any:
    body = await request.json()
    model = str(body.get("model", "fake"))
    if LATENCY:
        await asyncio.sleep(LATENCY)
    if not body.get("stream"):
        return JSONResponse({"id": "msg_fake", "type": "message", "role": "assistant", "model": model, "content": [{"type": "text", "text": "ok"}],
                             "stop_reason": "end_turn", "usage": {"input_tokens": 25, "output_tokens": 10}})

    async def stream() -> AsyncIterator[bytes]:
        yield event("message_start", {"type": "message_start", "message": {"id": "msg_fake", "model": model, "usage": {"input_tokens": 25, "output_tokens": 1}}})
        for i in range(CHUNKS):
            await asyncio.sleep(CHUNK_DELAY)
            yield event("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"w{i} "}})
        yield event("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": CHUNKS}})
        yield event("message_stop", {"type": "message_stop"})

    return StreamingResponse(stream(), media_type="text/event-stream")
