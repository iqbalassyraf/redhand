"""
The gateway reads a request body while counting it (H2.3). `request.body()` buffers the whole body before any length check, so a chunked
upload with no Content-Length (or a false one) made the gateway hold all of it first. Reading now stops at the limit.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import HTTPException

from agentwall.src.main import _read_json_body


class FakeRequest:
    def __init__(self, chunks: list[bytes], declared: str | None = None) -> None:
        self.headers: dict[str, str] = {"content-length": declared} if declared is not None else {}
        self._chunks = chunks
        self.pulled = 0

    async def stream(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            self.pulled += 1
            yield chunk

    async def body(self) -> bytes:
        raise AssertionError("the whole body must never be buffered before the limit is checked")


@pytest.mark.asyncio
async def test_a_chunked_body_over_the_limit_is_refused_after_the_limit_not_after_the_whole_body() -> None:
    request = FakeRequest([b"x" * 400] * 100)  # 40,000 bytes, no Content-Length
    with pytest.raises(HTTPException) as caught:
        await _read_json_body(request, 1000)  # type: ignore[arg-type]
    assert caught.value.status_code == 413
    assert request.pulled == 3, f"reading must stop at the chunk that passes the limit (pulled {request.pulled})"


@pytest.mark.asyncio
async def test_a_false_content_length_does_not_hide_a_larger_body() -> None:
    request = FakeRequest([b"x" * 600, b"x" * 600], declared="10")
    with pytest.raises(HTTPException) as caught:
        await _read_json_body(request, 1000)  # type: ignore[arg-type]
    assert caught.value.status_code == 413


@pytest.mark.asyncio
async def test_a_declared_length_over_the_limit_is_refused_without_reading() -> None:
    request = FakeRequest([b"{}"], declared="5000")
    with pytest.raises(HTTPException) as caught:
        await _read_json_body(request, 1000)  # type: ignore[arg-type]
    assert caught.value.status_code == 413 and request.pulled == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("chunks", "expected"),
    [([b'{"a":', b" 1}"], {"a": 1}), ([b""], None), ([b"not json"], None), ([b'{"a": NaN}'], None)],
)
async def test_a_body_within_the_limit_is_parsed_as_before(chunks: list[bytes], expected: Any) -> None:
    assert await _read_json_body(FakeRequest(chunks), 1000) == expected  # type: ignore[arg-type]
