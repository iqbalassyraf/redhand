"""
`scripts/benchmark_gateway.py` measures the gateway's own cost against the CLAUDE.md section 8 budget. It went stale once (its fake core
omitted fields the gateway had started to require, so every call was denied and it could not run), so this test builds its gateway and
makes calls: if the gateway grows a required field or argument and the script is not updated, this fails instead of the script rotting.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "benchmark_gateway.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("benchmark_gateway", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_the_benchmark_gateway_allows_a_call_and_the_script_measures_it() -> None:
    bench = _load()
    gateway, token = bench.build(2.0)
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_invoices", "arguments": {}}}
    response = await gateway.handle(server="xero", message=message, bearer_token=token, client_headers={}, upstream_authorization=None)
    assert response.status_code == 200, response.body
    result = await bench.run_case("test", 2.0, 20)  # asserts a 200 on every call
    assert set(result) == {"p50", "p99", "max"} and result["p50"] > 0


@pytest.mark.asyncio
async def test_the_benchmark_notices_a_denial() -> None:
    """If the fake core stopped satisfying the gateway the calls would be denied: the script must fail, not print numbers."""
    bench = _load()
    bench.STATE["status"] = "revoked"
    try:
        with pytest.raises(AssertionError):
            await bench.run_case("revoked", 2.0, 5)
    finally:
        bench.STATE["status"] = "active"
