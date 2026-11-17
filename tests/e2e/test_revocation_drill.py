"""
A short run of the revocation and failure drill (scripts/revocation_drill.py) on every build: real core, gateway and demo MCP server processes on loopback,
an agent calling through the gateway while an operator freezes, revokes and freezes everything. It fails when a refusal takes longer than the 5 s promise,
when an agent is never refused, or when a call is allowed after the first refusal. The failure-mode scenarios (core stopped or killed, upstream killed)
and the full 20-trial measurement run by hand: see docs/security/measurements/.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "revocation_drill.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("revocation_drill", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


drill = load()


def test_a_measure_holds_only_inside_the_promise_and_with_no_allow_after_a_refusal() -> None:
    ok = drill.Measure("x", seconds=[0.4, 1.0, 4.9])
    assert ok.held
    assert not drill.Measure("x", seconds=[0.4, 5.1]).held, "slower than the 5 s promise"
    assert not drill.Measure("x", seconds=[0.4], never_refused=1).held, "an agent that was never refused"
    assert not drill.Measure("x", seconds=[0.4], allowed_after_refusal=1).held, "an allow after the first refusal"
    assert drill.Measure("x").row().startswith("| x | 0 | n/a")


def test_freeze_revoke_and_freeze_all_take_effect_within_the_promise_on_real_processes() -> None:
    assert drill.main(["--trials", "2", "--quick"]) == 0
