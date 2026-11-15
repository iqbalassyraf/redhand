"""
The gateway's audit log is a hash chain held in memory. It used to grow without limit (a process that runs for weeks would run out of
memory) and its optional file append ran on the request thread. It is now bounded: the oldest records are dropped from memory, the hash of the
last dropped record anchors the retained window so the window still verifies, and the verify answer says how much is held. The durable,
complete record of every decision is the Black Box in redhand-core (CLAUDE.md sections 8 and 9). The file append moves to a writer thread.
"""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time

from agentwall.src.telemetry.audit_logger import MAX_RECORDS_DEFAULT, TamperEvidentAuditLogger


def add(log: TamperEvidentAuditLogger, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        log.record(trace_id=f"t{i}", span_id=f"s{i}", agent_id="a", caller_identity="c", tool_name="tool", arguments={"k": i},
                   firewall_decision="ALLOW")


def test_the_default_bound_is_stated_and_sane() -> None:
    assert 1_000 <= MAX_RECORDS_DEFAULT <= 100_000


def test_the_log_never_holds_more_than_its_bound_and_counts_what_it_dropped() -> None:
    log = TamperEvidentAuditLogger(max_records=100)
    add(log, 250)
    stats = log.stats()
    assert (stats.retained, stats.dropped, stats.total) == (100, 150, 250)
    assert [r["trace_id"] for r in log.get_recent(3)] == ["t247", "t248", "t249"]


def test_the_retained_window_still_verifies_after_old_records_are_dropped() -> None:
    log = TamperEvidentAuditLogger(max_records=50)
    add(log, 500)
    assert log.verify_chain_integrity() == (True, None)
    add(log, 10, start=500)  # the chain continues across the drop
    assert log.verify_chain_integrity() == (True, None)


def test_tampering_inside_the_window_is_still_detected_after_a_drop() -> None:
    log = TamperEvidentAuditLogger(max_records=50)
    add(log, 120)
    log._records[10].tool_name = "forged"
    ok, reason = log.verify_chain_integrity()
    assert ok is False and "Tampered hash" in (reason or "")


def test_a_broken_first_link_in_the_window_is_detected() -> None:
    log = TamperEvidentAuditLogger(max_records=50)
    add(log, 120)
    log._records[0].prev_record_hash = "0" * 64  # does not match the hash of the record that was dropped
    ok, reason = log.verify_chain_integrity()
    assert ok is False and "Broken link at index 0" in (reason or "")


def test_a_log_that_never_dropped_anything_verifies_from_genesis() -> None:
    log = TamperEvidentAuditLogger(max_records=50)
    add(log, 10)
    assert log.stats().dropped == 0 and log.verify_chain_integrity() == (True, None)
    log._records[0].prev_record_hash = "x"
    assert log.verify_chain_integrity()[0] is False


def test_the_bound_must_be_positive() -> None:
    for bad in (0, -1):
        try:
            TamperEvidentAuditLogger(max_records=bad)
        except ValueError:
            continue
        raise AssertionError("a non-positive bound was accepted")


def test_records_reach_the_file_through_the_writer_thread(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = TamperEvidentAuditLogger(log_file_path=str(path), max_records=10)
    add(log, 25)
    log.flush()
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert len(lines) == 25 and lines[-1]["trace_id"] == "t24"  # the file keeps everything; only memory is bounded
    log.close()


def test_a_slow_disk_does_not_block_the_caller(tmp_path: Path, monkeypatch) -> None:
    log = TamperEvidentAuditLogger(log_file_path=str(tmp_path / "slow.jsonl"), max_records=10)
    release = threading.Event()
    seen_on: list[str] = []

    def slow(line: str) -> None:
        seen_on.append(threading.current_thread().name)
        release.wait(5)

    monkeypatch.setattr(log, "_append_line", slow)
    started = time.perf_counter()
    add(log, 5)
    assert time.perf_counter() - started < 0.5  # record() returned without waiting for the disk
    release.set()
    log.flush()
    assert seen_on and all(name != threading.main_thread().name for name in seen_on)
    log.close()


def test_a_failing_file_never_breaks_recording(tmp_path: Path) -> None:
    log = TamperEvidentAuditLogger(log_file_path=str(tmp_path / "missing-dir" / "audit.jsonl"), max_records=10)
    add(log, 3)
    log.flush()
    assert log.stats().retained == 3 and log.stats().file_errors >= 1
    log.close()
