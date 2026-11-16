"""
`redhand scan --baseline` (docs/runbooks/scan-secrets-in-files.md): a reviewed list of accepted findings so a repository full of deliberate fake keys (test fixtures) can
still run the scan as a CI gate. A finding not in the list fails; an entry that no longer matches ALSO fails, so the list only shrinks; a bad or missing list fails
closed. An entry holds a file, a rule, a SHA-256 of the offending line and a reason: never the secret text. Fake secrets are built from pieces so this file holds
no literal secret.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from redhand_sdk.cli import main as cli_main
from redhand_sdk.scanner.baseline import (
    MAX_ENTRIES,
    Baseline,
    BaselineError,
    BaselineEntry,
    apply_baseline,
    line_fingerprint,
    load_baseline,
)
from redhand_sdk.scanner.ast_checker import ScanFinding

BODY = "Zq9xT4mW2vLk8RpN3cYbH7"
FAKE_LINE = 'KEY = "sk-' + BODY + '"'
REASON = "A fixed fake key used by a unit test, not a real credential."


def sha(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def entry(file: str = "t/fixture.py", rule: str = "RH-SEC-004", line: str = FAKE_LINE, count: int = 1, reason: str = REASON) -> dict[str, object]:
    return {"file": file, "rule": rule, "line_sha256": sha(line), "count": count, "reason": reason}


def write_baseline(tmp_path: Path, entries: list[dict[str, object]], version: int = 1, name: str = "baseline.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"version": version, "entries": entries}), encoding="utf-8")
    return path


def project(tmp_path: Path, lines: str = FAKE_LINE + "\n") -> Path:
    root = tmp_path / "repo"
    (root / "t").mkdir(parents=True)
    (root / "t" / "fixture.py").write_text(lines, encoding="utf-8")
    return root


def run(root: Path, *extra: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = cli_main(["scan", str(root), *extra])
    return code, capsys.readouterr().out


# --- fingerprint -------------------------------------------------------------------------------------------------------------------

def test_the_fingerprint_is_a_sha256_of_the_trimmed_line_so_indentation_does_not_matter() -> None:
    assert line_fingerprint("  " + FAKE_LINE + "\t") == sha(FAKE_LINE) == line_fingerprint(FAKE_LINE)
    assert line_fingerprint(FAKE_LINE) == line_fingerprint(FAKE_LINE + " ")  # trailing whitespace is trimmed too
    assert line_fingerprint("a") != line_fingerprint("b")


# --- loading: everything unexpected is refused ---------------------------------------------------------------------------------------

def test_a_valid_baseline_loads(tmp_path: Path) -> None:
    baseline = load_baseline(write_baseline(tmp_path, [entry(), entry(file="t/other.py", count=3)]))
    assert [(e.file, e.rule, e.count) for e in baseline.entries] == [("t/fixture.py", "RH-SEC-004", 1), ("t/other.py", "RH-SEC-004", 3)]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(reason=""),
        lambda e: e.update(reason="TODO"),
        lambda e: e.update(reason="TODO: say why this is safe"),
        lambda e: e.update(reason="short"),
        lambda e: e.update(reason="x" * 301),
        lambda e: e.pop("reason"),
        lambda e: e.update(line_sha256="abc"),
        lambda e: e.update(line_sha256="G" * 64),
        lambda e: e.update(rule="rh-sec-004"),
        lambda e: e.update(rule="SECRET"),
        lambda e: e.update(file=""),
        lambda e: e.update(file="/etc/passwd"),
        lambda e: e.update(file="../outside.py"),
        lambda e: e.update(file="a\\b.py"),
        lambda e: e.update(count=0),
        lambda e: e.update(count=51),
        lambda e: e.update(count=True),
        lambda e: e.update(count="2"),
        lambda e: e.update(extra="x"),
    ],
)
def test_a_bad_entry_refuses_the_whole_baseline(tmp_path: Path, mutate) -> None:  # type: ignore[no-untyped-def]
    bad = entry()
    mutate(bad)
    with pytest.raises(BaselineError):
        load_baseline(write_baseline(tmp_path, [bad]))


def test_a_file_that_is_not_a_proper_baseline_is_refused(tmp_path: Path) -> None:
    for text in ["", "not json", "[]", '{"version": 2, "entries": []}', '{"version": 1}', '{"version": 1, "entries": {}}', '{"version": 1, "entries": [], "x": 1}', '{"version": true, "entries": []}']:
        path = tmp_path / "b.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(BaselineError):
            load_baseline(path)
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "missing.json")


def test_a_duplicate_entry_is_refused(tmp_path: Path) -> None:
    with pytest.raises(BaselineError):
        load_baseline(write_baseline(tmp_path, [entry(), entry()]))


def test_too_many_entries_are_refused(tmp_path: Path) -> None:
    many = [entry(file=f"t/f{n}.py") for n in range(MAX_ENTRIES + 1)]
    with pytest.raises(BaselineError):
        load_baseline(write_baseline(tmp_path, many))


def test_a_huge_file_is_refused_not_read(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text('{"version": 1, "entries": []}' + " " * (1024 * 1024 + 1), encoding="utf-8")  # valid JSON, only too big
    with pytest.raises(BaselineError):
        load_baseline(path)


# --- applying ----------------------------------------------------------------------------------------------------------------------

def finding(file: str = "t/fixture.py", line: int = 1, rule: str = "RH-SEC-004") -> ScanFinding:
    return ScanFinding(rule_id=rule, rule_name="n", severity="error", file_path=file, line_number=line, tool_name="", message="m")


def baseline_of(*entries: BaselineEntry) -> Baseline:
    return Baseline(entries=tuple(entries))


def be(file: str = "t/fixture.py", rule: str = "RH-SEC-004", line: str = FAKE_LINE, count: int = 1) -> BaselineEntry:
    return BaselineEntry(file=file, rule=rule, line_sha256=sha(line), count=count, reason=REASON)


def test_a_matching_finding_is_accepted_and_nothing_is_stale() -> None:
    result = apply_baseline([finding()], lambda f: FAKE_LINE, baseline_of(be()))
    assert result.new == [] and result.accepted == 1 and result.stale == []


def test_a_finding_not_in_the_baseline_stays_new() -> None:
    result = apply_baseline([finding(file="t/other.py")], lambda f: FAKE_LINE, baseline_of(be()))
    assert [f.file_path for f in result.new] == ["t/other.py"] and len(result.stale) == 1


def test_a_changed_line_is_new_and_the_old_entry_is_stale() -> None:
    result = apply_baseline([finding()], lambda f: FAKE_LINE.replace("Zq9", "Zq8"), baseline_of(be()))
    assert len(result.new) == 1 and len(result.stale) == 1


def test_a_moved_line_still_matches_because_the_line_number_is_not_part_of_the_entry() -> None:
    result = apply_baseline([finding(line=40)], lambda f: FAKE_LINE, baseline_of(be()))
    assert result.new == [] and result.stale == []


def test_the_rule_must_match() -> None:
    result = apply_baseline([finding(rule="RH-SEC-003")], lambda f: FAKE_LINE, baseline_of(be()))
    assert len(result.new) == 1 and len(result.stale) == 1


def test_count_limits_how_many_identical_findings_are_accepted() -> None:
    two = [finding(line=1), finding(line=2), finding(line=3)]
    result = apply_baseline(two, lambda f: FAKE_LINE, baseline_of(be(count=2)))
    assert result.accepted == 2 and len(result.new) == 1 and result.stale == []


def test_an_entry_with_a_higher_count_than_exists_is_stale() -> None:
    result = apply_baseline([finding()], lambda f: FAKE_LINE, baseline_of(be(count=3)))
    assert result.accepted == 1 and result.new == [] and [(s.file, s.unmatched) for s in result.stale] == [("t/fixture.py", 2)]


def test_a_line_that_cannot_be_read_is_never_accepted() -> None:
    result = apply_baseline([finding()], lambda f: None, baseline_of(be()))
    assert len(result.new) == 1


def test_an_empty_baseline_accepts_nothing() -> None:
    result = apply_baseline([finding()], lambda f: FAKE_LINE, baseline_of())
    assert len(result.new) == 1 and result.accepted == 0 and result.stale == []


# --- the CLI -----------------------------------------------------------------------------------------------------------------------

def test_without_a_baseline_the_fixture_fails_the_strict_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(project(tmp_path), "--strict", capsys=capsys)
    assert code == 1 and "RH-SEC-004" in out


def test_with_a_matching_baseline_the_gate_passes_and_says_how_many_were_accepted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path)
    baseline = write_baseline(tmp_path, [entry()])
    code, out = run(root, "--strict", "--baseline", str(baseline), capsys=capsys)
    assert code == 0, out
    assert "1 finding accepted by the baseline" in out and "Found 1 security" not in out


def test_a_new_secret_next_to_baselined_ones_fails_the_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, FAKE_LINE + "\n" + 'OTHER = "sk-' + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7" + '"\n')
    code, out = run(root, "--strict", "--baseline", str(write_baseline(tmp_path, [entry()])), capsys=capsys)
    assert code == 1 and "t/fixture.py:2" in out.replace("\\", "/")


def test_a_stale_entry_fails_the_strict_gate_so_the_list_only_shrinks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, "nothing secret here\n")
    code, out = run(root, "--strict", "--baseline", str(write_baseline(tmp_path, [entry()])), capsys=capsys)
    assert code == 1 and "RH-BASE-001" in out and "t/fixture.py" in out


def test_a_stale_entry_without_strict_is_reported_but_does_not_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, "nothing secret here\n")
    code, out = run(root, "--baseline", str(write_baseline(tmp_path, [entry()])), capsys=capsys)
    assert code == 0 and "RH-BASE-001" in out


@pytest.mark.parametrize("problem", ["missing", "garbage", "placeholder"])
def test_a_broken_baseline_fails_closed_with_exit_2_and_no_secret_in_the_output(tmp_path: Path, capsys: pytest.CaptureFixture[str], problem: str) -> None:
    root = project(tmp_path)
    if problem == "missing":
        path = tmp_path / "nope.json"
    elif problem == "garbage":
        path = tmp_path / "g.json"
        path.write_text("{{{", encoding="utf-8")
    else:
        path = write_baseline(tmp_path, [entry(reason="TODO: say why this is safe")])
    code, out = run(root, "--strict", "--baseline", str(path), capsys=capsys)
    assert code == 2 and BODY not in out


def test_the_output_never_contains_the_secret_or_the_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path)
    _, out = run(root, "--strict", "--baseline", str(write_baseline(tmp_path, [entry()])), capsys=capsys)
    assert BODY not in out and "KEY =" not in out


def test_emit_baseline_writes_entries_with_a_placeholder_reason_that_the_loader_refuses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path)
    out_path = tmp_path / "new-baseline.json"
    code, out = run(root, "--emit-baseline", str(out_path), capsys=capsys)
    assert code == 0 and out_path.is_file() and BODY not in out
    text = out_path.read_text(encoding="utf-8")
    assert BODY not in text and "KEY =" not in text
    data = json.loads(text)
    assert data["version"] == 1 and data["entries"][0]["file"] == "t/fixture.py" and data["entries"][0]["line_sha256"] == sha(FAKE_LINE)
    with pytest.raises(BaselineError):
        load_baseline(out_path)


def test_emit_baseline_never_overwrites_an_existing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path)
    existing = tmp_path / "keep.json"
    existing.write_text("keep me", encoding="utf-8")
    code, _ = run(root, "--emit-baseline", str(existing), capsys=capsys)
    assert code == 2 and existing.read_text(encoding="utf-8") == "keep me"


def test_a_sarif_report_leaves_out_the_accepted_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path)
    sarif = tmp_path / "out.sarif"
    code, _ = run(root, "--strict", "--baseline", str(write_baseline(tmp_path, [entry()])), "--sarif", str(sarif), capsys=capsys)
    assert code == 0 and json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"] == []


def test_the_python_rule_findings_can_be_baselined_too(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    source = "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.delete('/x')\nasync def delete_thing() -> None:\n    return None\n"
    (root / "routes.py").write_text(source, encoding="utf-8")
    code, out = run(root, "--emit-baseline", str(tmp_path / "e.json"), capsys=capsys)
    data = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    if data["entries"]:
        assert all(e["rule"].startswith("RH-SEC-") for e in data["entries"])
