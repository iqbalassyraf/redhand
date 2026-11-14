"""
`redhand scan` finds secrets in prompt and config files (docs/plans/phase4-m5b-secrets-in-files.md): file, line and type only,
never the value, with every read bounded. Fake secrets are built from pieces so this file holds no literal secret.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import time

import pytest

from redhand_sdk.cli import main as cli_main
from redhand_sdk.scanner import secrets as secrets_module
from redhand_sdk.scanner.secrets import SECRET_PATTERNS, SecretFinding, scan_secrets, scan_text

# A body that appears nowhere else, so any leak of part of it into an output is visible.
BODY = "Zq9xT4mW2vLk8RpN3cYbH7"
FAKES = {
    "OPENAI_KEY": "sk-" + BODY,
    "ANTHROPIC_KEY": "sk-ant-" + BODY,
    "AWS_KEY": "AKIA" + "QX7RTV3KLMNPWZ4B",
    "GCP_BEARER": "ya29." + BODY,
    "PRIVATE_KEY": "-----BEGIN " + "RSA PRIVATE KEY-----",
}
AWS_DOC_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
FILE_NAMES = [".env", ".env.local", "settings.yaml", "settings.yml", "config.json", "pyproject.toml", "prompt.md", "prompt.txt", "agent.py"]


def put(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# What is found
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", FILE_NAMES)
@pytest.mark.parametrize("kind", sorted(FAKES))
def test_each_kind_is_found_in_each_file_type_at_the_right_line(tmp_path: Path, kind: str, name: str) -> None:
    put(tmp_path, name, f"first line\nsecond line\nkey = {FAKES[kind]}\nlast line\n")
    result = scan_secrets(tmp_path)
    assert [(Path(f.file_path).name, f.line_number, f.secret_type) for f in result.findings] == [(name, 3, kind)]
    assert result.files_read == 1


def test_an_anthropic_key_is_one_finding_not_two(tmp_path: Path) -> None:
    put(tmp_path, ".env", f"ANTHROPIC_API_KEY={FAKES['ANTHROPIC_KEY']}\n")
    assert [f.secret_type for f in scan_secrets(tmp_path).findings] == ["ANTHROPIC_KEY"]


def test_two_secrets_on_two_lines_and_the_same_secret_twice_on_one_line(tmp_path: Path) -> None:
    put(tmp_path, "prompt.txt", f"a {FAKES['OPENAI_KEY']} b {FAKES['OPENAI_KEY']}\n{FAKES['AWS_KEY']}\n")
    found = sorted((f.line_number, f.secret_type) for f in scan_secrets(tmp_path).findings)
    assert found == [(1, "OPENAI_KEY"), (2, "AWS_KEY")]  # one finding per line and kind


def test_a_file_given_by_name_is_scanned_whatever_its_extension(tmp_path: Path) -> None:
    path = put(tmp_path, "notes.cfg", f"token {FAKES['GCP_BEARER']}\n")
    assert [f.secret_type for f in scan_secrets(path).findings] == ["GCP_BEARER"]


def test_invalid_utf8_is_read_with_replacement_and_still_found(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_bytes(b"\xff\xfe junk \n" + FAKES["OPENAI_KEY"].encode() + b"\n")
    assert [(f.line_number, f.secret_type) for f in scan_secrets(tmp_path).findings] == [(2, "OPENAI_KEY")]


# ---------------------------------------------------------------------------
# What is not found
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "id = 3f2b8a64-9c1d-4e7a-b5f0-1a2b3c4d5e6f",            # a UUID
    "commit 9fceb02d0ae598e95dc970b74767f19372d61af8",      # a git hash
    "image = data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
    "ask for the sk- prefix to be removed",                  # a prefix with no key after it
    "word DATA3TX and A3TX alone",                           # the short A3T form without the rest of a key
    "-----BEGIN CERTIFICATE-----",                           # a certificate is public
])
def test_ordinary_text_is_not_a_secret(tmp_path: Path, text: str) -> None:
    put(tmp_path, "prompt.md", text + "\n")
    assert scan_secrets(tmp_path).findings == []


def test_the_aws_documentation_example_is_skipped_and_nothing_else_is(tmp_path: Path) -> None:
    put(tmp_path, "docs.md", f"example: {AWS_DOC_EXAMPLE}\nreal: {FAKES['AWS_KEY']}\n")
    assert [(f.line_number, f.secret_type) for f in scan_secrets(tmp_path).findings] == [(2, "AWS_KEY")]


def test_a_file_type_that_is_not_listed_is_not_read(tmp_path: Path) -> None:
    put(tmp_path, "data.csv", FAKES["OPENAI_KEY"] + "\n")
    result = scan_secrets(tmp_path)
    assert result.findings == [] and result.files_read == 0


@pytest.mark.parametrize("folder", [".git", "node_modules", ".venv", "__pycache__"])
def test_skipped_folders_are_not_read(tmp_path: Path, folder: str) -> None:
    put(tmp_path, f"{folder}/inner/prompt.txt", FAKES["OPENAI_KEY"] + "\n")
    result = scan_secrets(tmp_path)
    assert result.findings == [] and result.files_read == 0


# ---------------------------------------------------------------------------
# The value is never held, printed or exported
# ---------------------------------------------------------------------------


def test_a_finding_has_no_place_to_hold_a_value() -> None:
    assert {f.name for f in dataclasses.fields(SecretFinding)} == {"file_path", "line_number", "secret_type"}


@pytest.mark.parametrize("kind", sorted(FAKES))
def test_no_part_of_the_value_reaches_any_output(tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str) -> None:
    put(tmp_path, ".env", f"# comment\nSECRET={FAKES[kind]}\nOTHER=1\n")
    sarif = tmp_path / "out.sarif"
    code = cli_main(["scan", str(tmp_path), "--sarif", str(sarif), "--strict"])
    out = capsys.readouterr()
    everything = out.out + out.err + sarif.read_text(encoding="utf-8")
    assert code == 1  # a secret is an error, so a strict run fails
    assert "RH-SEC-004" in everything and ".env:2" in everything  # the finding itself is reported, with file and line
    for piece in (BODY, BODY[:6], BODY[-6:], "QX7RTV3K", "BEGIN RSA"):
        assert piece not in everything, f"part of the value leaked: {piece!r}"


def test_the_message_comes_from_a_fixed_table_not_from_the_file(tmp_path: Path) -> None:
    put(tmp_path, ".env", f"A={FAKES['OPENAI_KEY']}\n")
    [finding] = scan_secrets(tmp_path).findings
    message = finding.to_scan_finding().message
    assert message == secrets_module.SECRET_MESSAGES["OPENAI_KEY"]
    assert BODY not in message and finding.to_scan_finding().rule_id == "RH-SEC-004" and finding.to_scan_finding().severity == "error"


def test_an_unreadable_file_is_reported_by_path_and_reason_only(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read any file")
    path = put(tmp_path, ".env", f"A={FAKES['OPENAI_KEY']}\n")
    path.chmod(0)
    try:
        result = scan_secrets(tmp_path)
    finally:
        path.chmod(0o600)
    assert result.findings == [] and result.skipped == {"unreadable": 1}
    assert result.skipped_examples == [(str(path), "unreadable")]


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_a_file_over_one_mebibyte_is_skipped_and_counted_never_partly_read(tmp_path: Path) -> None:
    assert secrets_module.MAX_FILE_BYTES == 1024 * 1024
    big = put(tmp_path, "prompt.txt", "")
    big.write_text(FAKES["OPENAI_KEY"] + "\n" + "x" * (secrets_module.MAX_FILE_BYTES), encoding="utf-8")  # secret at the START of an oversize file
    result = scan_secrets(tmp_path)
    assert result.findings == [] and result.skipped == {"too large": 1} and result.files_read == 0


def test_a_file_of_exactly_one_mebibyte_is_read(tmp_path: Path) -> None:
    text = FAKES["OPENAI_KEY"] + "\n"
    (tmp_path / "prompt.txt").write_text(text + "y" * (secrets_module.MAX_FILE_BYTES - len(text)), encoding="utf-8")
    assert [f.line_number for f in scan_secrets(tmp_path).findings] == [1]


def test_a_binary_file_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_bytes(b"\x00\x01\x02" + FAKES["OPENAI_KEY"].encode())
    result = scan_secrets(tmp_path)
    assert result.findings == [] and result.skipped == {"binary": 1}


def test_a_symlinked_file_is_not_followed(tmp_path: Path) -> None:
    outside = put(tmp_path / "outside", "secret.txt", FAKES["OPENAI_KEY"] + "\n")
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "link.txt").symlink_to(outside)
    result = scan_secrets(scanned)
    assert result.findings == [] and result.skipped == {"symlink": 1}


def test_a_symlinked_folder_is_not_entered(tmp_path: Path) -> None:
    put(tmp_path / "outside", "secret.txt", FAKES["OPENAI_KEY"] + "\n")
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "linked_dir").symlink_to(tmp_path / "outside", target_is_directory=True)
    assert scan_secrets(scanned).findings == []


def test_the_number_of_files_is_limited_and_the_run_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets_module, "MAX_FILES", 5)
    for i in range(8):
        put(tmp_path, f"f{i}.txt", "nothing here\n")
    result = scan_secrets(tmp_path)
    assert result.files_read == 5 and result.stopped_at_file_limit is True


def test_the_number_of_findings_per_file_is_limited_and_the_run_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets_module, "MAX_FINDINGS_PER_FILE", 3)
    put(tmp_path, ".env", "".join(f"K{i}={FAKES['OPENAI_KEY']}\n" for i in range(7)))
    result = scan_secrets(tmp_path)
    assert len(result.findings) == 3 and result.files_with_capped_findings == 1


@pytest.mark.parametrize("line", [
    "a" * (1024 * 1024),
    "sk-" * 340_000,
    "-----BEGIN " + "A " * 500_000,
    "ya29." + "." * 1_000_000,
    "-" * 1_000_000,
])
def test_a_one_mebibyte_line_is_scanned_quickly(line: str) -> None:
    started = time.monotonic()
    scan_text(line, "x.txt")
    assert time.monotonic() - started < 3.0


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def test_a_clean_folder_exits_zero_even_when_strict_and_says_what_was_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    put(tmp_path, "prompt.md", "You are a helpful agent.\n")
    assert cli_main(["scan", str(tmp_path), "--strict"]) == 0
    text = capsys.readouterr().out
    assert "1 file" in text and "not a guarantee" in text.lower()
    assert "all agent tools guarded" not in text.lower()  # the old line implied more than is checked


def test_a_secret_fails_a_strict_run_and_not_a_plain_run(tmp_path: Path) -> None:
    put(tmp_path, ".env", f"K={FAKES['OPENAI_KEY']}\n")
    assert cli_main(["scan", str(tmp_path)]) == 0
    assert cli_main(["scan", str(tmp_path), "--strict"]) == 1


def test_the_sarif_report_names_the_rule_file_and_line_only(tmp_path: Path) -> None:
    put(tmp_path, "cfg/prompt.yaml", f"a: 1\nb: {FAKES['AWS_KEY']}\n")
    sarif = tmp_path / "out.sarif"
    cli_main(["scan", str(tmp_path), "--sarif", str(sarif)])
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    [result] = doc["runs"][0]["results"]
    assert result["ruleId"] == "RH-SEC-004"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("prompt.yaml")
    assert "QX7RTV3K" not in sarif.read_text(encoding="utf-8")


def test_the_summary_says_what_was_skipped_and_why(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    put(tmp_path, "prompt.txt", "ok\n")
    (tmp_path / "blob.txt").write_bytes(b"\x00binary")
    cli_main(["scan", str(tmp_path)])
    text = capsys.readouterr().out
    assert "1 file skipped" in text and "binary" in text


def test_the_python_scan_is_unchanged_when_there_is_no_secret(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    put(tmp_path, "tools.py", "@tool\ndef delete_everything():\n    pass\n")
    assert cli_main(["scan", str(tmp_path), "--strict"]) == 1
    text = capsys.readouterr().out
    assert "RH-SEC-001" in text and "RH-SEC-003" in text and "RH-SEC-004" not in text


def test_the_pattern_table_has_the_five_secret_kinds() -> None:
    assert sorted(name for name, _ in SECRET_PATTERNS) == sorted(FAKES)


@pytest.mark.parametrize("text", [
    "see risk-assessment-and-mitigation-plan for details",
    "task-management-service-account-name",
    "disk-encryption-configuration-guide-v2",
])
def test_a_hyphenated_word_that_ends_in_sk_is_not_an_api_key(tmp_path: Path, text: str) -> None:
    put(tmp_path, "docs.md", text + "\n")
    assert scan_secrets(tmp_path).findings == []


def test_an_aws_key_id_inside_a_longer_uppercase_string_is_not_reported(tmp_path: Path) -> None:
    put(tmp_path, "data.txt", "BLOB=" + "Z" + FAKES["AWS_KEY"] + "Q\n")
    assert scan_secrets(tmp_path).findings == []
