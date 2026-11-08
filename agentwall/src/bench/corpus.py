"""
The benchmark corpus: loading, validation and the placeholder expansion that keeps secret-shaped strings out of
the repository. Samples are JSONL, one file per category; the file name is the category.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Kind = Literal["tool_result", "tool_description", "manifest"]

# category -> the OWASP LLM Top 10 (2025) item it informs. The numbering follows the 2025 list as the project
# understands it; verify against the current OWASP publication before quoting it externally.
CATEGORY_OWASP: dict[str, str] = {
    "injection_indirect": "LLM01",
    "tool_poisoning": "LLM01",
    "secret_leak": "LLM02",
    "output_xss": "LLM05",
    "output_ssrf": "LLM05",
    "output_path": "LLM05",
    "manifest_risk": "LLM06",
}

DEFAULT_CORPUS_DIR = Path(__file__).resolve().parents[2] / "bench" / "corpus"

# Fake secrets, assembled from pieces so that no secret-shaped literal sits in the repository (secret scanners and
# push protection would flag it). None of these is a real credential.
_PEM_BODY_8 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj"
_PEM_BODY_RSA = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
MACROS: dict[str, str] = {
    "AWS_KEY": "AKIA" + "ZZ9QX8W7V6U5T4R3",
    "AWS_EXAMPLE_ID": "AKIA" + "IOSFODNN7EXAMPLE",
    "AWS_EXAMPLE_SECRET": "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "OPENAI_KEY": "sk-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    "ANTHROPIC_KEY": "sk-ant-" + "api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEf",
    "GCP_TOKEN": "ya" + "29.a0AfH6SMBx1234567890abcdefghijklmnop",
    "GITHUB_PAT": "gh" + "p_16C7e42F292c6912E7710c838347Ae178B4a",
    "GITHUB_OAUTH": "gh" + "o_16C7e42F292c6912E7710c838347Ae178B4a",
    "SLACK_TOKEN": "xo" + "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "STRIPE_KEY": "sk_" + "live_51Hh9abcdefghijklmnopqrstuvwxyz0123456789",
    "JWT": "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "GOOGLE_API_KEY": "AIza" + "SyA-abcdefghijklmnopqrstuvwxyz012345",
    "NPM_TOKEN": "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "BEARER_HEX": "3f9a1c7d4b8e2f60a5d1c9e7b3f4a8d2c6e0b1f5",
    "DB_URL": "postgres://admin:" + "S3cretPassw0rd!@db.internal:5432/prod",
    "PEM_PKCS8": "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY_8 + "\n-----END " + "PRIVATE KEY-----",
    "PEM_RSA": "-----BEGIN RSA " + "PRIVATE KEY-----\n" + _PEM_BODY_RSA + "\n-----END RSA " + "PRIVATE KEY-----",
}
_PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
MAX_TEXT_CHARS = 8000


class Sample(BaseModel):
    """One labelled example. `family` groups variants of one idea, so the report can say how many distinct ideas
    stand behind the sample count (variants of one idea are correlated, and the numbers should not pretend otherwise)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z_]+-\d{3}$")
    category: str
    kind: Kind
    label: Literal["malicious", "benign"]
    lang: Literal["en", "ms"]
    family: str = Field(min_length=1, max_length=40)
    hard: bool = False  # a benign sample built to look like an attack
    text: str | None = Field(default=None, max_length=MAX_TEXT_CHARS)
    manifest: dict[str, Any] | None = None
    note: str = Field(default="", max_length=200)
    # "dev" samples may be used to write and tune rules; "holdout" samples are only ever used to REPORT. A rule that is
    # tuned against its own test samples looks far better than it is. The split comes from the file name (<category>.holdout.jsonl).
    split: Literal["dev", "holdout"] = "dev"

    @model_validator(mode="after")
    def _shape(self) -> Sample:
        if self.category not in CATEGORY_OWASP:
            raise ValueError(f"unknown category {self.category!r}")
        if (self.kind == "manifest") != (self.manifest is not None) or (self.kind == "manifest") == (self.text is not None):
            raise ValueError("manifest samples carry a manifest and no text; all others carry text and no manifest")
        if self.hard and self.label != "benign":
            raise ValueError("only benign samples can be marked hard")
        if not self.id.startswith(self.category + "-"):
            raise ValueError("id must start with its category")
        return self


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def replace(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in MACROS:
                raise ValueError(f"unknown placeholder {{{{{name}}}}}")
            return MACROS[name]

        return _PLACEHOLDER.sub(replace, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_corpus(directory: Path = DEFAULT_CORPUS_DIR) -> list[Sample]:
    """Reads every `<category>.jsonl` in `directory`, validates it and expands placeholders. Raises ValueError on any
    problem: a corpus that does not validate must not produce numbers."""
    samples: list[Sample] = []
    seen: set[str] = set()
    files = sorted(directory.glob("*.jsonl"))
    if not files:
        raise ValueError(f"no corpus files in {directory}")
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                raw = {k: (_expand(v) if k in ("text", "manifest") else v) for k, v in raw.items()}
                sample = Sample.model_validate(raw)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path.name}:{number}: {exc}") from exc
            stem, _, kind = path.stem.partition(".")
            if sample.category != stem:
                raise ValueError(f"{path.name}:{number}: category {sample.category!r} does not match the file name")
            if kind != "holdout" and not re.fullmatch(r"|dev\d+", kind):
                raise ValueError(f"{path.name}: unknown corpus file kind {kind!r}")
            # "dev2" and "dev3" hold independently written samples that were measured once as blind rounds 1 and 2
            # (docs/security/blind-round-1.md, blind-round-2.md) and then used to improve the rules or train the model, so from then
            # on they are development data like any other.
            sample = sample.model_copy(update={"split": "holdout" if kind == "holdout" else "dev"})
            if sample.id in seen:
                raise ValueError(f"{path.name}:{number}: duplicate id {sample.id}")
            seen.add(sample.id)
            samples.append(sample)
    return samples


def corpus_digest(directory: Path = DEFAULT_CORPUS_DIR) -> str:
    """A fingerprint of the corpus files, so a baseline can tell that the corpus changed under it."""
    h = hashlib.sha256()
    for path in sorted(directory.glob("*.jsonl")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()[:16]
