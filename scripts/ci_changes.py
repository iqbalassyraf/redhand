#!/usr/bin/env python3
"""
Which CI jobs a change needs, from the list of changed files on stdin (one path per line). Prints GitHub step outputs:
`python=true|false`, `sql=true|false`, `dashboard=true|false`.

Fail closed: an unrecognised path, or no paths at all (the diff could not be computed), runs every job. Only paths known to be read by
no test are skipped. Standard library only: it runs before any dependency is installed.

Usage in CI: `git diff --name-only BASE HEAD | python3 scripts/ci_changes.py >> "$GITHUB_OUTPUT"`, or `--all` to run everything.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from fnmatch import fnmatchcase

JOBS = ("python", "sql", "dashboard")
ALL = frozenset(JOBS)

# First match wins. Python tests read SQL files (twin parity, the block gate), dashboard sources (the night brief's on-screen strings),
# the dashboard's package files (supply-chain test), deploy scripts and some docs, so those paths also run the python job.
RULES: tuple[tuple[str, frozenset[str]], ...] = (
    (".github/workflows/*", ALL),
    ("scripts/ci_changes.py", ALL),
    ("scripts/test_migrations.sh", frozenset({"python", "sql"})),
    ("supabase/*", frozenset({"python", "sql"})),
    ("apps/redhand-ui/*", frozenset({"python", "dashboard"})),
    ("agentwall/*", frozenset({"python"})),
    ("services/*", frozenset({"python"})),
    ("packages/*", frozenset({"python"})),
    ("battleground/*", frozenset({"python"})),
    ("examples/*", frozenset({"python"})),
    ("scripts/*", frozenset({"python"})),
    ("tests/*", frozenset({"python"})),
    ("deploy/*", frozenset({"python"})),
    ("pyproject.toml", frozenset({"python"})),
    ("uv.lock", frozenset({"python"})),
    (".redhand-scan-baseline.json", frozenset({"python"})),
    ("docs/testing/briefs/*", frozenset({"python"})),
    ("docs/security/*", frozenset({"python"})),
    ("docs/runbooks/*", frozenset({"python"})),
    ("docs/api/*", frozenset({"python"})),
    # Read by no test: the secret scan (which always runs) is the only check they need.
    ("docs/*", frozenset()),
    (".ai-sync/*", frozenset()),
    (".github/dependabot.yml", frozenset()),
    ("CHANGELOG.md", frozenset()),
    ("README.md", frozenset()),
    ("CLAUDE.md", frozenset()),
)


def areas_for(paths: Iterable[str]) -> frozenset[str]:
    """The jobs the changed paths need. No paths at all means the diff failed, so everything runs."""
    needed: set[str] = set()
    seen = False
    for raw in paths:
        path = raw.strip()
        if not path:
            continue
        seen = True
        for pattern, jobs in RULES:
            if fnmatchcase(path, pattern):
                needed |= jobs
                break
        else:
            return ALL
    return frozenset(needed) if seen else ALL


def main(argv: list[str]) -> int:
    needed = ALL if "--all" in argv[1:] else areas_for(sys.stdin.read().splitlines())
    for job in JOBS:
        print(f"{job}={'true' if job in needed else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
