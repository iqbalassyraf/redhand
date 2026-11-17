#!/usr/bin/env python3
"""
Issue one single-use sign-up code (Phase 4.5 D1, ADR 0026). Run by the platform owner; a code lets one signed-in person with no organization create one.

  export RH_CORE_URL=https://<core>          # the core service
  export RH_SERVICE_TOKEN=...                # core's INTERNAL_SERVICE_TOKEN (read from the environment, never from an argument or a file here)
  python3 scripts/issue_signup_code.py --note "Acme pilot" --days 14

The code is printed once and RedHand keeps only its hash. Send it to the person over a private channel. Never paste it into a ticket or chat room.
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--note", default=None, help="who it is for (stored, up to 200 characters)")
    parser.add_argument("--days", type=int, default=14, help="how long the code stays valid (1 to 90)")
    args = parser.parse_args()
    core = os.environ.get("RH_CORE_URL", "").rstrip("/")
    token = os.environ.get("RH_SERVICE_TOKEN", "")
    if not core or not token:
        print("Set RH_CORE_URL and RH_SERVICE_TOKEN in the environment first.", file=sys.stderr)
        return 2
    response = httpx.post(f"{core}/internal/v1/signup-codes", json={"note": args.note, "expires_in_days": args.days},
                          headers={"Authorization": f"Bearer {token}"}, timeout=15.0)
    if response.status_code != 201:
        print(f"Core refused: HTTP {response.status_code}", file=sys.stderr)
        return 1
    body = response.json()
    print(f"Sign-up code (shown once): {body['code']}\nValid until: {body['expires_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
