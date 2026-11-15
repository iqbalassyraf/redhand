"""
deploy/cloudrun/deploy.sh tells both services they run behind exactly one proxy (Cloud Run's front end), so per-address rate limits see the
caller and not Google (H3.3). The number must stay 1: a higher number would trust a part of X-Forwarded-For that the caller wrote. It is
deliberately a hop count, not uvicorn's `--forwarded-allow-ips '*'`, which takes the leftmost (forgeable) entry.
"""

from __future__ import annotations

import re
from pathlib import Path

DEPLOY = (Path(__file__).resolve().parents[2] / "deploy" / "cloudrun" / "deploy.sh").read_text(encoding="utf-8")
DOCKERFILES = [
    (Path(__file__).resolve().parents[2] / "deploy" / "cloudrun" / name).read_text(encoding="utf-8")
    for name in ("Dockerfile.core", "Dockerfile.gateway")
]


def test_core_and_gateway_are_told_they_sit_behind_one_proxy() -> None:
    assert re.search(r"@TRUSTED_PROXY_HOPS=1@", DEPLOY), "core must set TRUSTED_PROXY_HOPS=1"
    assert re.search(r"@AGENTWALL_TRUSTED_PROXY_HOPS=1@", DEPLOY), "the gateway must set AGENTWALL_TRUSTED_PROXY_HOPS=1"


def test_no_other_hop_count_is_ever_set() -> None:
    assert re.findall(r"TRUSTED_PROXY_HOPS=(\d+)", DEPLOY) == ["1", "1"]


def test_the_forgeable_uvicorn_wildcard_is_not_used() -> None:
    for text in (DEPLOY, *DOCKERFILES):
        assert "forwarded-allow-ips" not in text.lower() and "FORWARDED_ALLOW_IPS" not in text
