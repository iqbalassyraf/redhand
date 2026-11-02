"""
RedHand SDK - Sub-Millisecond Policy & Ephemeral Token Cache
File: packages/redhand-sdk/src/redhand_sdk/cache.py

Caches active downscoped cloud tokens and deterministic security evaluations
in volatile memory, reducing repeated STS roundtrips to <0.1ms.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import threading

from redhand_sdk.models import AWSEphemeralTokenMintResponse, EphemeralTokenMintResponse

logger = logging.getLogger("redhand.sdk.cache")


class TokenCacheEntry:
    __slots__ = ("token", "expires_at")

    def __init__(
        self,
        token: EphemeralTokenMintResponse | AWSEphemeralTokenMintResponse,
        expires_at: datetime,
    ) -> None:
        self.token = token
        self.expires_at = expires_at

    def is_valid(self, min_ttl_seconds: int = 30) -> bool:
        now = datetime.now(timezone.utc)
        delta = (self.expires_at - now).total_seconds()
        return delta > min_ttl_seconds


class PolicyAndTokenCache:
    """
    Thread-safe, sub-millisecond in-process cache for ephemeral tokens and
    verified policy evaluations.
    """

    def __init__(self, max_entries: int = 128) -> None:
        self._max_entries = max_entries
        self._tokens: dict[str, TokenCacheEntry] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _make_key(
        provider: str,
        target_resource: str,
        permissions: list[str],
        agent_id: str,
    ) -> str:
        sorted_perms = ",".join(sorted(permissions))
        return f"{provider}:{agent_id}:{target_resource}:{sorted_perms}"

    def get_token(
        self,
        *,
        provider: str,
        target_resource: str,
        permissions: list[str],
        agent_id: str,
        min_ttl_seconds: int = 30,
    ) -> EphemeralTokenMintResponse | AWSEphemeralTokenMintResponse | None:
        key = self._make_key(provider, target_resource, permissions, agent_id)
        with self._lock:
            entry = self._tokens.get(key)
            if entry and entry.is_valid(min_ttl_seconds):
                return entry.token
            if entry:
                self._tokens.pop(key, None)
        return None

    def put_token(
        self,
        *,
        provider: str,
        target_resource: str,
        permissions: list[str],
        agent_id: str,
        token: EphemeralTokenMintResponse | AWSEphemeralTokenMintResponse,
    ) -> None:
        key = self._make_key(provider, target_resource, permissions, agent_id)
        expires_at = (
            token.expires_at
            if isinstance(token, EphemeralTokenMintResponse)
            else token.expiration
        )
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        with self._lock:
            if len(self._tokens) >= self._max_entries:
                self.purge_expired()
            self._tokens[key] = TokenCacheEntry(token=token, expires_at=expires_at)

    def purge_expired(self) -> None:
        with self._lock:
            expired_keys = [
                k for k, v in self._tokens.items() if not v.is_valid(min_ttl_seconds=5)
            ]
            for k in expired_keys:
                self._tokens.pop(k, None)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


_global_cache: PolicyAndTokenCache | None = None


def get_default_cache() -> PolicyAndTokenCache:
    global _global_cache
    if _global_cache is None:
        _global_cache = PolicyAndTokenCache()
    return _global_cache

