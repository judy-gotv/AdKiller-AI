"""Free global spammer blacklist pre-check via Combot Anti-Spam (CAS)."""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger("adkiller.cas")

CAS_API_URL = "https://api.cas.chat/check"


class CASChecker:
    """Async CAS checker with 24h cache for valid responses and short retry cooldown on errors."""

    def __init__(
        self,
        ttl_seconds: int = 86400,
        error_ttl_seconds: int = 120,
        timeout: float = 2.5,
        max_cache: int = 10000,
        api_key: str = "",
        auth_cooldown_seconds: int = 21600,
    ):
        self.ttl = ttl_seconds
        self.error_ttl = error_ttl_seconds
        self.timeout = timeout
        self.max_cache = max_cache
        self.api_key = (api_key or "").strip()
        self.auth_cooldown = auth_cooldown_seconds
        self._disabled_until: float = 0.0
        self._cache: dict[int, tuple[float, bool]] = {}
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"User-Agent": "AdKillerAI/0.2"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=headers,
            )
        return self._client

    async def is_banned(self, user_id: int, *, now: Optional[float] = None) -> bool:
        ts = now if now is not None else time.time()
        if self._disabled_until > ts:
            return False
        cached = self._cache.get(user_id)
        if cached and cached[0] > ts:
            return cached[1]

        try:
            resp = await self._get_client().get(CAS_API_URL, params={"user_id": user_id})
            if resp.status_code in (401, 403):
                self._disabled_until = ts + self.auth_cooldown
                logger.warning(
                    "CAS 接口返回 %s（当前需要 API Key 或权限受限），已自动暂停 CAS 查询 %d 小时避免刷屏与延迟。",
                    resp.status_code,
                    max(1, self.auth_cooldown // 3600),
                )
                return False
            if resp.status_code != 200:
                logger.warning(
                    "CAS 返回非 200 状态码 (%s)，采用短期重试缓存 uid=%s",
                    resp.status_code,
                    user_id,
                )
                self._set_cache(user_id, False, ts + self.error_ttl)
                return False

            data = resp.json()
            if not isinstance(data, dict) or "ok" not in data:
                logger.warning("CAS 返回异常响应结构，采用短期重试缓存 uid=%s", user_id)
                self._set_cache(user_id, False, ts + self.error_ttl)
                return False

            result = bool(data.get("ok") is True)
        except Exception as exc:
            logger.debug("CAS 查询跳过（短期冷却后重试）uid=%s: %s", user_id, exc)
            self._set_cache(user_id, False, ts + self.error_ttl)
            return False

        self._set_cache(user_id, result, ts + self.ttl)
        return result

    def _set_cache(self, user_id: int, val: bool, expires_at: float) -> None:
        if len(self._cache) >= self.max_cache:
            self._cache.pop(next(iter(self._cache)))
        self._cache[user_id] = (expires_at, val)

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
