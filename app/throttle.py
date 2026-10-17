"""Failed-login counters. Redis when ID_REDIS_URL is set (shared by all instances), else process memory."""

import time

import redis.asyncio as redis

from app.config import get_settings

_redis: redis.Redis | None = None
_memory: dict[str, tuple[int, float]] = {}


def _client() -> redis.Redis | None:
    global _redis
    url = get_settings().redis_url
    if url and _redis is None:
        _redis = redis.from_url(url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    return _redis if url else None


async def counts(keys: list[str]) -> list[int]:
    r = _client()
    if r is not None:
        try:
            return [int(v or 0) for v in await r.mget(keys)]
        except Exception:  # noqa: BLE001 - throttling must never block sign-in when Redis is down
            return [0] * len(keys)
    now = time.monotonic()
    return [c if exp > now else 0 for c, exp in (_memory.get(k, (0, 0.0)) for k in keys)]


async def increment(keys: list[str], ttl: int) -> None:
    r = _client()
    if r is not None:
        try:
            pipe = r.pipeline(transaction=False)
            for k in keys:
                pipe.incr(k)
                pipe.expire(k, ttl, nx=True)
            await pipe.execute()
        except Exception:  # noqa: BLE001
            pass
        return
    now = time.monotonic()
    for k in keys:
        c, exp = _memory.get(k, (0, 0.0))
        _memory[k] = (c + 1, exp) if exp > now else (1, now + ttl)


async def clear(keys: list[str]) -> None:
    r = _client()
    if r is not None:
        try:
            await r.delete(*keys)
        except Exception:  # noqa: BLE001
            pass
        return
    for k in keys:
        _memory.pop(k, None)


def reset() -> None:
    global _redis
    _redis = None
    _memory.clear()
