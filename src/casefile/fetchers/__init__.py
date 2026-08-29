"""Fetcher contract: the result model, panel states, exceptions, registry and runner."""

import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from casefile.types import EntityType


class State:
    OK = "ok"
    EMPTY = "empty"
    NEEDS_KEY = "needs_key"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"


class NeedsKey(Exception):
    """A fetcher raises this when a required key is not configured."""


class RateLimited(Exception):
    """Raised when a source returns 429 after the single retry is exhausted."""


@dataclass(frozen=True)
class Finding:
    label: str
    value: str
    url: str | None = None


@dataclass(frozen=True)
class SourceResult:
    source_id: str
    state: str
    findings: tuple[Finding, ...] = ()
    detail: str | None = None  # error reason, or a note on the state
    elapsed_ms: int = 0


@dataclass(frozen=True)
class Registered:
    id: str
    accepts: tuple[EntityType, ...]
    func: Callable
    on_demand: bool = False
    cost_note: str | None = None


_REGISTRY: dict[str, Registered] = {}


def fetcher(id: str, accepts: list[EntityType], *, on_demand: bool = False, cost_note: str | None = None):
    """Register a fetcher. on_demand marks one whose egress is large enough to need consent."""

    def register(func: Callable) -> Callable:
        if id in _REGISTRY:
            raise ValueError(f"duplicate fetcher id {id}")
        _REGISTRY[id] = Registered(id=id, accepts=tuple(accepts), func=func, on_demand=on_demand, cost_note=cost_note)
        return func

    return register


def registered_fetcher(source_id: str) -> Registered | None:
    return _REGISTRY.get(source_id)


def fetched_ids() -> frozenset[str]:
    """Every source id that has a fetcher, for callers deciding what to render as a link."""
    return frozenset(_REGISTRY)


def fetchers_for(entity_type: EntityType) -> tuple[str, ...]:
    return tuple(r.id for r in _REGISTRY.values() if entity_type in r.accepts)


async def run_fetcher(source_id, value, entity_type, client) -> "SourceResult":
    """Run one fetcher and map its outcome to a SourceResult. Never raises."""
    rec = registered_fetcher(source_id)
    if rec is None:
        return SourceResult(source_id=source_id, state=State.ERROR, detail=f"no fetcher registered for {source_id}")
    start = time.monotonic()
    try:
        findings = tuple(await rec.func(value, entity_type, client))
        state = State.OK if findings else State.EMPTY
        return SourceResult(source_id, state, findings, elapsed_ms=_ms(start))
    except NeedsKey as exc:
        return SourceResult(source_id, State.NEEDS_KEY, detail=str(exc), elapsed_ms=_ms(start))
    except RateLimited as exc:
        return SourceResult(source_id, State.RATE_LIMITED, detail=str(exc), elapsed_ms=_ms(start))
    except httpx.TimeoutException:
        return SourceResult(source_id, State.TIMEOUT, detail="no response within the timeout", elapsed_ms=_ms(start))
    except Exception as exc:  # noqa: BLE001 -- a dead source must never break the page
        return SourceResult(source_id, State.ERROR, detail=str(exc), elapsed_ms=_ms(start))


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
