"""Fetcher contract: the result model, panel states, exceptions, registry and runner."""

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from casefile.types import EntityType, sanitize  # noqa: F401 -- re-exported: callers import it from here


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
    # casefile's own remark, not a source's: not starrable, not a pivot, never exported as a third-party claim.
    note: bool = False

    def __post_init__(self):
        # At the source, so the terminal, a panel, a case page and an export all show the same escaped text.
        object.__setattr__(self, "label", sanitize(self.label))
        object.__setattr__(self, "value", sanitize(self.value))


@dataclass(frozen=True)
class SourceResult:
    source_id: str
    state: str
    findings: tuple[Finding, ...] = ()
    detail: str | None = None  # error reason, or a note on the state
    elapsed_ms: int = 0
    fetched_at: float = 0.0  # set when rehydrated from the cache, so a panel can say how old it is


@dataclass(frozen=True)
class Registered:
    id: str
    accepts: tuple[EntityType, ...]
    func: Callable
    on_demand: bool = False
    cost_note: str | None = None
    # Opt-in: only a long sweep wants the resume crumbs, and everything else keeps the three-argument signature.
    checkpointed: bool = False
    # `note`: polarity is not self-evident, a known-good corpus hit and a malware hit look identical on screen.
    name: str = ""
    note: str | None = None
    # The target itself sees the request. Not on_demand: that is egress size, this is who learns you looked.
    contacts_target: bool = False


_REGISTRY: dict[str, Registered] = {}


def fetcher(
    id: str,
    accepts: list[EntityType],
    *,
    on_demand: bool = False,
    cost_note: str | None = None,
    name: str = "",
    note: str | None = None,
    checkpointed: bool = False,
    contacts_target: bool = False,
):
    """Register a fetcher. on_demand marks large egress; contacts_target, a request the target itself sees."""

    def register(func: Callable) -> Callable:
        if id in _REGISTRY:
            raise ValueError(f"duplicate fetcher id {id}")
        _REGISTRY[id] = Registered(
            id=id,
            accepts=tuple(accepts),
            func=func,
            on_demand=on_demand,
            cost_note=cost_note,
            name=name or id,
            note=note,
            checkpointed=checkpointed,
            contacts_target=contacts_target,
        )
        return func

    return register


def source_name(source_id: str) -> str:
    rec = _REGISTRY.get(source_id)
    return rec.name if rec else source_id


def source_note(source_id: str) -> str | None:
    rec = _REGISTRY.get(source_id)
    return rec.note if rec else None


def registered_fetcher(source_id: str) -> Registered | None:
    return _REGISTRY.get(source_id)


def fetched_ids() -> frozenset[str]:
    return frozenset(_REGISTRY)


def fetchers_for(entity_type: EntityType) -> tuple[Registered, ...]:
    return tuple(r for r in _REGISTRY.values() if entity_type in r.accepts)


# Wide enough for the wmn sweep's own 30-60s, narrow enough that nothing leaves a panel on "loading…" for ever:
# httpx's read timeout restarts on every chunk, so a source trickling bytes is unbounded without a deadline here.
# ponytail: one flat ceiling, per-source budgets only if a source ever legitimately needs longer than the sweep.
DEADLINE = 300.0


async def run_fetcher(source_id, value, entity_type, client, checkpoint=None) -> "SourceResult":
    """Run one fetcher and map its outcome to a SourceResult. Never raises.

    `checkpoint` reaches only a fetcher registered as checkpointed; the rest never see it.
    """
    rec = registered_fetcher(source_id)
    if rec is None:
        return SourceResult(source_id=source_id, state=State.ERROR, detail=f"no fetcher registered for {source_id}")
    start = time.monotonic()
    try:
        crumbs = {"checkpoint": checkpoint} if rec.checkpointed else {}
        async with asyncio.timeout(DEADLINE):
            findings = tuple(await rec.func(value, entity_type, client, **crumbs))
        state = State.OK if findings else State.EMPTY
        return SourceResult(source_id, state, findings, elapsed_ms=_ms(start))
    except NeedsKey as exc:
        return SourceResult(source_id, State.NEEDS_KEY, detail=str(exc), elapsed_ms=_ms(start))
    except RateLimited as exc:
        return SourceResult(source_id, State.RATE_LIMITED, detail=str(exc), elapsed_ms=_ms(start))
    except (httpx.TimeoutException, TimeoutError):  # TimeoutError is what asyncio.timeout raises on expiry
        return SourceResult(source_id, State.TIMEOUT, detail="no response within the timeout", elapsed_ms=_ms(start))
    except Exception as exc:  # noqa: BLE001 -- a dead source must never break the page
        return SourceResult(source_id, State.ERROR, detail=_reason(exc), elapsed_ms=_ms(start))


def _reason(exc: Exception) -> str:
    """Panel-sized reason, not repr: httpx stringifies a bad status into a paragraph ending in an MDN link."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"{exc.request.url.host} returned {exc.response.status_code}"
    if isinstance(exc, httpx.TransportError):
        return f"could not reach {exc.request.url.host}" if exc.request else "could not reach the source"
    if isinstance(exc, json.JSONDecodeError):
        return "the source answered, but not with JSON"
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return text or type(exc).__name__


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
