"""Fetcher contract: the result model, panel states, exceptions, registry and runner."""

from collections.abc import Callable
from dataclasses import dataclass

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


_REGISTRY: dict[str, Registered] = {}


def fetcher(id: str, accepts: list[EntityType]):
    def register(func: Callable) -> Callable:
        if id in _REGISTRY:
            raise ValueError(f"duplicate fetcher id {id}")
        _REGISTRY[id] = Registered(id=id, accepts=tuple(accepts), func=func)
        return func

    return register


def registered_fetcher(source_id: str) -> Registered | None:
    return _REGISTRY.get(source_id)


def has_fetcher(source_id: str) -> bool:
    return source_id in _REGISTRY


def fetchers_for(entity_type: EntityType) -> tuple[str, ...]:
    return tuple(r.id for r in _REGISTRY.values() if entity_type in r.accepts)
