"""TOML link catalogue: loading, validation, lookup and URL building."""

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from casefile.types import EntityType

PLACEHOLDER = "{value}"


class CatalogError(Exception):
    """A catalogue file is malformed. The message always names the file."""


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    name: str
    accepts: tuple[EntityType, ...]
    url: str
    notes: str | None = None


def _parse_source(raw: dict, origin: Path) -> Source:
    try:
        accepts = tuple(EntityType(a) for a in raw["accepts"])
        source = Source(
            id=raw["id"],
            name=raw["name"],
            accepts=accepts,
            url=raw["url"],
            notes=raw.get("notes"),
        )
    except (KeyError, ValueError) as exc:
        raise CatalogError(f"{origin.name}: invalid source entry {raw.get('id', '<no id>')}: {exc}") from exc
    if not source.url.startswith("https://"):
        raise CatalogError(f"{origin.name}: source {source.id} url must start with https://")
    if PLACEHOLDER not in source.url:
        raise CatalogError(f"{origin.name}: source {source.id} url has no {PLACEHOLDER}")
    if not source.accepts:
        raise CatalogError(f"{origin.name}: source {source.id} accepts nothing")
    return source


@lru_cache(maxsize=8)
def load_catalog(directory: Path | None = None) -> tuple[Source, ...]:
    """Cached: the web route calls this per request and the files never change at runtime."""
    directory = directory or Path(__file__).resolve().parent / "catalog"
    sources: list[Source] = []
    seen: dict[str, Path] = {}
    by_url: dict[tuple, str] = {}
    for path in sorted(directory.glob("*.toml")):
        with path.open("rb") as handle:
            try:
                document = tomllib.load(handle)
            except tomllib.TOMLDecodeError as exc:
                raise CatalogError(f"{path.name}: {exc}") from exc
        for raw in document.get("source", ()):
            source = _parse_source(raw, path)
            if source.id in seen:
                raise CatalogError(f"{path.name}: duplicate id {source.id}, already in {seen[source.id].name}")
            # Two ids pointing at one URL for the same type render as two rows going to one page,
            # which reads as a difference that is not there and costs a second visit.
            for entity_type in source.accepts:
                key = (entity_type, source.url)
                if key in by_url:
                    raise CatalogError(f"{path.name}: {source.id} duplicates {by_url[key]} for {entity_type}: same url")
                by_url[key] = source.id
            seen[source.id] = path
            sources.append(source)
    return tuple(sources)


def sources_for(catalog: tuple[Source, ...], entity_type: EntityType) -> tuple[Source, ...]:
    return tuple(s for s in catalog if entity_type in s.accepts)


def build_url(source: Source, value: str) -> str:
    return source.url.replace(PLACEHOLDER, quote(value, safe=""))


@dataclass(frozen=True)
class Link:
    """One catalogue source with its url already built for a specific value."""

    id: str
    name: str
    url: str
    notes: str | None = None


def links_for(candidate, exclude: frozenset[str] = frozenset()) -> tuple[Link, ...]:
    """Every catalogue link for a candidate, minus `exclude`.

    `exclude` carries the ids a caller renders some other way. The web page passes the ids that
    have a fetcher, because a source shown as a panel listed again as a link is the same source
    twice. It lives here rather than in the caller so every surface can apply the same rule.
    """
    catalog = load_catalog()
    return tuple(
        Link(s.id, s.name, build_url(s, candidate.value), s.notes)
        for s in sources_for(catalog, candidate.type)
        if s.id not in exclude
    )
