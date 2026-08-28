"""The result shape. One builder, three renderers: text, JSON and HTML."""

from dataclasses import dataclass

from casefile.catalog import build_url, load_catalog, sources_for
from casefile.detect import detect


@dataclass(frozen=True)
class Link:
    id: str
    name: str
    url: str
    notes: str | None = None


@dataclass(frozen=True)
class Section:
    type: str
    value: str
    links: tuple[Link, ...]


def links_for(candidate) -> tuple[Link, ...]:
    catalog = load_catalog()
    return tuple(
        Link(s.id, s.name, build_url(s, candidate.value), s.notes) for s in sources_for(catalog, candidate.type)
    )


def build_report(raw: str) -> tuple[Section, ...]:
    return tuple(Section(c.type.value, c.value, links_for(c)) for c in detect(raw))
