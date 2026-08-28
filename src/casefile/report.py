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


def build_report(raw: str) -> tuple[Section, ...]:
    catalog = load_catalog()
    return tuple(
        Section(
            type=candidate.type.value,
            value=candidate.value,
            links=tuple(
                Link(s.id, s.name, build_url(s, candidate.value), s.notes) for s in sources_for(catalog, candidate.type)
            ),
        )
        for candidate in detect(raw)
    )
