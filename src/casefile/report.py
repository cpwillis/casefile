"""Catalogue links for one detected candidate."""

from dataclasses import dataclass

from casefile.catalog import build_url, load_catalog, sources_for


@dataclass(frozen=True)
class Link:
    id: str
    name: str
    url: str
    notes: str | None = None


def links_for(candidate) -> tuple[Link, ...]:
    catalog = load_catalog()
    return tuple(
        Link(s.id, s.name, build_url(s, candidate.value), s.notes) for s in sources_for(catalog, candidate.type)
    )
