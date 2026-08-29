import pytest

from casefile.catalog import CatalogError, Source, build_url, load_catalog, sources_for
from casefile.types import EntityType


def test_loads_the_real_catalog():
    catalog = load_catalog()
    assert catalog
    assert all(isinstance(s, Source) for s in catalog)


def test_source_ids_are_unique_across_files():
    ids = [s.id for s in load_catalog()]
    assert len(ids) == len(set(ids)), f"duplicate ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_every_url_carries_the_value_placeholder():
    for source in load_catalog():
        assert "{value}" in source.url, f"{source.id} has no {{value}} in its url"


def test_every_url_is_https():
    """Blocks a contributed entry shipping javascript: or data: as a clickable link."""
    for source in load_catalog():
        assert source.url.startswith("https://"), f"{source.id} url is not https"


def test_non_https_scheme_is_rejected(tmp_path):
    (tmp_path / "evil.toml").write_bytes(
        b'[[source]]\nid = "x"\nname = "X"\naccepts = ["domain"]\nurl = "javascript:alert({value})"\n'
    )
    with pytest.raises(CatalogError, match="https"):
        load_catalog(tmp_path)


def test_every_accepts_entry_is_a_known_type():
    known = set(EntityType)
    for source in load_catalog():
        assert set(source.accepts) <= known, f"{source.id} accepts an unknown type"
        assert source.accepts, f"{source.id} accepts nothing"


def test_sources_for_filters_by_type():
    catalog = load_catalog()
    for source in sources_for(catalog, EntityType.DOMAIN):
        assert EntityType.DOMAIN in source.accepts


def test_build_url_percent_encodes_the_value():
    source = Source(id="x", name="X", accepts=(EntityType.COMPANY,), url="https://e.test/?q={value}")
    assert build_url(source, "Acme & Co/Ltd") == "https://e.test/?q=Acme%20%26%20Co%2FLtd"


def test_a_real_catalogue_entry_builds_its_real_url():
    """The shipped catalogue, not a synthetic Source: a bad template here reaches users."""
    from casefile.detect import detect
    from casefile.report import links_for

    (candidate,) = [c for c in detect("example.com") if c.type is EntityType.DOMAIN]
    crtsh = next(link for link in links_for(candidate) if link.id == "crtsh")
    assert crtsh.url == "https://crt.sh/?q=example.com"


def test_malformed_entry_raises_with_the_file_named(tmp_path):
    (tmp_path / "bad.toml").write_bytes(b'[[source]]\nid = "x"\n')
    with pytest.raises(CatalogError, match="bad.toml"):
        load_catalog(tmp_path)
