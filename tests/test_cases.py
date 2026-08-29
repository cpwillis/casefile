import pytest

from casefile.cases import (
    Star,
    case_id_for,
    cases_path,
    forget_all,
    is_starred,
    list_cases,
    load_case,
    star,
    unstar,
)
from casefile.types import EntityType


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Never touch the real ~/.local/share/casefile."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    yield


def _star(label="A", value="192.0.2.10", url=None):
    return Star(source_id="dns", label=label, value=value, url=url)


def test_cases_path_follows_xdg_data_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert cases_path() == tmp_path / "casefile" / "cases.db"


def test_case_id_is_derived_and_stable():
    assert case_id_for(EntityType.DOMAIN, "example.com") == "domain:example.com"
    assert case_id_for(EntityType.DOMAIN, "example.com") == case_id_for(EntityType.DOMAIN, "example.com")


def test_starring_creates_the_case_implicitly():
    assert list_cases() == ()
    star(EntityType.DOMAIN, "example.com", _star())
    (case,) = list_cases()
    assert case.entity_type == "domain"
    assert case.value == "example.com"
    assert case.star_count == 1


def test_starring_the_same_finding_twice_is_idempotent():
    star(EntityType.DOMAIN, "example.com", _star())
    star(EntityType.DOMAIN, "example.com", _star())
    (case,) = list_cases()
    assert case.star_count == 1


def test_load_case_returns_its_stars():
    star(EntityType.DOMAIN, "example.com", _star(label="A", value="192.0.2.10"))
    star(EntityType.DOMAIN, "example.com", _star(label="MX", value="0 ."))
    case = load_case(case_id_for(EntityType.DOMAIN, "example.com"))
    assert case is not None
    assert {(s.label, s.value) for s in case.stars} == {("A", "192.0.2.10"), ("MX", "0 .")}


def test_is_starred_reflects_state():
    finding = _star()
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is False
    star(EntityType.DOMAIN, "example.com", finding)
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is True
    unstar(EntityType.DOMAIN, "example.com", finding)
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is False


def test_removing_the_last_star_removes_the_case():
    """No empty cases to tidy up: a case exists exactly while something is starred in it."""
    finding = _star()
    star(EntityType.DOMAIN, "example.com", finding)
    unstar(EntityType.DOMAIN, "example.com", finding)
    assert list_cases() == ()
    assert load_case(case_id_for(EntityType.DOMAIN, "example.com")) is None


def test_removing_one_of_two_stars_keeps_the_case():
    a, b = _star(label="A"), _star(label="MX", value="0 .")
    star(EntityType.DOMAIN, "example.com", a)
    star(EntityType.DOMAIN, "example.com", b)
    unstar(EntityType.DOMAIN, "example.com", a)
    (case,) = list_cases()
    assert case.star_count == 1


def test_cases_are_listed_most_recently_updated_first():
    star(EntityType.DOMAIN, "old.example", _star())
    star(EntityType.DOMAIN, "new.example", _star())
    assert [c.value for c in list_cases()] == ["new.example", "old.example"]


def test_two_types_of_the_same_value_are_separate_cases():
    star(EntityType.DOMAIN, "acme.example", _star())
    star(EntityType.COMPANY, "acme.example", _star())
    assert len(list_cases()) == 2


def test_forget_all_empties_the_store_and_removes_the_file():
    star(EntityType.DOMAIN, "example.com", _star())
    assert cases_path().exists()
    assert forget_all() == 1
    assert list_cases() == ()
    assert not cases_path().exists()


def test_unknown_case_loads_as_none():
    assert load_case("domain:nope.example") is None


def test_clear_cache_never_touches_saved_cases(tmp_path, monkeypatch):
    """The trap the two-store design exists to avoid.

    --clear-cache is documented as a privacy control. If it also destroyed the work you
    deliberately saved, it would be a footgun rather than a feature.
    """
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    from casefile.cache import clear_cache

    star(EntityType.DOMAIN, "example.com", _star())
    clear_cache()
    assert len(list_cases()) == 1, "clear_cache destroyed saved cases"
