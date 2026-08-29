import pytest

from casefile.cases import (
    CaseStoreError,
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


def test_deleting_a_case_takes_its_stars_with_it():
    """delete_case relies on the ON DELETE CASCADE, so the pragma that enables it is load-bearing.

    Without this, a regression in store.connect's `PRAGMA foreign_keys = ON` would orphan every
    star silently: the case list would look right and the rows would still be on disk.
    """
    from casefile.cases import _connect, delete_case

    star(EntityType.DOMAIN, "example.com", _star(label="A"))
    star(EntityType.DOMAIN, "example.com", _star(label="MX", value="0 ."))
    star(EntityType.DOMAIN, "other.example", _star())
    assert delete_case(case_id_for(EntityType.DOMAIN, "example.com")) is True
    with _connect() as conn:
        remaining = conn.execute("SELECT case_id FROM stars").fetchall()
    assert remaining == [("domain:other.example",)], f"orphaned stars left behind: {remaining}"


def test_deleting_an_unknown_case_reports_that_nothing_went():
    star(EntityType.DOMAIN, "example.com", _star())
    from casefile.cases import delete_case

    assert delete_case("domain:never-saved.example") is False
    assert len(list_cases()) == 1


def test_unknown_case_loads_as_none():
    assert load_case("domain:nope.example") is None


def test_clear_cache_never_touches_saved_cases():
    """The trap the two-store design exists to avoid.

    --clear-cache is documented as a privacy control. If it also destroyed the work you
    deliberately saved, it would be a footgun rather than a feature.
    """
    from casefile.cache import clear_cache

    star(EntityType.DOMAIN, "example.com", _star())
    clear_cache()
    assert len(list_cases()) == 1, "clear_cache destroyed saved cases"


def test_a_corrupt_store_does_not_break_reads():
    """The cases store sits on the hot path of core search, which never depended on it."""
    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is not a sqlite database")
    assert list_cases() == ()
    assert load_case("domain:example.com") is None
    assert is_starred(EntityType.DOMAIN, "example.com", _star()) is False


def test_a_corrupt_store_reports_a_failed_write_rather_than_pretending():
    """Silently failing to save is worse than saying the save failed."""
    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is not a sqlite database")
    with pytest.raises(CaseStoreError):
        star(EntityType.DOMAIN, "example.com", _star())


def test_browsing_alone_does_not_create_the_store():
    is_starred(EntityType.DOMAIN, "example.com", _star())
    list_cases()
    assert not cases_path().exists()


def test_forget_all_removes_the_rollback_journal():
    """sqlite defaults to rollback-journal mode, and the journal holds the pre-image pages."""
    star(EntityType.DOMAIN, "example.com", _star())
    forget_all()
    leftovers = [p.name for p in cases_path().parent.iterdir()]
    assert leftovers == [], f"purge left {leftovers} behind"
