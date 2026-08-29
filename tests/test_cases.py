import pytest

from casefile.cases import (
    CaseStoreError,
    Star,
    case_for_target,
    cases_path,
    delete_case,
    forget_all,
    is_starred,
    list_cases,
    load_case,
    remove_target,
    rename_case,
    save_target,
    star,
    unstar,
)
from casefile.types import EntityType


def _star(label="A", value="192.0.2.10", url=None):
    return Star(source_id="dns", label=label, value=value, url=url)


def test_cases_path_follows_xdg_data_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert cases_path() == tmp_path / "casefile" / "cases.db"


def test_saving_a_search_creates_a_case_with_no_stars_in_it():
    """The gap this closes: a search worth keeping, with nothing yet worth starring."""
    cid = save_target(EntityType.USERNAME, "acme-example")
    (case,) = list_cases()
    assert case.id == cid
    assert case.name == "acme-example"
    assert case.star_count == 0
    assert [(t.entity_type, t.value) for t in case.targets] == [("username", "acme-example")]


def test_two_identifiers_can_be_joined_into_one_case():
    """The point of the model: these are the same subject to a person and nothing alike to a
    detector, so they must be one row on the dashboard, not two."""
    cid = save_target(EntityType.USERNAME, "acme-example")
    save_target(EntityType.DOMAIN, "acme.example", case_id=cid)
    (case,) = list_cases()
    assert {t.value for t in case.targets} == {"acme-example", "acme.example"}
    assert {t.entity_type for t in case.targets} == {"username", "domain"}


def test_joining_a_target_that_already_had_its_own_case_moves_its_findings():
    """Save one, save the other, then decide they are the same thing: nothing may be orphaned."""
    save_target(EntityType.USERNAME, "acme-example")
    star(EntityType.USERNAME, "acme-example", _star(label="profile", value="p"))
    second = save_target(EntityType.DOMAIN, "acme.example")
    star(EntityType.DOMAIN, "acme.example", _star(label="A", value="192.0.2.10"))
    assert len(list_cases()) == 2

    save_target(EntityType.USERNAME, "acme-example", case_id=second)
    (case,) = list_cases()
    assert len(case.targets) == 2
    assert case.star_count == 2, "a finding was lost when its target moved case"
    assert {s.target_value for s in case.stars} == {"acme-example", "acme.example"}


def test_case_for_target_finds_the_case_a_search_is_already_in():
    cid = save_target(EntityType.USERNAME, "acme-example")
    found = case_for_target(EntityType.USERNAME, "acme-example")
    assert found is not None and found.id == cid
    assert case_for_target(EntityType.USERNAME, "someone-else") is None


def test_an_identifier_belongs_to_at_most_one_case():
    a = save_target(EntityType.USERNAME, "acme-example")
    b = save_target(EntityType.DOMAIN, "other.example")
    save_target(EntityType.USERNAME, "acme-example", case_id=b)
    assert case_for_target(EntityType.USERNAME, "acme-example").id == b
    assert load_case(a) is None, "the case it left kept an empty husk on the dashboard"


def test_a_case_that_loses_its_last_identifier_goes():
    """Distinct from losing its last star, which keeps the case: an investigation with no
    identifiers in it has nothing left to be about."""
    save_target(EntityType.DOMAIN, "example.com")
    remove_target(EntityType.DOMAIN, "example.com")
    assert list_cases() == ()


def test_starring_alone_still_starts_a_case():
    """The quick path stays one click: you should not have to save before you can star."""
    star(EntityType.DOMAIN, "example.com", _star())
    (case,) = list_cases()
    assert case.name == "example.com"
    assert case.star_count == 1


def test_starring_the_same_finding_twice_is_idempotent():
    star(EntityType.DOMAIN, "example.com", _star())
    star(EntityType.DOMAIN, "example.com", _star())
    assert list_cases()[0].star_count == 1


def test_removing_the_last_star_keeps_the_case():
    """Changed from the old model on purpose: a case you saved deliberately must not evaporate
    because you changed your mind about one row."""
    finding = _star()
    star(EntityType.DOMAIN, "example.com", finding)
    unstar(EntityType.DOMAIN, "example.com", finding)
    (case,) = list_cases()
    assert case.star_count == 0
    assert len(case.targets) == 1


def test_is_starred_reflects_state():
    finding = _star()
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is False
    star(EntityType.DOMAIN, "example.com", finding)
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is True
    unstar(EntityType.DOMAIN, "example.com", finding)
    assert is_starred(EntityType.DOMAIN, "example.com", finding) is False


def test_stars_are_attributed_to_the_target_they_came_from():
    cid = save_target(EntityType.USERNAME, "acme-example")
    save_target(EntityType.DOMAIN, "acme.example", case_id=cid)
    star(EntityType.USERNAME, "acme-example", _star(label="profile", value="p"))
    star(EntityType.DOMAIN, "acme.example", _star(label="A", value="192.0.2.10"))
    case = load_case(cid)
    assert {(s.target_type, s.label) for s in case.stars} == {("username", "profile"), ("domain", "A")}
    assert {t.value: t.star_count for t in case.targets} == {"acme-example": 1, "acme.example": 1}


def test_removing_a_target_takes_its_findings_and_leaves_the_rest():
    cid = save_target(EntityType.USERNAME, "acme-example")
    save_target(EntityType.DOMAIN, "acme.example", case_id=cid)
    star(EntityType.USERNAME, "acme-example", _star(label="profile", value="p"))
    star(EntityType.DOMAIN, "acme.example", _star())
    remove_target(EntityType.DOMAIN, "acme.example")
    case = load_case(cid)
    assert [t.value for t in case.targets] == ["acme-example"]
    assert [s.label for s in case.stars] == ["profile"]


def test_a_case_can_be_renamed():
    cid = save_target(EntityType.USERNAME, "acme-example")
    rename_case(cid, "  Acme-Example investigation  ")
    assert load_case(cid).name == "Acme-Example investigation"


def test_a_case_cannot_be_renamed_to_nothing():
    cid = save_target(EntityType.USERNAME, "acme-example")
    with pytest.raises(CaseStoreError):
        rename_case(cid, "   ")
    assert load_case(cid).name == "acme-example"


def test_saving_onto_a_case_that_does_not_exist_is_refused():
    with pytest.raises(CaseStoreError):
        save_target(EntityType.USERNAME, "acme-example", case_id="nope")


def test_cases_are_listed_most_recently_updated_first():
    save_target(EntityType.DOMAIN, "old.example")
    save_target(EntityType.DOMAIN, "new.example")
    assert [c.name for c in list_cases()] == ["new.example", "old.example"]


def test_deleting_a_case_takes_its_targets_and_stars_with_it():
    """delete_case relies on ON DELETE CASCADE, so the pragma enabling it is load-bearing."""
    from casefile.cases import _connect

    cid = save_target(EntityType.USERNAME, "acme-example")
    star(EntityType.USERNAME, "acme-example", _star())
    save_target(EntityType.DOMAIN, "other.example")
    assert delete_case(cid) is True
    with _connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM stars").fetchone()[0] == 0
        assert [r[0] for r in conn.execute("SELECT value FROM targets")] == ["other.example"]


def test_deleting_an_unknown_case_reports_that_nothing_went():
    save_target(EntityType.DOMAIN, "example.com")
    assert delete_case("never-existed") is False
    assert len(list_cases()) == 1


def test_forget_all_empties_the_store_and_removes_the_file():
    save_target(EntityType.DOMAIN, "example.com")
    assert cases_path().exists()
    assert forget_all() == 1
    assert list_cases() == ()
    assert not cases_path().exists()


def test_unknown_case_loads_as_none():
    assert load_case("nope") is None


def test_clear_cache_never_touches_saved_cases():
    """The trap the two-store design exists to avoid: --clear-cache is documented as a privacy
    control, and destroying deliberately saved work would make it a footgun."""
    from casefile.cache import clear_cache

    save_target(EntityType.DOMAIN, "example.com")
    clear_cache()
    assert len(list_cases()) == 1


def test_a_corrupt_store_does_not_break_reads():
    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is not a sqlite database")
    assert list_cases() == ()
    assert load_case("whatever") is None
    assert case_for_target(EntityType.DOMAIN, "example.com") is None
    assert is_starred(EntityType.DOMAIN, "example.com", _star()) is False


def test_a_corrupt_store_reports_a_failed_write_rather_than_pretending():
    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is not a sqlite database")
    with pytest.raises(CaseStoreError):
        star(EntityType.DOMAIN, "example.com", _star())
    with pytest.raises(CaseStoreError):
        save_target(EntityType.DOMAIN, "example.com")


def test_browsing_alone_does_not_create_the_store():
    is_starred(EntityType.DOMAIN, "example.com", _star())
    case_for_target(EntityType.DOMAIN, "example.com")
    list_cases()
    assert not cases_path().exists()


def test_forget_all_removes_the_rollback_journal():
    """sqlite defaults to rollback-journal mode, and the journal holds the pre-image pages."""
    save_target(EntityType.DOMAIN, "example.com")
    forget_all()
    leftovers = [p.name for p in cases_path().parent.iterdir()]
    assert leftovers == [], f"purge left {leftovers} behind"


V1_SCHEMA = """
CREATE TABLE cases (
    id          TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE stars (
    case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_id  TEXT NOT NULL,
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    url        TEXT,
    starred_at REAL NOT NULL,
    PRIMARY KEY (case_id, source_id, label, value)
);
"""


def _write_v1_store():
    """A store as 1.0 left it: a case per target, and stars keyed only by case."""
    import sqlite3

    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    conn.execute("INSERT INTO cases VALUES ('domain:example.com', 'domain', 'example.com', 100.0, 200.0)")
    conn.execute("INSERT INTO cases VALUES ('username:octocat', 'username', 'octocat', 300.0, 400.0)")
    conn.executemany(
        "INSERT INTO stars VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("domain:example.com", "dns", "A", "192.0.2.10", None, 150.0),
            ("domain:example.com", "crtsh", "subdomain", "a.example.com", "https://a.example.com", 160.0),
            ("username:octocat", "github", "profile", "octocat", "https://github.example/x", 350.0),
        ],
    )
    conn.commit()
    conn.close()


def test_a_pre_existing_v1_store_is_migrated_rather_than_breaking():
    """CREATE TABLE IF NOT EXISTS is silent when the table exists with different columns, so
    without a migration an upgraded store opens fine and fails on the first write."""
    _write_v1_store()
    cases = list_cases()
    assert {c.name for c in cases} == {"example.com", "octocat"}
    by_name = {c.name: c for c in cases}
    assert [(t.entity_type, t.value) for t in by_name["example.com"].targets] == [("domain", "example.com")]
    assert by_name["example.com"].star_count == 2
    assert by_name["octocat"].star_count == 1


def test_migration_keeps_every_starred_finding_and_its_target():
    _write_v1_store()
    case = next(c for c in list_cases() if c.name == "example.com")
    assert {(s.source_id, s.label, s.value) for s in case.stars} == {
        ("dns", "A", "192.0.2.10"),
        ("crtsh", "subdomain", "a.example.com"),
    }
    assert {s.target_value for s in case.stars} == {"example.com"}
    assert next(s for s in case.stars if s.source_id == "crtsh").url == "https://a.example.com"


def test_a_migrated_store_is_then_fully_writable():
    """The failure this migration exists to prevent was on write, not on open."""
    _write_v1_store()
    cid = next(c for c in list_cases() if c.name == "octocat").id
    save_target(EntityType.DOMAIN, "octocat.example", case_id=cid)
    star(EntityType.DOMAIN, "octocat.example", _star())
    rename_case(cid, "octocat investigation")
    case = load_case(cid)
    assert case.name == "octocat investigation"
    assert {t.value for t in case.targets} == {"octocat", "octocat.example"}
    assert case.star_count == 2


def test_migration_runs_once_and_is_stable():
    _write_v1_store()
    first = [(c.name, c.star_count) for c in list_cases()]
    for _ in range(3):
        list_cases()
    assert [(c.name, c.star_count) for c in list_cases()] == first
