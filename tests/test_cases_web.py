import pytest
from starlette.testclient import TestClient

from casefile.web.app import app

client = TestClient(app)
SAME = {"sec-fetch-site": "same-origin"}
STAR = {"t": "domain", "v": "example.com", "source_id": "dns", "label": "A", "value": "192.0.2.10", "url": ""}


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    yield


def test_star_requires_a_same_origin_header():
    """A page you visit while casefile runs must not be able to write to your cases."""
    assert client.post("/star", data=STAR, headers={"sec-fetch-site": "cross-site"}).status_code == 403


def test_star_refuses_a_request_with_no_sec_fetch_site():
    """Stricter than the read-only panel guard: only this app's own page may mutate."""
    assert client.post("/star", data=STAR).status_code == 403


def test_star_is_not_reachable_by_get():
    assert client.get("/star", params=STAR).status_code == 405


def test_starring_then_unstarring_round_trips():
    from casefile.cases import list_cases

    first = client.post("/star", data=STAR, headers=SAME)
    assert first.status_code == 200
    assert "★" in first.text  # filled star
    assert len(list_cases()) == 1

    second = client.post("/star", data=STAR, headers=SAME)
    assert "☆" in second.text  # hollow again
    assert list_cases() == ()


def test_star_rejects_an_unknown_entity_type():
    bad = dict(STAR, t="not-a-type")
    assert client.post("/star", data=bad, headers=SAME).status_code == 400


def test_cases_page_lists_a_saved_case():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get("/cases").text
    assert "example.com" in text
    assert "1 saved" in text


def test_index_shows_where_you_left_off():
    assert "Where you left off" not in client.get("/").text
    client.post("/star", data=STAR, headers=SAME)
    assert "Where you left off" in client.get("/").text


def test_case_detail_shows_only_starred_findings():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get("/case/domain:example.com").text
    assert "192.0.2.10" in text
    assert "rdap" not in text


def test_missing_case_falls_back_to_the_list():
    assert "no longer exists" in client.get("/case/domain:nope.example").text


@pytest.mark.parametrize(
    ("fmt", "needle"), [("md", "# example.com"), ("json", '"target"'), ("html", "<!doctype html>")]
)
def test_export_downloads_each_format(fmt, needle):
    client.post("/star", data=STAR, headers=SAME)
    resp = client.get(f"/case/domain:example.com/export.{fmt}")
    assert resp.status_code == 200
    assert needle in resp.text
    assert "attachment" in resp.headers["content-disposition"]


def test_export_rejects_an_unknown_format():
    client.post("/star", data=STAR, headers=SAME)
    assert client.get("/case/domain:example.com/export.pdf").status_code == 404
