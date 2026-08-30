import json

import pytest
from helpers import stub_result

from casefile.cli import main
from casefile.fetchers import Finding, SourceResult, State


def test_text_output_lists_types_and_links(capsys):
    assert main(["example.com", "--no-fetch"]) == 0
    out = capsys.readouterr().out
    assert "DOMAIN" in out
    assert "crt.sh" in out
    assert "https://crt.sh/?q=example.com" in out


def test_json_output_is_valid_and_structured(capsys):
    assert main(["example.com", "--json", "--no-fetch"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"] == "example.com"
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert domain["value"] == "example.com"
    assert any(link["id"] == "crtsh" for link in domain["links"])


def test_unrecognised_input_exits_nonzero(capsys):
    assert main(["   "]) == 1
    assert "nothing recognised" in capsys.readouterr().err


def test_only_one_positional_value_is_accepted():
    with pytest.raises(SystemExit):
        main(["one.example", "two.example"])


def test_fetch_fans_out_over_registered_sources(monkeypatch, capsys):
    async def fake_run(source_id, value, entity_type, client, *, use_cache=True):
        return SourceResult(source_id, State.OK, (Finding(label="A", value="192.0.2.10"),))

    monkeypatch.setattr("casefile.cli.run_cached", fake_run)
    assert main(["example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert any(s["state"] == "ok" for s in domain["sources"])


def test_no_fetch_omits_sources(capsys):
    assert main(["example.com", "--json", "--no-fetch"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert domain["sources"] == []


def test_json_links_carry_the_full_contract_keys(capsys):
    assert main(["example.com", "--json", "--no-fetch"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert domain["links"]
    for link in domain["links"]:
        assert set(link) == {"id", "name", "url", "notes"}


def test_text_output_strips_control_characters_from_third_party_findings(monkeypatch, capsys):
    """A finding value with ESC/CR must not reach the terminal raw, or it can blank prior output."""

    async def fake_run(source_id, value, entity_type, client, *, use_cache=True):
        return SourceResult(source_id, State.OK, (Finding(label="handle", value="benign\x1b[2K\rERASED"),))

    monkeypatch.setattr("casefile.cli.run_cached", fake_run)
    assert main(["example.com"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\r" not in out
    assert "benign" in out
    assert "ERASED" in out


def test_clear_cache_flag_reports_and_exits_zero(capsys):
    """--clear-cache is documented as a privacy control, so it must actually be wired up."""
    assert main(["--clear-cache"]) == 0
    assert "cleared" in capsys.readouterr().out


def test_no_cache_flag_disables_the_cache(monkeypatch, capsys):
    """--no-fetch would skip _fetch_all and leave --no-cache with zero coverage, so this must reach the fetch path."""
    seen_use_cache = []

    async def fake_run(source_id, value, entity_type, client, *, use_cache=True):
        seen_use_cache.append(use_cache)
        return SourceResult(source_id, State.OK)

    monkeypatch.setattr("casefile.cli.run_cached", fake_run)
    assert main(["example.com", "--json", "--no-cache"]) == 0
    assert "candidates" in capsys.readouterr().out
    assert seen_use_cache
    assert all(use_cache is False for use_cache in seen_use_cache)


@pytest.mark.parametrize(("extra", "deep"), [([], False), (["--deep"], True)])
def test_deep_is_what_admits_the_on_demand_sources(monkeypatch, capsys, extra, deep):
    """casefile <username> must not fire hundreds of requests without --deep."""
    seen = []

    async def fake(source_id, value, entity_type, client, *, use_cache=True):
        seen.append(source_id)
        return SourceResult(source_id, State.OK, (Finding(label="A", value="1"),))

    monkeypatch.setattr("casefile.cli.run_cached", fake)
    assert main(["octocat", "--json", *extra]) == 0
    assert ("whatsmyname" in seen) is deep
    assert "github" in seen  # the cheap source runs either way


def test_text_output_keeps_a_finding_url(monkeypatch, capsys):
    """For a WhatsMyName hit the value is the category and the url is the result, so dropping urls loses the hit."""

    async def fake(source_id, value, entity_type, client, *, use_cache=True):
        return SourceResult(source_id, State.OK, (Finding("GitHub", "coding", url="https://github.example/x"),))

    monkeypatch.setattr("casefile.cli.run_cached", fake)
    assert main(["octocat"]) == 0
    assert "https://github.example/x" in capsys.readouterr().out


def test_a_fetched_source_is_not_also_listed_as_a_link(monkeypatch, capsys):
    """A source is shown once: as its result if it ran, otherwise as a link."""
    monkeypatch.setattr("casefile.cli.run_cached", stub_result(Finding("A", "1")))
    assert main(["example.com", "--json"]) == 0
    domain = next(c for c in json.loads(capsys.readouterr().out)["candidates"] if c["type"] == "domain")
    assert "crtsh" in {s["source_id"] for s in domain["sources"]}
    assert not any(link["id"] == "crtsh" for link in domain["links"])


def test_no_fetch_keeps_every_link_including_the_fetchable_ones(capsys):
    """Nothing ran, so nothing else represents those sources and the links must all survive."""
    assert main(["example.com", "--json", "--no-fetch"]) == 0
    domain = next(c for c in json.loads(capsys.readouterr().out)["candidates"] if c["type"] == "domain")
    assert any(link["id"] == "crtsh" for link in domain["links"])


def test_the_sanitiser_shows_a_homograph_instead_of_repairing_it(monkeypatch, capsys):
    """str.isprintable() is false for zero-width and bidi chars, so deleting them turns a lookalike into its target."""
    from casefile.export import sanitize

    assert sanitize("paypa\u200bl.example") == "paypa\\u200bl.example"
    assert sanitize("a\u202eb") == "a\\u202eb"
    assert sanitize("a\xa0b") == "a\\xa0b"
    assert "\x1b" not in sanitize("a\x1b[31mb")


def test_cases_lists_what_is_saved_and_exits_nonzero_when_nothing_is(capsys):
    from casefile.cases import save_target
    from casefile.types import EntityType

    assert main(["--cases"]) == 1
    assert "no saved cases" in capsys.readouterr().err

    save_target(EntityType.USERNAME, "acme-example")
    assert main(["--cases"]) == 0
    out = capsys.readouterr().out
    assert "acme-example" in out


def test_export_writes_the_case_and_rejects_an_unknown_id(capsys):
    from casefile.cases import Star, list_cases, star
    from casefile.types import EntityType

    star(EntityType.DOMAIN, "example.com", Star("dns", "A", "192.0.2.10"))
    cid = list_cases()[0].id

    assert main(["--export", cid]) == 0
    assert "192.0.2.10" in capsys.readouterr().out
    assert main(["--export", cid, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "example.com"

    assert main(["--export", "never-existed"]) == 1
    assert "no such case" in capsys.readouterr().err


def test_export_escapes_a_control_character_rather_than_rewriting_the_terminal(capsys):
    """An exported value is third-party text going to a terminal, and it must survive readable."""
    from casefile.cases import Star, list_cases, star
    from casefile.types import EntityType

    star(EntityType.DOMAIN, "example.com", Star("dns", "A", "a\x1b[31mred"))
    assert main(["--export", list_cases()[0].id]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "red" in out, "the value was dropped instead of escaped"


def test_forget_cases_empties_the_store(capsys):
    from casefile.cases import list_cases, save_target
    from casefile.types import EntityType

    save_target(EntityType.DOMAIN, "example.com")
    assert main(["--forget-cases"]) == 0
    assert "forgot 1" in capsys.readouterr().out
    assert list_cases() == ()


def test_build_demo_writes_a_usable_site(capsys, tmp_path):
    out = tmp_path / "site"
    assert main(["--build-demo", str(out)]) == 0
    assert "wrote" in capsys.readouterr().out
    assert (out / "index.html").exists()
    assert (out / "static" / "casefile.css").exists()


def test_deep_accepts_a_named_source_not_only_all_of_them(monkeypatch, capsys):
    """All-or-nothing made one expensive source a switch over every expensive source there will ever be."""
    seen = []

    async def fake(source_id, value, entity_type, client, *, use_cache=True):
        seen.append(source_id)
        return SourceResult(source_id, State.OK, (Finding(label="A", value="1"),))

    monkeypatch.setattr("casefile.cli.run_cached", fake)
    assert main(["octocat", "--json", "--deep", "whatsmyname"]) == 0
    assert "whatsmyname" in seen

    seen.clear()
    assert main(["octocat", "--json", "--deep", "no-such-source"]) == 0
    assert "whatsmyname" not in seen, "a name that matches nothing must not run everything"
    assert "github" in seen


def test_check_links_reports_a_verdict_per_link(monkeypatch, capsys):
    import casefile.cli as climod

    async def fake(links, client):
        return {link.id: "missing" if link.id == "crtsh" else "live" for link in links}

    monkeypatch.setattr(climod, "check_links", fake)
    assert main(["example.com", "--no-fetch", "--check-links"]) == 0
    out = capsys.readouterr().out
    assert "missing" in out and "live" in out
    assert "tell you nothing" in out


def test_deep_before_the_target_does_not_swallow_it(monkeypatch, capsys):
    """`casefile --deep example.com` must search the target with deep sources, not read it as a source and serve."""
    seen = {}

    async def fake(candidates, use_cache=True, deep=False):
        seen["deep"] = deep
        seen["values"] = [c.value for c in candidates]
        return {}

    monkeypatch.setattr("casefile.cli._fetch_all", fake)
    assert main(["--deep", "example.com"]) == 0
    assert "example.com" in seen["values"]  # the target was searched, not treated as a source
    assert seen["deep"] is True  # bare deep: all on-demand sources
