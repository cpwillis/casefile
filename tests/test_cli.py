import json

import pytest

from casefile.cli import main


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
    import casefile.cli as climod
    from casefile.fetchers import Finding, SourceResult, State

    async def fake_run(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="A", value="192.0.2.10"),))

    monkeypatch.setattr(climod, "run_fetcher", fake_run)
    assert main(["example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert any(s["state"] == "ok" for s in domain["sources"])


def test_no_fetch_omits_sources(monkeypatch, capsys):
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
    import casefile.cli as climod
    from casefile.fetchers import Finding, SourceResult, State

    async def fake_run(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="handle", value="benign\x1b[2K\rERASED"),))

    monkeypatch.setattr(climod, "run_fetcher", fake_run)
    assert main(["example.com"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\r" not in out
    assert "benign" in out
    assert "ERASED" in out
