import json

import pytest

from casefile.cli import main


def test_text_output_lists_types_and_links(capsys):
    assert main(["example.com"]) == 0
    out = capsys.readouterr().out
    assert "DOMAIN" in out
    assert "crt.sh" in out
    assert "https://crt.sh/?q=example.com" in out


def test_json_output_is_valid_and_structured(capsys):
    assert main(["example.com", "--json"]) == 0
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
