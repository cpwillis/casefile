import pytest

from casefile.config import get_key


@pytest.mark.parametrize(
    ("dotenv", "key", "expected"),
    [
        ("# a comment\n\nMY_KEY = from_file \nOTHER=x\n", "MY_KEY", "from_file"),
        ('Q="quoted"\n', "Q", "quoted"),
        ("MY_KEY=v\n", "ABSENT", None),
        (None, "ABSENT", None),  # no .env file at all
        # .env.example ships keys with empty values; those must not read as configured
        ("BLANK=\n", "BLANK", None),
    ],
)
def test_dotenv_parsing(monkeypatch, tmp_path, dotenv, key, expected):
    monkeypatch.delenv(key, raising=False)
    path = tmp_path / ".env"
    if dotenv is not None:
        path.write_text(dotenv)
    assert get_key(key, path) == expected


def test_environment_wins_over_dotenv(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("MY_KEY=from_file\n")
    monkeypatch.setenv("MY_KEY", "from_env")
    assert get_key("MY_KEY", tmp_path / ".env") == "from_env"


def test_a_non_utf8_dotenv_reads_as_absent_not_an_error(monkeypatch, tmp_path):
    """A .env with a stray non-UTF-8 byte must not raise into the panel; valid lines still read."""
    monkeypatch.delenv("MY_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_bytes(b"MY_KEY=ok\nJUNK=\xff\xfe\n")
    assert get_key("MY_KEY", path) == "ok"
    assert get_key("MISSING", path) is None
