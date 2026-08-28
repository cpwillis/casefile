from casefile.config import get_key


def test_environment_wins_over_dotenv(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("MY_KEY=from_file\n")
    monkeypatch.setenv("MY_KEY", "from_env")
    assert get_key("MY_KEY", tmp_path / ".env") == "from_env"


def test_reads_from_dotenv_when_environment_is_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("MY_KEY", raising=False)
    (tmp_path / ".env").write_text("# a comment\n\nMY_KEY = from_file \nOTHER=x\n")
    assert get_key("MY_KEY", tmp_path / ".env") == "from_file"


def test_missing_key_is_none(monkeypatch, tmp_path):
    monkeypatch.delenv("ABSENT", raising=False)
    (tmp_path / ".env").write_text("MY_KEY=v\n")
    assert get_key("ABSENT", tmp_path / ".env") is None


def test_missing_dotenv_file_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.delenv("ABSENT", raising=False)
    assert get_key("ABSENT", tmp_path / "nope.env") is None


def test_quotes_are_stripped(monkeypatch, tmp_path):
    monkeypatch.delenv("Q", raising=False)
    (tmp_path / ".env").write_text('Q="quoted"\n')
    assert get_key("Q", tmp_path / ".env") == "quoted"


def test_empty_value_is_treated_as_absent(monkeypatch, tmp_path):
    """`.env.example` ships keys with empty values; those must not read as configured."""
    monkeypatch.delenv("BLANK", raising=False)
    (tmp_path / ".env").write_text("BLANK=\n")
    assert get_key("BLANK", tmp_path / ".env") is None
