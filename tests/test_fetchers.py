from casefile.fetchers import Finding, NeedsKey, RateLimited, SourceResult, State


def test_state_names_are_exact():
    assert (State.OK, State.EMPTY, State.NEEDS_KEY, State.RATE_LIMITED, State.TIMEOUT, State.ERROR) == (
        "ok",
        "empty",
        "needs_key",
        "rate_limited",
        "timeout",
        "error",
    )


def test_finding_defaults_url_to_none():
    assert Finding(label="A", value="1").url is None


def test_source_result_is_flat_and_defaults_empty():
    r = SourceResult(source_id="x", state=State.EMPTY)
    assert r.findings == ()
    assert r.detail is None
    assert r.elapsed_ms == 0


def test_exceptions_exist():
    assert issubclass(NeedsKey, Exception)
    assert issubclass(RateLimited, Exception)
