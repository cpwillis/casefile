import pytest

import casefile.fetchers.http as http


def test_the_default_suite_runs_without_politeness_sleeps():
    """They were 88% of the suite's wall time against a transport with nobody to be polite to."""
    assert http.JITTER == 0.0
    assert http.BACKOFF == 0.0


@pytest.mark.live
def test_the_live_suite_keeps_its_politeness():
    """`make live` really does hit several hundred third parties, so it must not be stripped."""
    assert http.JITTER == 0.25
    assert http.BACKOFF == 0.5
