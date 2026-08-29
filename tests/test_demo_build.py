import ipaddress
import re

import pytest

from casefile.demo import build_demo, demo_slug_for, load_targets

FORBIDDEN = ("hx-get", "hx-post", "hx-trigger", "/panel/", "/star", "/case/", "127.0.0.1", "localhost")


@pytest.fixture
def built(tmp_path):
    build_demo(tmp_path / "dist")
    return tmp_path / "dist"


def test_build_writes_an_index_and_a_page_per_target(built):
    assert (built / "index.html").exists()
    for target in load_targets():
        assert (built / f"{demo_slug_for(target.query)}.html").exists()


def test_the_demo_is_inert(built):
    """No backend exists behind these pages, so nothing may try to call one."""
    for page in built.glob("*.html"):
        text = page.read_text()
        for token in FORBIDDEN:
            assert token not in text, f"{page.name} references {token}"


def test_the_search_box_is_disabled(built):
    """A form that silently does nothing is worse than one visibly switched off."""
    assert "disabled" in (built / "index.html").read_text()


def test_pages_navigate_to_each_other_without_javascript(built):
    index = (built / "index.html").read_text()
    hrefs = set(re.findall(r'href="([a-z0-9.-]+\.html)"', index))
    assert hrefs, "index links to no example pages"
    for href in hrefs:
        assert (built / href).exists()


def test_real_states_are_shown_not_just_successes(built):
    """A demo where everything succeeded misrepresents the tool."""
    text = (built / "example-com.html").read_text()
    states = set(re.findall(r'data-state="([a-z-]+)"', text))
    assert "ok" in states
    assert {"empty", "timeout"} & states, f"only happy-path states shown: {states}"


def test_static_assets_are_copied(built):
    assert (built / "static" / "casefile.css").exists()


def test_demo_data_carries_no_real_personal_data():
    """Institutional or reserved targets only. This ships in a public repo."""
    for target in load_targets():
        for result in target.panels.values():
            for finding in result.findings:
                for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", finding.value):
                    address = ipaddress.ip_address(token)
                    assert not address.is_global, f"{token} is a routable address in demo data"


def test_every_demo_target_produces_at_least_one_section(built):
    for target in load_targets():
        page = (built / f"{demo_slug_for(target.query)}.html").read_text()
        assert 'class="type-section"' in page, f"{target.query} rendered no readings"
