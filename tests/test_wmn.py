from casefile.fetchers.wmn import WMN_ATTRIBUTION, check_url, load_sites


def test_dataset_loads_with_many_sites():
    sites = load_sites()
    assert len(sites) > 600


def test_every_site_has_a_usable_check_url():
    for site in load_sites():
        assert "{account}" in site.uri_check, site.name


def test_check_url_substitutes_and_encodes():
    (site,) = [s for s in load_sites() if "{account}" in s.uri_check][:1]
    url = check_url(site, "a b/c")
    assert "{account}" not in url
    assert "a%20b%2Fc" in url


def test_attribution_names_the_project_and_licence():
    assert "WhatsMyName" in WMN_ATTRIBUTION
    assert "CC BY-SA 4.0" in WMN_ATTRIBUTION


def test_protection_flags_are_exposed():
    sites = load_sites()
    assert any(s.protection for s in sites), "the dataset marks captcha/cloudflare sites"
