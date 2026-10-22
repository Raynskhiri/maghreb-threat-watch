import pytest

from mtw.domains import clean_host, is_same_or_subdomain, parse


@pytest.mark.parametrize("raw,expected", [
    ("https://Biat-Login.xyz/auth?x=1", "biat-login.xyz"),
    ("*.biat-login.xyz", "biat-login.xyz"),
    ("biat-login.xyz.", "biat-login.xyz"),
    ("http://user@evil.com:8080/path", "evil.com"),
    ("  WWW.Example.COM  ", "www.example.com"),
])
def test_clean_host(raw, expected):
    assert clean_host(raw) == expected


def test_parse_tunisian_second_level_suffix():
    pd = parse("secure.biat-online.com.tn")
    assert pd.suffix == "com.tn"
    assert pd.name == "biat-online"
    assert pd.subdomain == "secure"
    assert pd.registrable == "biat-online.com.tn"


def test_parse_hosting_platform_is_a_suffix():
    pd = parse("flouci-pay.netlify.app")
    assert pd.on_hosting
    assert pd.name == "flouci-pay"
    assert pd.registrable == "flouci-pay.netlify.app"


def test_parse_punycode_is_decoded():
    host = "biаt-login.com".encode("idna").decode()  # Cyrillic "а"
    pd = parse(host)
    assert pd.is_idn
    assert pd.host.startswith("xn--")
    assert pd.unicode_host == "biаt-login.com"


@pytest.mark.parametrize("raw", ["", "localhost", "192.168.1.10", "com.tn", "http://"])
def test_parse_rejects_non_domains(raw):
    assert parse(raw) is None


def test_subdomain_check():
    assert is_same_or_subdomain("www.biat.com.tn", "biat.com.tn")
    assert is_same_or_subdomain("biat.com.tn", "biat.com.tn")
    assert not is_same_or_subdomain("notbiat.com.tn", "biat.com.tn")
    assert not is_same_or_subdomain("biat.com.tn.evil.xyz", "biat.com.tn")
