from datetime import date

from mtw.report import defang_host, defang_url, render_spl, render_xql

FINDING = {
    "date": "2026-10-22", "host": "secure.biat-login.xyz", "unicode_host": "secure.biat-login.xyz",
    "registrable": "biat-login.xyz", "brand_name": "BIAT", "country": "TN", "sector": "bank",
    "severity": "high", "score": 80, "match_type": "exact", "sources": ["openphish"],
}


def test_defang_host():
    assert defang_host("biat-login.xyz") == "biat-login[.]xyz"


def test_defang_url_only_touches_scheme_and_host():
    assert defang_url("https://biat-login.xyz/a.php?x=1.2") == "hxxps://biat-login[.]xyz/a.php?x=1.2"


def test_xql_hunts_registrable_domain_with_escaped_dots():
    q = render_xql([FINDING], date(2026, 10, 22))
    assert "dataset = xdr_data" in q
    assert 'dns_query_name ~= "(^|[.])(?:biat-login[.]xyz)$"' in q
    assert "config case_sensitive = false" in q.splitlines()[4]


def test_xql_and_spl_when_nothing_found():
    assert "Nothing to hunt" in render_xql([], date(2026, 10, 22))
    assert "no medium or high" in render_spl([], date(2026, 10, 22))


def test_spl_includes_subdomain_wildcard():
    q = render_spl([FINDING], date(2026, 10, 22))
    assert '"biat-login.xyz", "*.biat-login.xyz"' in q
    assert "datamodel=Network_Resolution" in q
