import pytest

from mtw.matcher import damerau

SEV_RANK = {"low": 1, "medium": 2, "high": 3}

# (domain, expected brand id, minimum severity, expected match type)
POSITIVES = [
    ("biat-secure-login.xyz", "biat", "high", "exact"),
    ("biatsecurelogin.top", "biat", "high", "affix"),
    ("mybiat.online", "biat", "medium", "affix"),
    ("biat.com.tn.verify-account.xyz", "biat", "high", "exact"),
    ("biat-com-tn.top", "biat", "high", "exact"),
    ("b1at-tn.com", "biat", "high", "leet"),
    ("biаt-login.com".encode("idna").decode(), "biat", "high", "homoglyph"),
    ("espace-client-attijari.site", "attijari-tn", "high", "exact"),
    ("attijarlbank-login.com", "attijari-tn", "medium", "typo"),
    ("amenb4nk.net", "amen", "medium", "leet"),
    ("ооredoo-gift.com".encode("idna").decode(), "ooredoo", "high", "homoglyph"),
    ("oredoo-recharge.xyz", "ooredoo", "medium", "typo"),
    ("poste.tn.colis-suivi.xyz", "poste-tn", "high", "affix"),
    ("tunisietelecom-facture.online", "tunisietelecom", "high", "exact"),
    ("flouci-pay.netlify.app", "flouci", "high", "exact"),
    ("baridimob-dz.top", "poste-dz", "high", "exact"),
    ("royalairmaroc-promo.xyz", "ram", "high", "exact"),
    ("stb-tn-verification.com", "stb", "medium", "weak"),
    ("steg-facture-tn.com", "steg", "medium", "weak"),
    ("cmi-paiement.com", "cmi", "low", "weak"),
    ("https://jibaya-impots.com/declaration", "finances-tn", "medium", "exact"),
]

# Real domains from a WhoisDS newly-registered list and the OpenPhish feed
# that a naive substring search would flag. None of them should match.
NEGATIVES = [
    "posterflex.com",            # "poste"
    "laposteexpress.com",        # French La Poste, not ours
    "laposte-livraison.com",
    "sibiatex.online",           # "biat" inside another word
    "wafapartners.com",          # "wafa"
    "tunisiansabroad.com",
    "tn-lm.com",
    "goatbet178.online",         # once matched "atbnet" as a typo
    "plusonedesk.com",           # once matched "sonede"
    "stinet.chat",               # once matched "stbnet"
    "steg-sparvurtum.site",      # "steg" is a German word
    "dinar-exchange.com",        # "dinar" vs "edinar"
    "sncf-connect-login.com",    # SNCF France vs SNCFT
    "tmobile-login.com",
    "bankofamerica-login.vercel.app",
    "stbcafe.com",
    "iam-rich.com",
]

# Includes real subdomains seen in crt.sh that were flagged before the
# official domain list was complete (attijarinet is Attijariwafa's e-banking).
OFFICIAL = ["www.biat.com.tn", "e-dinar.poste.tn", "ebanking.attijaribank.com.tn", "www.ooredoo.qa", "biat.com.tn",
            "attijarinet.attijariwafa.com", "attijarifactures.attijariwafa.com"]


@pytest.mark.parametrize("domain,brand,min_sev,kind", POSITIVES)
def test_detects_lookalikes(matcher, domain, brand, min_sev, kind):
    f = matcher.evaluate(domain)
    assert f is not None, f"{domain} was not flagged"
    assert f.brand_id == brand
    assert f.match_type == kind
    assert SEV_RANK[f.severity] >= SEV_RANK[min_sev], f.reasons


@pytest.mark.parametrize("domain", NEGATIVES)
def test_ignores_noise(matcher, domain):
    f = matcher.evaluate(domain)
    assert f is None, f"{domain} flagged as {f and f.brand_id}: {f and f.reasons}"


@pytest.mark.parametrize("domain", OFFICIAL)
def test_never_flags_official_domains(matcher, domain):
    assert matcher.is_allowed(domain)
    assert matcher.evaluate(domain) is None


def test_reasons_add_up_to_score(matcher):
    f = matcher.evaluate("biat-secure-login.xyz")
    import re
    points = sum(int(m) for r in f.reasons for m in re.findall(r"\(\+(\d+)\)", r))
    assert points == f.score


def test_score_is_capped(matcher):
    f = matcher.evaluate("biat.com.tn.biat-secure-login-verify-account.xyz")
    assert f.score == 100


def test_damerau_distance():
    assert damerau("attijaribank", "attijarlbank", 2) == 1
    assert damerau("ooredoo", "oredoo", 2) == 1
    assert damerau("abcd", "abdc", 2) == 1          # transposition
    assert damerau("biat", "something", 2) == 3     # early exit returns limit + 1
