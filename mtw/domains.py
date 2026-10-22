"""Domain parsing helpers.

Keeps the project dependency-free: instead of the full Public Suffix List we
ship the second-level suffixes that matter for the Maghreb plus the free
hosting platforms phishing kits love. Good enough for scoring; not a general
purpose PSL replacement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Multi-label public suffixes we care about.
MULTI_SUFFIXES = {
    # Tunisia
    "com.tn", "ens.tn", "fin.tn", "gov.tn", "ind.tn", "intl.tn", "nat.tn",
    "net.tn", "org.tn", "info.tn", "perso.tn", "tourism.tn", "edunet.tn",
    "rnrt.tn", "rns.tn", "rnu.tn", "mincom.tn", "agrinet.tn", "defense.tn",
    # Morocco
    "co.ma", "net.ma", "gov.ma", "org.ma", "ac.ma", "press.ma",
    # Algeria
    "com.dz", "org.dz", "net.dz", "gov.dz", "edu.dz", "asso.dz", "pol.dz", "art.dz",
    # Libya, Egypt and other common ones
    "com.ly", "net.ly", "gov.ly", "org.ly", "com.eg", "gov.eg",
    "co.uk", "org.uk", "com.au", "com.br", "co.za", "com.sa", "co.in", "com.tr",
}

# Free hosting and tunnelling platforms. Treated as public suffixes so that
# "biat-login.netlify.app" has the registrable name "biat-login".
HOSTING_SUFFIXES = {
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "appspot.com", "github.io", "gitlab.io",
    "herokuapp.com", "onrender.com", "fly.dev", "railway.app", "glitch.me",
    "repl.co", "replit.app", "blogspot.com", "wixsite.com", "weebly.com",
    "webflow.io", "framer.app", "framer.website", "gitbook.io",
    "000webhostapp.com", "square.site", "mystrikingly.com", "godaddysites.com",
    "carrd.co", "azurewebsites.net", "azurestaticapps.net", "surge.sh",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
    "duckdns.org", "ddns.net", "no-ip.org", "serveo.net", "loca.lt",
    "teachable.com", "myshopify.com", "hostingersite.com", "webcindario.com",
}

_ALL_SUFFIXES = MULTI_SUFFIXES | HOSTING_SUFFIXES
_HOST_RE = re.compile(r"^[a-z0-9\-\._~ -￿]+$")


@dataclass(frozen=True)
class ParsedDomain:
    host: str            # full host, lowercased, ascii (punycode) form
    unicode_host: str    # host with punycode labels decoded
    registrable: str     # e.g. "biat-login.xyz"
    name: str            # registrable without suffix, e.g. "biat-login"
    subdomain: str       # e.g. "secure.www"
    suffix: str          # e.g. "xyz", "com.tn", "netlify.app"
    is_idn: bool
    on_hosting: bool


def clean_host(value: str) -> str:
    """Turn a URL, a cert name or a raw domain into a bare lowercase host."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if value.count(":") == 1:
        value = value.split(":")[0]
    value = value.lstrip("*.").strip(".")
    return value


def to_unicode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or ":" in host


def parse(value: str) -> ParsedDomain | None:
    host = clean_host(value)
    if not host or "." not in host or is_ip(host) or not _HOST_RE.match(host):
        return None
    ascii_host = to_ascii(host)
    uni_host = to_unicode(ascii_host)
    labels = ascii_host.split(".")

    suffix = labels[-1]
    for n in (3, 2):
        if len(labels) >= n:
            candidate = ".".join(labels[-n:])
            if candidate in _ALL_SUFFIXES:
                suffix = candidate
                break
    suffix_len = suffix.count(".") + 1
    if len(labels) <= suffix_len:
        return None

    name_ascii = labels[-suffix_len - 1]
    sub_ascii = ".".join(labels[: -suffix_len - 1])
    name = to_unicode(name_ascii)
    sub = to_unicode(sub_ascii) if sub_ascii else ""

    return ParsedDomain(
        host=ascii_host,
        unicode_host=uni_host,
        registrable=f"{name_ascii}.{suffix}",
        name=name,
        subdomain=sub,
        suffix=suffix,
        is_idn="xn--" in ascii_host,
        on_hosting=suffix in HOSTING_SUFFIXES,
    )


def is_same_or_subdomain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)
