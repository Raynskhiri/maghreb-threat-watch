from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from .. import __version__

USER_AGENT = f"maghreb-threat-watch/{__version__} (+https://github.com/topics/maghreb-threat-watch)"


@dataclass
class Observation:
    value: str                 # domain, certificate name or URL as seen in the source
    source: str
    url: str | None = None     # full URL when the source gives one (phishing feeds)
    extra: dict = field(default_factory=dict)


@dataclass
class SourceResult:
    name: str
    observations: list[Observation] = field(default_factory=list)
    status: str = "ok"         # ok, skipped, error
    detail: str = ""
    seconds: float = 0.0


def session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def get(sess: requests.Session, url: str, *, timeout: int = 60, retries: int = 2,
        accept: tuple[int, ...] = (), **kwargs) -> requests.Response:
    """GET with a couple of polite retries on timeouts and 5xx.

    Status codes listed in `accept` are returned instead of raising
    (crt.sh answers 404 when a search has no results)."""
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = sess.get(url, timeout=timeout, **kwargs)
            if resp.status_code in accept:
                return resp
            if resp.status_code >= 500 and attempt < retries:
                time.sleep(5 * (attempt + 1))
                continue
            resp.raise_for_status()
            return resp
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(5 * (attempt + 1))
    raise last_exc or RuntimeError(f"failed to fetch {url}")
