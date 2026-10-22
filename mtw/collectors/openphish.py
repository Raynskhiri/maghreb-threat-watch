"""OpenPhish community feed: confirmed phishing URLs, refreshed a few times a day."""

from __future__ import annotations

import time

from .base import Observation, SourceResult, get, session

DEFAULT_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


def collect_openphish(*_, url: str = DEFAULT_URL, **__) -> SourceResult:
    started = time.monotonic()
    result = SourceResult("openphish")
    try:
        resp = get(session(), url, timeout=60)
        for line in resp.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                result.observations.append(Observation(value=line, source="openphish", url=line))
    except Exception as exc:  # noqa: BLE001
        result.status, result.detail = "error", str(exc)[:200]
    result.seconds = round(time.monotonic() - started, 1)
    return result
