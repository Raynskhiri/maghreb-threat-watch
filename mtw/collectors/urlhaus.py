"""URLhaus (abuse.ch): recent malware distribution URLs.

abuse.ch requires a free Auth-Key. Put it in the URLHAUS_AUTH_KEY environment
variable (a GitHub Actions secret). Without it this source is skipped.
"""

from __future__ import annotations

import os
import time

from .base import Observation, SourceResult, get, session

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"


def collect_urlhaus(*_, **__) -> SourceResult:
    started = time.monotonic()
    result = SourceResult("urlhaus")
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        result.status, result.detail = "skipped", "URLHAUS_AUTH_KEY not set"
        return result
    try:
        resp = get(session(), API_URL, timeout=60, headers={"Auth-Key": key})
        data = resp.json()
        for row in data.get("urls", []) or []:
            url = row.get("url")
            if url:
                result.observations.append(Observation(
                    value=url, source="urlhaus", url=url,
                    extra={"threat": row.get("threat"), "tags": row.get("tags") or []},
                ))
    except Exception as exc:  # noqa: BLE001
        result.status, result.detail = "error", str(exc)[:200]
    result.seconds = round(time.monotonic() - started, 1)
    return result
