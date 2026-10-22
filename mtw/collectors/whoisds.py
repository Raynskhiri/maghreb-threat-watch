"""WhoisDS free daily list of newly registered domains.

Covers generic TLDs (.com, .xyz, .online and friends), not ccTLDs like .tn.
Fresh registrations are where most phishing domains start their life.
"""

from __future__ import annotations

import base64
import io
import time
import zipfile
from datetime import date, timedelta

from .base import Observation, SourceResult, get, session

URL_TEMPLATE = "https://www.whoisds.com/whois-database/newly-registered-domains/{token}/nrd"


def _token(day: date) -> str:
    return base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()


def collect_whoisds(*_, day: date | None = None, **__) -> SourceResult:
    started = time.monotonic()
    result = SourceResult("whoisds")
    day = day or (date.today() - timedelta(days=1))
    try:
        resp = get(session(), URL_TEMPLATE.format(token=_token(day)), timeout=120)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                if not name.endswith(".txt"):
                    continue
                for line in zf.read(name).decode("utf-8", "ignore").splitlines():
                    line = line.strip()
                    if line:
                        result.observations.append(Observation(value=line, source="whoisds",
                                                               extra={"registered": day.isoformat()}))
        result.detail = f"newly registered on {day.isoformat()}"
    except zipfile.BadZipFile:
        result.status, result.detail = "error", f"no list published for {day.isoformat()} yet"
    except Exception as exc:  # noqa: BLE001
        result.status, result.detail = "error", str(exc)[:200]
    result.seconds = round(time.monotonic() - started, 1)
    return result
