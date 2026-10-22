"""Certificate Transparency via crt.sh.

Phishing sites almost always get a free TLS certificate, and every public
certificate is logged. Searching the logs for brand keywords often finds a
lookalike site before the first victim does.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from ..config import Brand
from .base import Observation, SourceResult, get, session

log = logging.getLogger(__name__)
CRTSH_URL = "https://crt.sh/"


def _keywords(brands: list[Brand]) -> list[str]:
    # Weak keywords ("stb", "bna") match millions of certificates and would
    # time out; they are covered by the other sources instead.
    out: list[str] = []
    for b in brands:
        for kw in b.keywords:
            if len(kw) >= 4 and kw not in out:
                out.append(kw)
    return out


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "")).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def collect_crtsh(brands: list[Brand], *, lookback_days: int = 3, timeout: int = 90,
                  pause_seconds: float = 4, **_: object) -> SourceResult:
    started = time.monotonic()
    result = SourceResult("crt.sh")
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    sess = session()
    failures = 0
    keywords = _keywords(brands)
    seen: set[str] = set()

    for i, kw in enumerate(keywords):
        if i:
            time.sleep(pause_seconds)
        try:
            resp = get(sess, CRTSH_URL, timeout=timeout, retries=1, accept=(404,),
                       params={"q": f"%{kw}%", "output": "json", "exclude": "expired", "deduplicate": "Y"})
            rows = resp.json() if resp.status_code == 200 and resp.text.strip() else []
        except Exception as exc:  # noqa: BLE001 (crt.sh fails often; keep going)
            failures += 1
            log.warning("crt.sh query for %r failed: %s", kw, exc)
            continue
        for row in rows:
            issued = _parse_time(row.get("entry_timestamp") or row.get("not_before") or "")
            if issued and issued < since:
                continue
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower()
                if not name or name in seen:
                    continue
                seen.add(name)
                result.observations.append(Observation(
                    value=name,
                    source="crt.sh",
                    extra={"crt_id": row.get("id"), "issuer": row.get("issuer_name", ""),
                           "not_before": row.get("not_before", "")},
                ))

    result.seconds = round(time.monotonic() - started, 1)
    if failures and failures == len(keywords):
        result.status, result.detail = "error", "all crt.sh queries failed"
    elif failures:
        result.detail = f"{failures}/{len(keywords)} keyword queries failed"
    return result
