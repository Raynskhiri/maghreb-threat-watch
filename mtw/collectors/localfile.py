"""Read domains or URLs from a local text file, one per line.

Useful for your own data: a DNS log export, a zone file extract, a list a
colleague shared. Lines starting with # are ignored.
"""

from __future__ import annotations

import time
from pathlib import Path

from .base import Observation, SourceResult


def collect_file(path: str | Path, source_name: str | None = None) -> SourceResult:
    started = time.monotonic()
    path = Path(path)
    result = SourceResult(source_name or path.name)
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                url = line if "://" in line else None
                result.observations.append(Observation(value=line, source=result.name, url=url))
    except OSError as exc:
        result.status, result.detail = "error", str(exc)
    result.seconds = round(time.monotonic() - started, 1)
    return result
