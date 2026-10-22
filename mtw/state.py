"""Remember which domains were already reported, so each one is announced once."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path


class State:
    def __init__(self, path: Path):
        self.path = path
        self.hosts: dict[str, dict] = {}
        if path.exists():
            try:
                self.hosts = json.loads(path.read_text(encoding="utf-8")).get("hosts", {})
            except (json.JSONDecodeError, OSError):
                self.hosts = {}

    def is_new(self, host: str) -> bool:
        return host not in self.hosts

    def touch(self, host: str, day: date, score: int, severity: str) -> None:
        entry = self.hosts.get(host)
        if entry is None:
            self.hosts[host] = {"first_seen": day.isoformat(), "last_seen": day.isoformat(),
                                "score": score, "severity": severity}
        else:
            entry["last_seen"] = day.isoformat()
            if score > entry.get("score", 0):
                entry["score"], entry["severity"] = score, severity

    def prune(self, today: date, retention_days: int) -> int:
        cutoff = (today - timedelta(days=retention_days)).isoformat()
        old = [h for h, e in self.hosts.items() if e.get("last_seen", "") < cutoff]
        for h in old:
            del self.hosts[h]
        return len(old)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"hosts": dict(sorted(self.hosts.items()))}
        self.path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
