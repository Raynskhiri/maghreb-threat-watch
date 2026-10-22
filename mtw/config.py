"""Load brands and settings from YAML."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .normalize import compact, fold

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_DIR = ROOT / "config"


@dataclass
class Brand:
    id: str
    name: str
    country: str
    sector: str
    keywords: list[str] = field(default_factory=list)
    weak_keywords: list[str] = field(default_factory=list)
    official_domains: list[str] = field(default_factory=list)


@dataclass
class Settings:
    thresholds: dict
    alert_severity: str
    lookback_days: int
    state_retention_days: int
    sources: dict
    lure_words: set[str]
    country_hints: dict[str, set[str]]
    affixes: set[str]
    suspicious_tlds: set[str]
    typo_ignore: set[str] = field(default_factory=set)


def _norm_kw(word: str) -> str:
    return compact(fold(str(word)))


def load_brands(path: Path | None = None) -> list[Brand]:
    path = path or DEFAULT_CONFIG_DIR / "brands.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    brands = []
    seen = set()
    for raw in data.get("brands", []):
        brand = Brand(
            id=raw["id"],
            name=raw["name"],
            country=str(raw.get("country", "")).upper().replace(" ", ""),
            sector=raw.get("sector", ""),
            keywords=[_norm_kw(k) for k in raw.get("keywords", []) or []],
            weak_keywords=[_norm_kw(k) for k in raw.get("weak_keywords", []) or []],
            official_domains=[d.lower().strip(".") for d in raw.get("official_domains", []) or []],
        )
        if brand.id in seen:
            raise ValueError(f"duplicate brand id: {brand.id}")
        if not brand.keywords and not brand.weak_keywords:
            raise ValueError(f"brand {brand.id} has no keywords")
        seen.add(brand.id)
        brands.append(brand)
    return brands


def load_settings(path: Path | None = None) -> Settings:
    path = path or DEFAULT_CONFIG_DIR / "settings.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Settings(
        thresholds=data.get("thresholds", {"high": 70, "medium": 45, "low": 30}),
        alert_severity=data.get("alert_severity", "high"),
        lookback_days=int(data.get("lookback_days", 3)),
        state_retention_days=int(data.get("state_retention_days", 120)),
        sources=data.get("sources", {}),
        lure_words={_norm_kw(w) for w in data.get("lure_words", [])},
        country_hints={k.upper(): {_norm_kw(w) for w in v} for k, v in data.get("country_hints", {}).items()},
        affixes={_norm_kw(w) for w in data.get("affixes", [])},
        suspicious_tlds={str(t).lower().lstrip(".") for t in data.get("suspicious_tlds", [])},
        typo_ignore={_norm_kw(w) for w in data.get("typo_ignore", [])},
    )


def load_allowlist(path: Path | None = None) -> set[str]:
    path = path or DEFAULT_CONFIG_DIR / "allowlist.txt"
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower().strip(".")
        if line:
            out.add(line)
    return out
