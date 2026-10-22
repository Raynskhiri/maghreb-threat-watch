"""Data sources. Each collector returns observations and never raises:
one broken feed must not stop the daily run."""

from .base import Observation, SourceResult
from .crtsh import collect_crtsh
from .localfile import collect_file
from .openphish import collect_openphish
from .urlhaus import collect_urlhaus
from .whoisds import collect_whoisds

COLLECTORS = {
    "crtsh": collect_crtsh,
    "openphish": collect_openphish,
    "whoisds": collect_whoisds,
    "urlhaus": collect_urlhaus,
}

__all__ = [
    "COLLECTORS",
    "Observation",
    "SourceResult",
    "collect_crtsh",
    "collect_file",
    "collect_openphish",
    "collect_urlhaus",
    "collect_whoisds",
]
