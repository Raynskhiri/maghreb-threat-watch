"""Score a domain against the brand list.

The score (0 to 100) is the sum of one base match and some context bonuses.
Every point added is recorded as a human readable reason, so an analyst can
see exactly why a domain was flagged.

Base match (best one wins):
  exact      a token is exactly the brand keyword          biat-login.xyz
  contains   long keyword inside a token                   myattijaribank.com
  affix      keyword glued to known affixes/lure words     biat24, mybiat, biatsecure
  homoglyph  match only after undoing look-alike letters   biаt (Cyrillic a)
  leet       match only after undoing digit swaps          b1at, amenb4nk
  typo       one or two edits away from a long keyword     attijarlbank
  weak       short generic keyword as a whole token        stb-verif.com

Context bonuses: lure words, country hints, abused TLDs, free hosting,
punycode, the official domain embedded in a fake host.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from .config import Brand, Settings
from .domains import ParsedDomain, is_same_or_subdomain, parse
from .normalize import compact, fold, skeletons

BASE_POINTS = {
    "exact": 50,
    "contains": 48,
    "affix": 45,
    "homoglyph": 50,
    "leet": 48,
    "typo": 38,
    "weak": 25,
    "weak-affix": 22,
}
DECEPTION_BONUS = 15
EMBEDDED_OFFICIAL_BONUS = 20
LURE_FIRST, LURE_EXTRA, LURE_CAP = 15, 5, 25
HINT_BONUS = 10
TLD_BONUS = 10
HOSTING_BONUS = 10
IDN_BONUS = 5

_SPLIT_RE = re.compile(r"[.\-_~]+")


@dataclass
class Finding:
    host: str
    unicode_host: str
    registrable: str
    brand_id: str
    brand_name: str
    country: str
    sector: str
    keyword: str
    match_type: str
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def damerau(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance with an early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if row_min > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


CONTAINS_MIN_LEN = 8      # shorter keywords must sit on a word boundary
TYPO_MIN_LEN = 7          # shorter keywords are too close to everyday words
TYPO_WINDOW_MIN_LEN = 8   # typo hidden inside a longer glued token


def _typo_limit(keyword: str) -> int:
    if len(keyword) >= 13:
        return 2
    if len(keyword) >= TYPO_MIN_LEN:
        return 1
    return 0


class Matcher:
    def __init__(self, brands: list[Brand], settings: Settings, allowlist: set[str] | None = None):
        self.brands = brands
        self.settings = settings
        self.allow = set(allowlist or set())
        for b in brands:
            self.allow.update(b.official_domains)
        self.all_hints = set().union(*settings.country_hints.values()) if settings.country_hints else set()
        self.glue_words = settings.affixes | settings.lure_words | self.all_hints

    # ------------------------------------------------------------------ helpers
    def is_allowed(self, host: str) -> bool:
        return any(is_same_or_subdomain(host, d) for d in self.allow)

    @lru_cache(maxsize=8192)
    def segment(self, rest: str) -> tuple[str, ...] | None:
        """Split `rest` into glue words or digit runs. None if impossible.

        Prefers the fewest pieces, so "securelogin" -> ("secure", "login").
        """
        if not rest:
            return ()
        if len(rest) > 32:
            return None
        best: list[tuple[str, ...] | None] = [None] * (len(rest) + 1)
        best[0] = ()
        for i in range(1, len(rest) + 1):
            for j in range(max(0, i - 16), i):
                prev = best[j]
                if prev is None:
                    continue
                piece = rest[j:i]
                if piece in self.glue_words or piece.isdigit():
                    cand = prev + (piece,)
                    if best[i] is None or len(cand) < len(best[i]):
                        best[i] = cand
        return best[-1]

    def _segmentable(self, rest: str) -> bool:
        return self.segment(rest) is not None

    def _affix_match(self, token: str, kw: str) -> bool:
        if token.startswith(kw) and self._segmentable(token[len(kw):]):
            return True
        if token.endswith(kw) and self._segmentable(token[: -len(kw)]):
            return True
        if kw in token:
            i = token.index(kw)
            return self._segmentable(token[:i]) and self._segmentable(token[i + len(kw):])
        return False

    # ------------------------------------------------------------ base matching
    def _match_strong(self, kw: str, brand: Brand, tokens: list[str], variants: dict[str, set[str]]) -> tuple[str, str] | None:
        """Return (match_type, evidence) for a strong keyword, or None."""
        long_kw = len(kw) >= CONTAINS_MIN_LEN
        # Plain (as typed) checks first.
        for t in tokens:
            if t == kw:
                return "exact", t
        for t in tokens:
            if long_kw and kw in t:
                return "contains", t
            if self._affix_match(t, kw):
                return "affix", t
        # Deceptive spellings.
        for t in tokens:
            for v in variants[t]:
                if v == t:
                    continue
                if v == kw or (long_kw and kw in v) or self._affix_match(v, kw):
                    kind = "homoglyph" if not t.isascii() else "leet"
                    return kind, t
        # Typos. Skipped for compound keywords built from a country code or a
        # short brand code ("postetn", "stbnet"): a typo there is just a
        # different word.
        limit = _typo_limit(kw)
        if kw.endswith(("tn", "ma", "dz")) or any(kw.startswith(w) for w in brand.weak_keywords):
            limit = 0
        if limit:
            for t in tokens:
                for v in variants[t] | {t}:
                    if v == kw or v in self.settings.typo_ignore:
                        continue
                    if damerau(v, kw, limit) <= limit:
                        return "typo", t
                    if len(kw) >= TYPO_WINDOW_MIN_LEN and len(kw) + 1 < len(v) <= 40:
                        for size in (len(kw) - 1, len(kw), len(kw) + 1):
                            for s in range(0, len(v) - size + 1):
                                window = v[s:s + size]
                                if window in self.settings.typo_ignore:
                                    continue
                                if window[0] != kw[0] or window[-1] != kw[-1]:
                                    continue
                                if damerau(window, kw, limit) <= limit:
                                    rest_ok = self._segmentable(v[:s]) and self._segmentable(v[s + size:])
                                    if rest_ok:
                                        return "typo", t
        return None

    def _match_weak(self, kw: str, tokens: list[str], variants: dict[str, set[str]]) -> tuple[str, str] | None:
        for t in tokens:
            if t == kw or kw in variants[t]:
                return "weak", t
        for t in tokens:
            if t.startswith(kw) and self._segmentable(t[len(kw):]) and t[len(kw):]:
                return "weak-affix", t
        return None

    # ---------------------------------------------------------------- scoring
    def _context(self, brand: Brand, pd: ParsedDomain, tokens: list[str], evidence: str, kw: str) -> tuple[int, list[str]]:
        bonus = 0
        reasons: list[str] = []
        s = self.settings

        # Words glued to the brand inside the same token ("biatsecurelogin").
        glued: set[str] = set()
        ev = fold(evidence)
        if kw in ev:
            for part in ev.split(kw):
                glued.update(self.segment(part) or ())
        words = set(tokens) | glued

        # Lure words: whole tokens, glued words, or long lure words anywhere.
        lures = words & s.lure_words
        leftover = ev.replace(kw, " ")
        for word in s.lure_words:
            if len(word) >= 5 and word in leftover:
                lures.add(word)
        if lures:
            pts = min(LURE_CAP, LURE_FIRST + LURE_EXTRA * (len(lures) - 1))
            bonus += pts
            reasons.append(f"lure words {sorted(lures)} (+{pts})")

        # Country hint in tokens or in the suffix (e.g. a fake .com.tn).
        hint_pool = words | set(pd.suffix.split("."))
        countries = [c.strip() for c in brand.country.split(",")]
        hints = set()
        for c in countries:
            hints |= hint_pool & s.country_hints.get(c, set())
        # "postetn" already carries the "tn": do not count it twice.
        hints = {h for h in hints if not kw.endswith(h)}
        if hints:
            bonus += HINT_BONUS
            reasons.append(f"country hint {sorted(hints)} (+{HINT_BONUS})")

        tld = pd.suffix.rsplit(".", 1)[-1]
        if tld in s.suspicious_tlds and not pd.on_hosting:
            bonus += TLD_BONUS
            reasons.append(f"abused TLD .{tld} (+{TLD_BONUS})")

        if pd.on_hosting:
            bonus += HOSTING_BONUS
            reasons.append(f"free hosting {pd.suffix} (+{HOSTING_BONUS})")

        if pd.is_idn:
            bonus += IDN_BONUS
            reasons.append(f"punycode domain (+{IDN_BONUS})")

        # The real domain pasted inside a fake one: biat.com.tn.verify.xyz,
        # biat-com-tn.top. For two-label domains (poste.tn) only the literal
        # dotted form counts, otherwise it would just repeat the keyword match.
        host_fold = fold(pd.unicode_host)
        host_compact = compact(host_fold)
        for official in brand.official_domains:
            literal = official in host_fold
            long_compact = official.count(".") >= 2 and compact(official) in host_compact
            if literal or long_compact:
                bonus += EMBEDDED_OFFICIAL_BONUS
                reasons.append(f"embeds official domain {official} (+{EMBEDDED_OFFICIAL_BONUS})")
                break

        return bonus, reasons

    def severity(self, score: int) -> str | None:
        t = self.settings.thresholds
        if score >= t.get("high", 70):
            return "high"
        if score >= t.get("medium", 45):
            return "medium"
        if score >= t.get("low", 30):
            return "low"
        return None

    def evaluate(self, value: str, keep_below_threshold: bool = False) -> Finding | None:
        pd = parse(value)
        if pd is None or self.is_allowed(pd.host):
            return None

        label_text = f"{pd.subdomain}.{pd.name}" if pd.subdomain else pd.name
        tokens = [t for t in _SPLIT_RE.split(label_text.lower()) if t]
        if not tokens:
            return None
        # Also look at the name, and the whole host label part, with separators
        # removed: "b-i-a-t" -> "biat", "poste.tn.colis" -> "postetncolis".
        for joined in (compact(pd.name.lower()), compact(label_text.lower())):
            if joined not in tokens:
                tokens.append(joined)
        variants = {t: skeletons(t) for t in tokens}

        best: Finding | None = None
        for brand in self.brands:
            candidates = []
            for kw in brand.keywords:
                m = self._match_strong(kw, brand, tokens, variants)
                if m:
                    candidates.append((m[0], m[1], kw))
            if not candidates:
                for kw in brand.weak_keywords:
                    m = self._match_weak(kw, tokens, variants)
                    if m:
                        candidates.append((m[0], m[1], kw))
            if not candidates:
                continue
            # Highest base points, then the longest (most specific) keyword.
            match_type, evidence, kw = max(candidates, key=lambda c: (BASE_POINTS[c[0]], len(c[2])))

            base = BASE_POINTS[match_type]
            reasons = [f"{match_type} match on '{kw}' in '{evidence}' (+{base})"]
            score = base
            if match_type in ("homoglyph", "leet"):
                score += DECEPTION_BONUS
                reasons.append(f"deceptive spelling (+{DECEPTION_BONUS})")
            bonus, extra = self._context(brand, pd, tokens, evidence, kw)
            score = min(100, score + bonus)
            reasons += extra
            # A short code like "steg" or "cmi" is only interesting next to a
            # lure word, a country hint or the real domain.
            if match_type.startswith("weak") and not any(
                    r.startswith(("lure", "country hint", "embeds")) for r in extra):
                score = min(score, self.settings.thresholds.get("low", 30) - 1)
                reasons.append("short brand code without lure or country context (capped)")

            sev = self.severity(score)
            if sev is None and not keep_below_threshold:
                continue
            finding = Finding(
                host=pd.host,
                unicode_host=pd.unicode_host,
                registrable=pd.registrable,
                brand_id=brand.id,
                brand_name=brand.name,
                country=brand.country,
                sector=brand.sector,
                keyword=kw,
                match_type=match_type,
                score=score,
                severity=sev or "none",
                reasons=reasons,
            )
            if best is None or (finding.score, len(kw)) > (best.score, len(best.keyword)):
                best = finding
        return best
