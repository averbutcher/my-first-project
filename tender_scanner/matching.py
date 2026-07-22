"""Single source of truth for matching free text to workers and branches.

Every part of the app that has to answer "who is this?" or "which branch is
this?" goes through here: WhatsApp message lines, clock2go Excel rows, saved
shift rows, the sales/arnakot reports and the salary report. Keeping one
implementation means the comparison and the reports can never disagree about
who a line belongs to.

Identity rule: the **workers table is the authority**. Message text and Excel
text are each resolved to a worker from that table, and only then compared to
each other — so a person is the same person regardless of how any one source
spells their name.
"""

import re

# Invisible bidi/format characters, common in WhatsApp copy-paste text
_INVISIBLE_CHARS_RE = re.compile(
    "[​‌‍‎‏‪‫‬‭‮⁠﻿]"
)


def normalize_match_text(s: str) -> str:
    """Normalize free text for comparison: strip invisible characters and
    collapse whitespace, so visually identical strings compare equal."""
    if not s:
        return ""
    s = _INVISIBLE_CHARS_RE.sub("", str(s))
    return re.sub(r"\s+", " ", s).strip()


def name_words(name: str) -> frozenset:
    """The set of words in a name — order-independent, so "אוחנה אביחי" and
    "אביחי אוחנה" compare equal."""
    return frozenset(w for w in normalize_match_text(name).split(" ") if w)


class NameMatcher:
    """Resolves free-text names to one of a fixed set of canonical names.

    Priority:
      1. alias / nickname (exact)
      2. canonical name (exact)
      3. word-set containment — every word of the shorter name appears in the
         longer one. This covers middle names ("אביחי אוחנה" →
         "אביחי אלירן אוחנה") and reversed order ("אוחנה אביחי אלירן").

    A tie between two or more candidates never guesses: it returns None so the
    caller can flag the line for a human instead of silently picking the wrong
    person.
    """

    def __init__(self, names, aliases: dict = None):
        self._canonical: set = set()
        self._words: list = []          # [(canonical, word_set)]
        for n in names or []:
            canon = normalize_match_text(n)
            if not canon or canon in self._canonical:
                continue
            self._canonical.add(canon)
            self._words.append((canon, name_words(canon)))

        # A nickname only counts if it points at a name we actually know
        self._aliases: dict = {}
        for nick, full in (aliases or {}).items():
            nick_n = normalize_match_text(nick)
            full_n = normalize_match_text(full)
            if nick_n and full_n and full_n in self._canonical and nick_n != full_n:
                self._aliases[nick_n] = full_n

    def resolve(self, name: str):
        """Canonical name, or None when unknown/ambiguous."""
        key = normalize_match_text(name)
        if not key:
            return None
        if key in self._aliases:
            return self._aliases[key]
        if key in self._canonical:
            return key
        words = name_words(key)
        if not words:
            return None
        hits = [canon for canon, wset in self._words if words <= wset or wset <= words]
        return hits[0] if len(hits) == 1 else None

    def resolve_or_blank(self, name: str) -> str:
        return self.resolve(name) or ""


class BranchMatcher:
    """Resolves workplace text to a canonical "number - name" branch label,
    using each branch's own name plus any configured nicknames."""

    def __init__(self, branches=None):
        self._map: dict = {}
        for b in branches or []:
            label = self.normalize_label(
                f"{(b.get('number') or '').strip()} - {(b.get('name') or '').strip()}"
            )
            if not label:
                continue
            nicks = [n for n in (b.get("nicknames") or []) if str(n).strip()]
            nicks.append(b.get("name") or "")
            for nick in nicks:
                key = normalize_match_text(nick)
                if key:
                    self._map[key] = label

    @staticmethod
    def normalize_label(text: str) -> str:
        """Canonicalize a "number - name" label so dash spacing, extra
        whitespace and leading zeros don't break matching."""
        text = normalize_match_text(text)
        if not text:
            return ""
        if "-" in text:
            num_part, _, name_part = text.partition("-")
        else:
            num_part, name_part = "", text
        num_part = num_part.strip().lstrip("0") or ("0" if num_part.strip() else "")
        name_part = " ".join(name_part.strip().split())
        return f"{num_part} - {name_part}".strip(" -")

    def resolve(self, text: str) -> str:
        """Canonical branch label, or "" when unrecognized."""
        return self._map.get(normalize_match_text(text), "")

    def as_dict(self) -> dict:
        return dict(self._map)


def build_worker_matcher(workers, extra_aliases: dict = None) -> NameMatcher:
    """NameMatcher over the workers table, using each worker's nickname as an
    alias (plus any aliases configured in the shift-comparison settings)."""
    names = [w.get("full_name", "") for w in workers or [] if w.get("full_name")]
    aliases = dict(extra_aliases or {})
    for w in workers or []:
        nick, full = w.get("nickname"), w.get("full_name")
        if nick and full:
            aliases[nick] = full
    return NameMatcher(names, aliases)
