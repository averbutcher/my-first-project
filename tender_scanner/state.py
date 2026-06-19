"""Persistent state: track which tenders have already been processed."""

import json
from pathlib import Path

STATE_FILE = Path(__file__).parent / "seen_tenders.json"


def load_seen() -> set[str]:
    if not STATE_FILE.exists():
        return set()
    try:
        return set(json.loads(STATE_FILE.read_text(encoding="utf-8")))
    except Exception:
        return set()


def save_seen(seen: set[str]) -> None:
    STATE_FILE.write_text(
        json.dumps(sorted(seen), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def filter_new(tender_metas: list[dict], seen: set[str]) -> list[dict]:
    return [t for t in tender_metas if t["tender_id"] not in seen]
