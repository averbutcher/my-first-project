"""Persistent state: track which tenders have already been processed."""

import json
from pathlib import Path


def load_seen(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return set()


def save_seen(seen: set[str], path: Path) -> None:
    path.write_text(
        json.dumps(sorted(seen), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def filter_new(tender_metas: list[dict], seen: set[str]) -> list[dict]:
    return [t for t in tender_metas if t["tender_id"] not in seen]
