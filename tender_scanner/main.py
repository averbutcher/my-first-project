"""Entry point for the daily tender scanner."""

import asyncio
import json
import logging
import os
import sys
from datetime import date
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from analyzer import analyze_tender
from emailer import send_digest
from scraper import fetch_tender_list, fetch_tender_detail
from state import load_seen, save_seen, filter_new

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "logs" / f"scan_{date.today().isoformat()}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


def load_settings() -> dict:
    path = BASE_DIR / "settings.json"
    return json.loads(path.read_text(encoding="utf-8"))


async def run() -> None:
    load_dotenv(BASE_DIR / ".env")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gmail_password = os.environ.get("GMAIL_APP_PASSWORD", "")

    if not api_key:
        log.error("ANTHROPIC_API_KEY not set. Add it to tender_scanner/.env")
        sys.exit(1)
    if not gmail_password:
        log.error("GMAIL_APP_PASSWORD not set. Add it to tender_scanner/.env")
        sys.exit(1)

    settings = load_settings()
    client = anthropic.Anthropic(api_key=api_key)

    log.info("=== Tender Scanner starting ===")

    # 1. Fetch listing
    log.info("Fetching tender list from mr.gov.il...")
    all_tenders = await fetch_tender_list(settings)
    log.info(f"Found {len(all_tenders)} tenders on site.")

    # 2. Filter to new ones
    seen = load_seen()
    new_tenders = filter_new(all_tenders, seen)
    log.info(f"{len(new_tenders)} new (unseen) tenders to process.")

    if not new_tenders:
        log.info("Nothing new today. Exiting.")
        return

    # 3. Fetch details + PDF for each new tender
    analyses = []
    for i, meta in enumerate(new_tenders, 1):
        log.info(f"[{i}/{len(new_tenders)}] Processing: {meta['title'][:80]}")
        tender = await fetch_tender_detail(meta, settings)
        tender.raw_metadata["publish_date"] = meta.get("publish_date", "")
        tender.raw_metadata["update_date"] = meta.get("update_date", "")

        log.info(f"  PDF text length: {len(tender.pdf_text)} chars")
        analysis = analyze_tender(tender, settings, client)
        analyses.append(analysis)
        # Mark as seen immediately so a crash mid-run doesn't reprocess
        seen.add(meta["tender_id"])
        save_seen(seen)

    # 4. Send digest email
    log.info(f"Sending digest email with {len(analyses)} analyses...")
    send_digest(analyses, settings, gmail_password)

    log.info("=== Done ===")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
