"""Playwright scraper for mr.gov.il tender listings and PDF extraction."""

import re
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

from pypdf import PdfReader
from playwright.async_api import async_playwright, Page, TimeoutError as PWTimeout

BASE = "https://mr.gov.il"


@dataclass
class Tender:
    tender_id: str
    title: str
    url: str
    publisher: str = ""
    deadline: str = ""
    pdf_text: str = ""
    raw_metadata: dict = field(default_factory=dict)


async def _safe_text(page: Page, selector: str, default: str = "") -> str:
    try:
        el = await page.query_selector(selector)
        return (await el.inner_text()).strip() if el else default
    except Exception:
        return default


async def fetch_tender_list(settings: dict) -> list[dict]:
    """Return list of {tender_id, title, url} dicts from the search results page."""
    base_url: str = settings["scraper"]["base_url"]
    timeout: int = settings["scraper"]["page_load_timeout_ms"]
    max_tenders: int = settings["scraper"]["max_tenders_per_run"]
    days_back: int = settings["scraper"].get("days_back", 7)
    cutoff: date = date.today() - timedelta(days=days_back)

    results: list[dict] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            locale="he-IL",
            extra_http_headers={"Accept-Language": "he-IL,he;q=0.9"},
        )
        page = await context.new_page()

        await page.goto(base_url, timeout=timeout, wait_until="domcontentloaded")

        # Wait for tender cards to appear
        try:
            await page.wait_for_selector("div.result-container", timeout=15000)
        except PWTimeout:
            await browser.close()
            return results

        # Keep clicking "הצג עוד" until the oldest update date on the page is past the cutoff
        # Safety limit: ceil(max_tenders / 20) clicks, since each click loads ~20 tenders
        max_clicks = max(15, (max_tenders // 20) + 1)
        for _ in range(max_clicks):
            btn = await page.query_selector("button.show-more-button")
            if not btn:
                break
            all_update_dates = await _extract_update_dates(page)
            if all_update_dates and min(all_update_dates) < cutoff:
                break
            try:
                await btn.click()
                await page.wait_for_timeout(2000)
            except Exception:
                break

        # Extract all visible tender cards, filtered by update date
        items = await page.query_selector_all("div.result-container")
        for item in items:
            if len(results) >= max_tenders:
                break
            try:
                link_el = await item.query_selector("a[href*='/p/']")
                if not link_el:
                    continue
                href = await link_el.get_attribute("href") or ""
                if not href.startswith("http"):
                    href = BASE + href

                update_date = await _card_update_date(item)
                if update_date and update_date < cutoff:
                    continue

                # Skip tenders whose submission deadline has passed
                if await _card_is_expired(item):
                    continue

                pub_date = await _card_publish_date(item)
                title_el = await item.query_selector("h2.search-results-content-head")
                title = (await title_el.inner_text()).strip() if title_el else (await link_el.inner_text()).strip()
                tender_id = _extract_id_from_url(href)
                if tender_id and href:
                    results.append({
                        "tender_id": tender_id,
                        "title": title,
                        "url": href,
                        "publish_date": pub_date.strftime("%d/%m/%Y") if pub_date else "",
                        "update_date": update_date.strftime("%d/%m/%Y") if update_date else "",
                    })
            except Exception:
                continue

        await browser.close()

    return results


async def _card_date_by_label(item, label: str) -> Optional[date]:
    """Find a date span that follows a label span containing the given Hebrew text."""
    try:
        # Use JS to find the label span and read the next sibling's text
        text = await item.evaluate(f"""el => {{
            const spans = el.querySelectorAll('span');
            for (let i = 0; i < spans.length - 1; i++) {{
                if (spans[i].textContent.includes('{label}')) {{
                    return spans[i + 1].textContent.trim();
                }}
            }}
            return '';
        }}""")
        return _parse_il_date(text)
    except Exception:
        return None


async def _card_is_expired(item) -> bool:
    """Return True if the tender card shows חלף מועד ההגשה (deadline passed)."""
    try:
        text = await item.evaluate("el => el.textContent")
        return "חלף מועד ההגשה" in text
    except Exception:
        return False


async def _card_update_date(item) -> Optional[date]:
    return await _card_date_by_label(item, "תאריך עדכון")


async def _card_publish_date(item) -> Optional[date]:
    return await _card_date_by_label(item, "תאריך פרסום")


async def _extract_update_dates(page: Page) -> list[date]:
    """Get all visible update dates on the page for cutoff checking."""
    dates = []
    items = await page.query_selector_all("div.result-container")
    for item in items:
        d = await _card_update_date(item)
        if d:
            dates.append(d)
    return dates


def _parse_il_date(text: str) -> Optional[date]:
    """Parse DD/MM/YYYY date string."""
    m = re.match(r"(\d{2})/(\d{2})/(\d{4})", text)
    if m:
        try:
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            pass
    return None


async def fetch_tender_detail(tender_meta: dict, settings: dict) -> Tender:
    """Open the tender page, download the PDF and extract its text."""
    timeout: int = settings["scraper"]["page_load_timeout_ms"]
    tender = Tender(
        tender_id=tender_meta["tender_id"],
        title=tender_meta["title"],
        url=tender_meta["url"],
    )

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            locale="he-IL",
            extra_http_headers={"Accept-Language": "he-IL,he;q=0.9"},
            accept_downloads=True,
        )
        page = await context.new_page()

        try:
            await page.goto(tender.url, timeout=timeout, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
        except PWTimeout:
            await browser.close()
            return tender

        # Extract title from page when we only have a URL as the title
        if not tender.title or tender.title.startswith("http"):
            try:
                # Try the HTML <title> tag first (always available, no JS needed)
                doc_title = await page.title()
                # mr.gov.il format: "כותרת המכרז | mr.gov.il" — take the part before the pipe
                if doc_title:
                    part = doc_title.split("|")[0].strip()
                    if part and len(part) > 10:
                        tender.title = part
            except Exception:
                pass

        if not tender.title or tender.title.startswith("http"):
            try:
                for selector in ["h1", "h2"]:
                    els = await page.query_selector_all(selector)
                    for el in els:
                        page_title = (await el.inner_text()).strip()
                        if page_title and len(page_title) > 10 and not page_title.startswith("http"):
                            tender.title = page_title
                            break
                    if tender.title and not tender.title.startswith("http"):
                        break
            except Exception:
                pass

        # Publisher: text after "שם המפרסם:"
        try:
            spans = await page.query_selector_all(".details-wrapper span.font-weight-normal")
            if spans:
                tender.publisher = (await spans[0].inner_text()).strip()
        except Exception:
            pass

        # Deadline: last .last-date number span
        try:
            deadline_els = await page.query_selector_all("span.number.last-date")
            if deadline_els:
                tender.deadline = (await deadline_els[-1].inner_text()).strip()
        except Exception:
            pass

        # Find the booklet PDF link (חוברת המכרז)
        pdf_url = await _find_booklet_pdf(page)
        if pdf_url:
            tender.pdf_text = await _download_and_extract_pdf(context, pdf_url, timeout)

        await browser.close()

    return tender


async def _find_booklet_pdf(page: Page) -> Optional[str]:
    """Find חוברת המכרז PDF link on the page."""
    for selector in [
        "a:has-text('חוברת המכרז')",
        "a:has-text('חוברת')",
        "a[href$='.pdf']",
        "a[href*='pdf']",
        "a[href*='PDF']",
    ]:
        try:
            el = await page.query_selector(selector)
            if el:
                href = await el.get_attribute("href") or ""
                if href:
                    return href if href.startswith("http") else BASE + href
        except Exception:
            continue
    return None


async def _download_and_extract_pdf(context, pdf_url: str, timeout: int) -> str:
    """Download a PDF and extract its text."""
    page = await context.new_page()
    try:
        # Try direct HTTP fetch first (faster than waiting for download event)
        response = await context.request.get(pdf_url, timeout=timeout)
        body = await response.body()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        return _extract_pdf_text(tmp_path)
    except Exception:
        try:
            async with page.expect_download(timeout=timeout) as dl_info:
                await page.goto(pdf_url, timeout=timeout)
            download = await dl_info.value
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                await download.save_as(tmp.name)
                tmp_path = tmp.name
            return _extract_pdf_text(tmp_path)
        except Exception:
            return ""
    finally:
        await page.close()


def _extract_pdf_text(path: str) -> str:
    try:
        reader = PdfReader(path)
        pages = [page.extract_text() or "" for page in reader.pages]
        Path(path).unlink(missing_ok=True)
        return "\n".join(pages)[:50000]
    except Exception:
        return ""


def _extract_id_from_url(url: str) -> str:
    m = re.search(r"/p/([A-Za-z0-9_\-]+)", url)
    if m:
        return m.group(1)
    m = re.search(r"tenderId=([A-Za-z0-9_\-]+)", url)
    if m:
        return m.group(1)
    return str(abs(hash(url)))
