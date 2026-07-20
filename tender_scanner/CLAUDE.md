# Electra Target Tools — Project Context

## What this is
Internal tooling platform for **Electra Target** company.
Live site: https://tender-scanner.up.railway.app/
Deployed on: Railway
Stack: Python, FastAPI (`server.py` = production), Streamlit (`app.py` = local dev), Playwright scraper, Claude API

## Key files
- `server.py` — FastAPI REST API, what Railway actually runs. SSE streaming for scan progress.
- `app.py` — Streamlit version of the same UI (for local testing)
- `analyzer.py` — All Claude API calls: `analyze_tender()`, `distill_knowledge()`
- `scraper.py` — Playwright scraper for mr.gov.il, `Tender` dataclass
- `engine.py` — Shift comparison logic: parse_message, parse_excel, compare, export_to_excel, find_suspicious_lines
- `state.py` — Tracks which tenders were already seen
- `emailer.py` — Gmail digest sender
- `users.yaml` — User credentials, roles, per-user app access
- `settings.json` — Tender scanner settings (days back, max tenders, budget range, labor costs)
- `data/shared/knowledge.json` — Learned guidelines from Learning Mode, injected into every Claude API call
- `static/index.html` — Frontend HTML served by FastAPI

## Tools built so far

### 1. סריקת מכרזים (Tender Scanner)
- Scrapes government tenders from mr.gov.il
- Downloads PDFs, sends to Claude (claude-sonnet-4-6) for relevance analysis
- Rates each tender: High / Medium / Low (גבוהה / בינונית / נמוכה)
- Tabs: scan, manual URL, history, favorites, learning (admin only), settings
- Per-user data stored in `data/users/{username}/`

### 2. השוואת משמרות (Shift Comparison)
- Paste a WhatsApp message with shift data + upload Excel file (or fetch it from Gmail)
- Compares them and flags: ✅ OK, ⚠️ gap, 🟠 missing in message, 🔴 missing in Excel
- Tabs: השוואה, שעות עובדים (saved shifts ledger), מכירות, עובדים, סניפים, דוח מלא (monthly+daily), דוח סניפים, חגים
- Every saved shift line stores two resolved links: `worker_key` (full name from the
  workers table; matched nickname → exact → unique first word, see
  `make_worker_resolver` in engine.py) and `branch_key` (canonical "number - name"
  label via branch nicknames). Links are recomputed on every save/edit/upload
  (`_enrich_shift_row` in server.py); manual dropdown picks survive when
  auto-resolution fails. "🔄 חשב מחדש" re-resolves all lines.
- All reports count hours by `worker_key`/`branch_key` (fallback: raw worker_name);
  hours with no branch link show as "לא משויך" in the branch report
- Per-user config in `data/users/{username}/shifts_config.json`

### 3. ניתוח מגייסים (Recruiter Analysis) — built
- Upload Excel file (same format as call log report, sheet name "פיד")
- Parses columns: calldate(A), src(C=extension), dst(D), billsec(K), disposition(L)
- Extension extracted from src: strips "910" prefix (e.g. 9100242 → 242)
- Two tabs: תצוגת מגייס (single recruiter) + מבט על (all recruiters comparison)
- Single view: 6 stat cards, hourly chart, calls/day chart, minutes/day chart, long calls table, repeat numbers table
- Overview: comparison table + 4 bar charts (total calls, answer %, total minutes, avg/day)
- Configurable: long call threshold (min), repeat threshold (count), default days back
- Recruiter name→extension mapping in sidebar settings
- Access controlled: only users with recruiter_analysis in their apps list; others see 🔒 button
- Data stored in data/shared/recruiter_data.json; config in data/shared/recruiter_config.json
- Charts are inline SVG (no external library)

## How Claude API is used
- Stateless — no persistent session on Claude's side
- Every tender analysis sends fresh: hardcoded company profile + knowledge.json + optional session feedback
- Company profile (in `analyzer.py` SYSTEM_PROMPT): Electra Target specializes in BPO, labor-intensive project management, logistics, health, transport, facility management, administration
- PDF text (up to 30,000 chars) sent per tender as user message

## Auth & users
- Cookie-based auth (itsdangerous + bcrypt)
- Users defined in `users.yaml` with role (admin/user) and allowed apps list
- Admin users get the Learning Mode tab in Tender Scanner

## Adding a new tool
Follow this pattern:
1. Add app ID and label to `APP_INFO` dict in `server.py` and `app.py`
2. Add the app's backend routes to `server.py`
3. Add the app's UI section to the frontend (`static/index.html` or `app.py`)
4. Add sidebar settings section if needed
5. Grant access to users in `users.yaml` under their `apps:` list
