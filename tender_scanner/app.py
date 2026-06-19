import asyncio
import concurrent.futures
import json
import os
import sys
from pathlib import Path

import anthropic
import streamlit as st
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

from analyzer import analyze_tender, distill_knowledge
from emailer import send_digest
from scraper import fetch_tender_list, fetch_tender_detail
from state import load_seen, save_seen, filter_new

BASE_DIR = Path(__file__).parent
SETTINGS_FILE = BASE_DIR / "settings.json"

load_dotenv(BASE_DIR / ".env")

st.set_page_config(page_title="Tender Scanner", page_icon="🔍", layout="wide", initial_sidebar_state="collapsed")

# ── Shared data (all users) ────────────────────────────────────────────────────
KNOWLEDGE_FILE = BASE_DIR / "data" / "shared" / "knowledge.json"
(BASE_DIR / "data" / "shared").mkdir(parents=True, exist_ok=True)

# ── Per-user data helpers ──────────────────────────────────────────────────────
def user_dir(username: str) -> Path:
    d = BASE_DIR / "data" / "users" / username
    d.mkdir(parents=True, exist_ok=True)
    return d

def history_file(username: str) -> Path:
    return user_dir(username) / "all_tenders.json"

def favorites_file(username: str) -> Path:
    return user_dir(username) / "favorites.json"

def last_scan_file(username: str) -> Path:
    return user_dir(username) / "last_scan.json"

def seen_file(username: str) -> Path:
    return user_dir(username) / "seen_tenders.json"


def load_settings():
    return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))


def save_settings_file(s):
    SETTINGS_FILE.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")


def save_last_scan(results: list, username: str):
    last_scan_file(username).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


def load_last_scan(username: str) -> list:
    f = last_scan_file(username)
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def load_history(username: str) -> list:
    try:
        f = history_file(username)
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def append_to_history(result: dict, username: str):
    history = load_history(username)
    existing_ids = {r["tender_id"] for r in history}
    if result["tender_id"] not in existing_ids:
        history.insert(0, result)
    else:
        history = [result if r["tender_id"] == result["tender_id"] else r for r in history]
    history_file(username).write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")


def load_knowledge() -> list:
    try:
        if KNOWLEDGE_FILE.exists():
            return json.loads(KNOWLEDGE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def save_knowledge(guidelines: list):
    KNOWLEDGE_FILE.write_text(json.dumps(guidelines, ensure_ascii=False, indent=2), encoding="utf-8")


def load_favorites(username: str) -> set:
    try:
        f = favorites_file(username)
        if f.exists():
            return set(json.loads(f.read_text(encoding="utf-8")))
    except Exception:
        pass
    return set()


def save_favorites(favs: set, username: str):
    favorites_file(username).write_text(json.dumps(list(favs), ensure_ascii=False), encoding="utf-8")


def parse_relevance(analysis: str) -> str:
    import re
    if analysis == "NO_PDF":
        return "no_pdf"
    if analysis.startswith("שגיאה") or analysis.startswith("NO_PDF"):
        return "unknown"
    # Look for the value AFTER a colon on the רלוונטיות line
    # e.g. "רלוונטיות ל-Electra Target (גבוהה / בינונית / נמוכה): גבוהה"
    match = re.search(r'רלוונטיות[^\n]*?:\s*\**(גבוהה|בינונית|נמוכה)', analysis)
    if match:
        word = match.group(1)
        return {"גבוהה": "high", "בינונית": "medium", "נמוכה": "low"}[word]
    # Fallback: recommendation line
    match = re.search(r'המלצה[^\n]*?:\s*\**(כן|שקול|לא)\b', analysis)
    if match:
        word = match.group(1)
        return {"כן": "high", "שקול": "medium", "לא": "low"}[word]
    # Last resort: find the word anywhere in the first 300 chars after the relevance header
    rel_idx = analysis.find("רלוונטיות")
    if rel_idx != -1:
        snippet = analysis[rel_idx:rel_idx + 300]
        for word, level in [("גבוהה", "high"), ("בינונית", "medium"), ("נמוכה", "low")]:
            # Skip the options list pattern "(גבוהה / בינונית / נמוכה)"
            cleaned = re.sub(r'\([^)]*\)', '', snippet)
            if word in cleaned:
                return level
    return "unknown"


def relevance_badge(r: str) -> str:
    return {"high": "🟢 רלוונטיות גבוהה", "medium": "🟡 רלוונטיות בינונית",
            "low": "🔴 רלוונטיות נמוכה", "unknown": "⚪ לא ידוע",
            "no_pdf": "⬛ ללא PDF"}[r]


def chat_with_claude(result: dict, history: list, client) -> str:
    system = f"""אתה יועץ עסקי שניתח מכרז עבור Electra Target.

פרטי המכרז:
- כותרת: {result['title']}
- מפרסם: {result.get('publisher', 'לא ידוע')}
- מועד הגשה: {result.get('deadline', 'לא צוין')}

הניתוח המקורי שלך:
{result['analysis']}

ענה על שאלות המשתמש בעברית בלבד. אם המשתמש מתקן אותך או נותן מידע חדש, הודה ועדכן את עמדתך. היה ממוקד ותמציתי."""

    messages = [{"role": m["role"], "content": m["content"]} for m in history]
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=system,
        messages=messages,
    )
    return response.content[0].text


def star_button(tender_id: str, prefix: str, username: str):
    is_fav = tender_id in st.session_state.favorites
    label = "⭐ מועדף" if is_fav else "☆ הוסף למועדפים"
    if st.button(label, key=f"fav_{prefix}_{tender_id}", use_container_width=True):
        if is_fav:
            st.session_state.favorites.discard(tender_id)
        else:
            st.session_state.favorites.add(tender_id)
        save_favorites(st.session_state.favorites, username)
        st.rerun()


def run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def run_async_with_timeout(coro, timeout: int = 90):
    """Run an async coroutine in a thread with a hard timeout that works even with Playwright."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"עיבוד המכרז נתקע ועבר {timeout} שניות — מדלג")


# ── Auth ──────────────────────────────────────────────────────────────────────
with open(BASE_DIR / "users.yaml", encoding="utf-8") as _f:
    _auth_config = yaml.load(_f, SafeLoader)

authenticator = stauth.Authenticate(
    _auth_config["credentials"],
    _auth_config["cookie"]["name"],
    _auth_config["cookie"]["key"],
    _auth_config["cookie"]["expiry_days"],
)

# ── Global RTL styles ─────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Base RTL for the whole app */
  .stApp, .stApp * { direction: rtl; }

  /* Text inputs & textareas */
  .stTextInput input,
  .stTextArea textarea,
  .stNumberInput input { direction: rtl; text-align: right; }

  /* Labels */
  label, .stTextInput label, .stTextArea label,
  .stNumberInput label, .stCheckbox label,
  .stSelectbox label { text-align: right; display: block; }

  /* Markdown blocks */
  .stMarkdown, .stMarkdown p { text-align: right; }

  /* Alerts / info / warning / success */
  .stAlert, .stAlert p { text-align: right; }

  /* Expander headers */
  .stExpander summary { direction: rtl; text-align: right; }

  /* Status widget */
  [data-testid="stStatusWidget"] { direction: rtl; }

  /* Column containers — keep natural flow but RTL */
  [data-testid="column"] { direction: rtl; }

  /* Tabs — align to the right */
  [data-testid="stTabs"] [role="tablist"],
  [data-baseweb="tab-list"],
  .stTabs [role="tablist"] {
    direction: rtl !important;
    justify-content: flex-start !important;
  }

  /* Sidebar */
  [data-testid="stSidebar"] { direction: rtl; }

  /* Form submit buttons */
  .stFormSubmitButton button { width: 100%; }

  /* Spinner text */
  .stSpinner p { text-align: right; }
</style>
""", unsafe_allow_html=True)

# ── Login ─────────────────────────────────────────────────────────────────────
authenticator.login()

if not st.session_state.get("authentication_status"):
    st.markdown("""
    <div style="direction:rtl; text-align:center; margin-top:80px;">
      <h1>🔍 Tender Scanner — Electra Target</h1>
      <p style="color:#666;">אנא התחבר כדי להמשיך</p>
    </div>
    """, unsafe_allow_html=True)
    if st.session_state.get("authentication_status") is False:
        st.error("שם משתמש או סיסמה שגויים")
    st.stop()

# ── Authenticated ──────────────────────────────────────────────────────────────
current_user: str = st.session_state["username"]
current_name: str = st.session_state["name"]
is_admin: bool = _auth_config["credentials"]["usernames"].get(current_user, {}).get("role") == "admin"

api_key = os.environ.get("ANTHROPIC_API_KEY", "")
if not api_key:
    st.error("⚠️ ANTHROPIC_API_KEY לא נמצא. בדוק את קובץ .env")
    st.stop()

client = anthropic.Anthropic(api_key=api_key)

# ── Header ────────────────────────────────────────────────────────────────────
col_title, col_user = st.columns([5, 1])
with col_title:
    st.markdown("""
    <div style="direction:rtl; text-align:right; padding-bottom:8px;">
      <h1 style="margin:0;">🔍 Tender Scanner — Electra Target</h1>
    </div>
    """, unsafe_allow_html=True)
with col_user:
    st.markdown(f"<div style='text-align:right; padding-top:16px; color:#666;'>שלום, {current_name}</div>", unsafe_allow_html=True)
    authenticator.logout("התנתק")

if "favorites" not in st.session_state:
    st.session_state.favorites = load_favorites(current_user)

_tab_labels = ["📡 סריקה", "🔗 ניתוח לפי URL", "📋 כל המכרזים שנותחו", "⭐ מועדפים"]
if is_admin:
    _tab_labels.append("🧠 למידה")
_tab_labels.append("⚙️ הגדרות")

_tabs = st.tabs(_tab_labels)
tab_scanner  = _tabs[0]
tab_manual   = _tabs[1]
tab_history  = _tabs[2]
tab_favorites = _tabs[3]
if is_admin:
    tab_learning = _tabs[4]
    tab_settings = _tabs[5]
else:
    tab_settings = _tabs[4]


# ── SCANNER TAB ───────────────────────────────────────────────────────────────
with tab_scanner:
    settings = load_settings()
    days_back = settings["scraper"].get("days_back", 7)
    max_t = settings["scraper"]["max_tenders_per_run"]

    st.markdown(
        f"<div style='direction:rtl; color:#666; margin-bottom:12px;'>"
        f"סורק מכרזים מ-<b>{days_back}</b> הימים האחרונים | עד <b>{max_t}</b> מכרזים לריצה"
        f"</div>", unsafe_allow_html=True
    )

    col_run, col_skip, col_spacer = st.columns([1, 1, 4])
    with col_run:
        run_btn = st.button("▶  הפעל סריקה", type="primary", use_container_width=True)
    with col_skip:
        skip_seen = st.checkbox("דלג על מכרזים שנסרקו כבר", value=True)

    if "results" not in st.session_state:
        st.session_state.results = load_last_scan(current_user)
    if "relevance_filter" not in st.session_state:
        st.session_state.relevance_filter = "all"
    if "chats" not in st.session_state:
        st.session_state.chats = {}

    # ── Run scan ──
    if run_btn:
        st.session_state.results = []
        st.session_state.relevance_filter = "all"
        settings = load_settings()
        seen = load_seen(seen_file(current_user)) if skip_seen else set()

        with st.status("סורק את האתר...", expanded=True) as status:
            st.write("📡 מתחבר ל-mr.gov.il...")
            try:
                tender_list = run_async(fetch_tender_list(settings))
            except Exception as e:
                status.update(label=f"שגיאה בסריקה: {e}", state="error")
                st.stop()

            new_tenders = filter_new(tender_list, seen) if skip_seen else tender_list
            st.write(f"✅ נמצאו **{len(tender_list)}** מכרזים | **{len(new_tenders)}** חדשים לניתוח")

            if not new_tenders:
                status.update(label="אין מכרזים חדשים היום", state="complete")
            else:
                progress = st.progress(0)
                for i, meta in enumerate(new_tenders):
                    st.write(f"🔎 [{i+1}/{len(new_tenders)}] {meta['title'][:80]}")
                    try:
                        tender = run_async_with_timeout(
                            fetch_tender_detail(meta, settings), timeout=90
                        )
                        tender.raw_metadata["publish_date"] = meta.get("publish_date", "")
                        tender.raw_metadata["update_date"] = meta.get("update_date", "")
                        if not tender.pdf_text:
                            analysis = {"tender_id": tender.tender_id, "title": tender.title,
                                        "url": tender.url, "publisher": tender.publisher,
                                        "deadline": tender.deadline,
                                        "publish_date": meta.get("publish_date", ""),
                                        "update_date": meta.get("update_date", ""),
                                        "has_pdf": False, "analysis": "NO_PDF"}
                        else:
                            analysis = analyze_tender(tender, settings, client, knowledge=load_knowledge())
                    except Exception as e:
                        analysis = {"tender_id": meta["tender_id"], "title": meta["title"],
                                    "url": meta["url"], "publisher": "", "deadline": "",
                                    "publish_date": meta.get("publish_date", ""),
                                    "update_date": meta.get("update_date", ""),
                                    "has_pdf": False, "analysis": f"שגיאה בעיבוד: {e}"}
                    st.session_state.results.append(analysis)
                    save_last_scan(st.session_state.results, current_user)
                    append_to_history(analysis, current_user)
                    seen.add(meta["tender_id"])
                    if skip_seen:
                        save_seen(seen, seen_file(current_user))
                    progress.progress((i + 1) / len(new_tenders))

                save_last_scan(st.session_state.results, current_user)
                status.update(
                    label=f"✅ הסריקה הושלמה — {len(st.session_state.results)} מכרזים נותחו",
                    state="complete"
                )

    # ── Results ──
    if st.session_state.results:
        results = st.session_state.results
        order = {"high": 0, "medium": 1, "low": 2, "unknown": 3, "no_pdf": 4}
        results_sorted = sorted(results, key=lambda r: order[parse_relevance(r["analysis"])])

        counts = {k: sum(1 for r in results if parse_relevance(r["analysis"]) == k)
                  for k in ["high", "medium", "low", "no_pdf"]}

        st.markdown("---")

        # Filter row
        fc1, fc2, fc3, fc4, fc5 = st.columns([1, 1, 1, 1, 2])
        with fc1:
            if st.button(f"הכל ({len(results)})", use_container_width=True):
                st.session_state.relevance_filter = "all"
        with fc2:
            if st.button(f"🟢 גבוהה ({counts['high']})", use_container_width=True):
                st.session_state.relevance_filter = "high"
        with fc3:
            if st.button(f"🟡 בינונית ({counts['medium']})", use_container_width=True):
                st.session_state.relevance_filter = "medium"
        with fc4:
            if st.button(f"🔴 נמוכה ({counts['low']})", use_container_width=True):
                st.session_state.relevance_filter = "low"
        with fc5:
            gmail_pw = os.environ.get("GMAIL_APP_PASSWORD", "")
            if gmail_pw and st.button("📧 שלח דיגסט במייל", use_container_width=True):
                try:
                    send_digest(results_sorted, settings, gmail_pw)
                    st.success("✅ המייל נשלח!")
                except Exception as e:
                    st.error(f"שגיאה בשליחת מייל: {e}")

        filt = st.session_state.relevance_filter
        filtered = [r for r in results_sorted
                    if filt == "all" or parse_relevance(r["analysis"]) == filt]

        st.markdown(
            f"<div style='direction:rtl; margin:8px 0 16px;'>"
            f"<b>מציג {len(filtered)} מכרזים</b>"
            f"</div>", unsafe_allow_html=True
        )

        for r in filtered:
            rel = parse_relevance(r["analysis"])
            badge = relevance_badge(rel)
            pdf_icon = "✅ PDF" if r.get("has_pdf") else "⚠️ ללא PDF"
            title_short = r["title"][:90] + ("..." if len(r["title"]) > 90 else "")

            with st.expander(f"{badge}   |   {title_short}", expanded=(rel == "high")):
                mc1, mc2 = st.columns([3, 1])
                with mc1:
                    if r.get("publisher"):
                        st.markdown(f"**מפרסם:** {r['publisher']}")
                    if r.get("publish_date"):
                        st.markdown(f"**תאריך פרסום:** {r['publish_date']}")
                    if r.get("update_date"):
                        st.markdown(f"**תאריך עדכון:** {r['update_date']}")
                    if r.get("deadline"):
                        st.markdown(f"**מועד הגשה:** {r['deadline']}")
                with mc2:
                    star_button(r["tender_id"], "scan", current_user)
                    st.markdown(f"**{pdf_icon}**")
                    st.markdown(f"[🔗 לדף המכרז]({r['url']})")
                st.markdown("---")
                if r["analysis"] == "NO_PDF":
                    st.warning("לא נמצא PDF למכרז זה — הניתוח דולג.")
                else:
                    st.markdown(
                        f"<div style='direction:rtl; text-align:right; line-height:1.8;'>{r['analysis']}</div>",
                        unsafe_allow_html=True
                    )

                # ── Chat ──
                if r["analysis"] == "NO_PDF":
                    continue
                chat_key = f"chat_{r['tender_id']}"
                if chat_key not in st.session_state.chats:
                    st.session_state.chats[chat_key] = []

                chat_history = st.session_state.chats[chat_key]

                st.markdown("---")
                st.markdown(
                    "<div style='direction:rtl; font-weight:600; margin-bottom:8px;'>💬 שאל שאלה או תקן את הניתוח</div>",
                    unsafe_allow_html=True
                )

                # Show existing chat messages
                for msg in chat_history:
                    if msg["role"] == "user":
                        st.markdown(
                            f"<div style='direction:rtl; background:#e8f0fe; border-radius:8px; padding:10px 14px; margin:6px 0;'>🧑 {msg['content']}</div>",
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f"<div style='direction:rtl; background:#f0f4f0; border-radius:8px; padding:10px 14px; margin:6px 0; line-height:1.7;'>🤖 {msg['content']}</div>",
                            unsafe_allow_html=True
                        )

                # Input form
                with st.form(key=f"form_{r['tender_id']}", clear_on_submit=True):
                    user_input = st.text_input(
                        "הודעה",
                        placeholder="לדוגמה: למה דירגת את זה גבוהה? / מה מספר העובדים הנדרש?",
                        label_visibility="collapsed",
                        key=f"input_{r['tender_id']}"
                    )
                    send_btn = st.form_submit_button("שלח ↵", use_container_width=False)

                if send_btn and user_input.strip():
                    chat_history.append({"role": "user", "content": user_input.strip()})
                    with st.spinner("Claude חושב..."):
                        try:
                            reply = chat_with_claude(r, chat_history, client)
                        except Exception as e:
                            reply = f"שגיאה: {e}"
                    chat_history.append({"role": "assistant", "content": reply})
                    st.session_state.chats[chat_key] = chat_history
                    st.rerun()


# ── MANUAL URL TAB ────────────────────────────────────────────────────────────
with tab_manual:
    st.markdown("<div style='direction:rtl;'>", unsafe_allow_html=True)
    st.markdown("### ניתוח מכרז לפי קישור")
    st.markdown("<div style='direction:rtl; color:#666; margin-bottom:16px;'>הדבק קישור למכרז מ-mr.gov.il וקבל ניתוח מיידי</div>", unsafe_allow_html=True)

    url_input = st.text_input("קישור למכרז", placeholder="https://mr.gov.il/ilgstorefront/he/p/400...")
    analyze_btn = st.button("🔍 נתח מכרז", type="primary")

    if "manual_result" not in st.session_state:
        st.session_state.manual_result = None

    if analyze_btn and url_input.strip():
        settings = load_settings()
        url = url_input.strip()
        from scraper import _extract_id_from_url
        tender_id = _extract_id_from_url(url)
        meta = {"tender_id": tender_id, "title": url, "url": url,
                "publish_date": "", "update_date": ""}

        with st.status("מנתח את המכרז...", expanded=True) as status:
            st.write("📄 פותח את דף המכרז...")
            try:
                tender = run_async_with_timeout(fetch_tender_detail(meta, settings), timeout=90)
                tender.raw_metadata["publish_date"] = ""
                tender.raw_metadata["update_date"] = ""

                if not tender.pdf_text:
                    st.warning("לא נמצא PDF — מנתח לפי פרטי הדף בלבד")

                if not tender.title or tender.title.startswith("http"):
                    tender.title = f"מכרז {tender_id}"

                st.write("🤖 שולח ל-Claude לניתוח...")
                if not tender.pdf_text:
                    result = {"tender_id": tender_id, "title": tender.title, "url": url,
                              "publisher": tender.publisher, "deadline": tender.deadline,
                              "publish_date": "", "update_date": "",
                              "has_pdf": False, "analysis": "NO_PDF"}
                else:
                    result = analyze_tender(tender, settings, client, knowledge=load_knowledge())

                st.session_state.manual_result = result
                append_to_history(result, current_user)
                status.update(label="✅ הניתוח הושלם ונשמר בהיסטוריה", state="complete")
            except Exception as e:
                status.update(label=f"שגיאה: {e}", state="error")

    if st.session_state.manual_result:
        r = st.session_state.manual_result
        rel = parse_relevance(r["analysis"])
        badge = relevance_badge(rel)
        st.markdown("---")
        st.markdown(f"### {badge}   |   {r['title']}")

        mc1, mc2 = st.columns([3, 1])
        with mc1:
            if r.get("publisher"):
                st.markdown(f"**מפרסם:** {r['publisher']}")
            if r.get("deadline"):
                st.markdown(f"**מועד הגשה:** {r['deadline']}")
        with mc2:
            star_button(r["tender_id"], "manual", current_user)
            pdf_icon = "✅ PDF" if r.get("has_pdf") else "⚠️ ללא PDF"
            st.markdown(f"**{pdf_icon}**")
            st.markdown(f"[🔗 לדף המכרז]({r['url']})")

        st.markdown("---")
        if r["analysis"] == "NO_PDF":
            st.warning("לא נמצא PDF — הניתוח דולג.")
        else:
            st.markdown(
                f"<div style='direction:rtl; text-align:right; line-height:1.8;'>{r['analysis']}</div>",
                unsafe_allow_html=True
            )

        # Chat
        st.markdown("---")
        st.markdown("<div style='direction:rtl; font-weight:600; margin-bottom:8px;'>💬 שאל שאלה או תקן את הניתוח</div>", unsafe_allow_html=True)
        chat_key = f"manual_chat_{r['tender_id']}"
        if chat_key not in st.session_state.chats:
            st.session_state.chats[chat_key] = []
        chat_history = st.session_state.chats[chat_key]

        for msg in chat_history:
            bg = "#e8f0fe" if msg["role"] == "user" else "#f0f4f0"
            icon = "🧑" if msg["role"] == "user" else "🤖"
            st.markdown(f"<div style='direction:rtl; background:{bg}; border-radius:8px; padding:10px 14px; margin:6px 0;'>{icon} {msg['content']}</div>", unsafe_allow_html=True)

        with st.form(key="manual_chat_form", clear_on_submit=True):
            user_input = st.text_input("הודעה", placeholder="שאל שאלה על המכרז...", label_visibility="collapsed")
            if st.form_submit_button("שלח ↵") and user_input.strip():
                chat_history.append({"role": "user", "content": user_input.strip()})
                with st.spinner("Claude חושב..."):
                    try:
                        reply = chat_with_claude(r, chat_history, client)
                    except Exception as e:
                        reply = f"שגיאה: {e}"
                chat_history.append({"role": "assistant", "content": reply})
                st.session_state.chats[chat_key] = chat_history
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# ── HISTORY TAB ───────────────────────────────────────────────────────────────
with tab_history:
    history = load_history(current_user)
    if not history:
        st.info("עדיין לא נותחו מכרזים. הפעל סריקה כדי להתחיל.")
    else:
        order = {"high": 0, "medium": 1, "low": 2, "unknown": 3, "no_pdf": 4}
        history_sorted = sorted(history, key=lambda r: order.get(parse_relevance(r["analysis"]), 3))
        counts_h = {k: sum(1 for r in history if parse_relevance(r["analysis"]) == k)
                    for k in ["high", "medium", "low"]}

        st.markdown(f"**סה\"כ {len(history)} מכרזים נותחו**")

        if "history_filter" not in st.session_state:
            st.session_state.history_filter = "all"

        hc1, hc2, hc3, hc4 = st.columns([1, 1, 1, 1])
        with hc1:
            if st.button(f"הכל ({len(history)})", key="h_all", use_container_width=True):
                st.session_state.history_filter = "all"
        with hc2:
            if st.button(f"🟢 גבוהה ({counts_h['high']})", key="h_high", use_container_width=True):
                st.session_state.history_filter = "high"
        with hc3:
            if st.button(f"🟡 בינונית ({counts_h['medium']})", key="h_med", use_container_width=True):
                st.session_state.history_filter = "medium"
        with hc4:
            if st.button(f"🔴 נמוכה ({counts_h['low']})", key="h_low", use_container_width=True):
                st.session_state.history_filter = "low"

        hfilt = st.session_state.history_filter
        h_filtered = [r for r in history_sorted
                      if hfilt == "all" or parse_relevance(r["analysis"]) == hfilt]

        st.markdown("---")
        for r in h_filtered:
            rel = parse_relevance(r["analysis"])
            badge = relevance_badge(rel)
            pdf_icon = "✅ PDF" if r.get("has_pdf") else "⚠️ ללא PDF"
            title_short = r["title"][:90] + ("..." if len(r["title"]) > 90 else "")

            with st.expander(f"{badge}   |   {title_short}"):
                mc1, mc2 = st.columns([3, 1])
                with mc1:
                    if r.get("publisher"):
                        st.markdown(f"**מפרסם:** {r['publisher']}")
                    if r.get("publish_date"):
                        st.markdown(f"**תאריך פרסום:** {r['publish_date']}")
                    if r.get("update_date"):
                        st.markdown(f"**תאריך עדכון:** {r['update_date']}")
                    if r.get("deadline"):
                        st.markdown(f"**מועד הגשה:** {r['deadline']}")
                with mc2:
                    star_button(r["tender_id"], "hist", current_user)
                    st.markdown(f"**{pdf_icon}**")
                    st.markdown(f"[🔗 לדף המכרז]({r['url']})")
                st.markdown("---")
                st.markdown(
                    f"<div style='direction:rtl; text-align:right; line-height:1.8;'>{r['analysis']}</div>",
                    unsafe_allow_html=True
                )

                # Chat
                chat_key = f"history_chat_{r['tender_id']}"
                if chat_key not in st.session_state.chats:
                    st.session_state.chats[chat_key] = []
                chat_history = st.session_state.chats[chat_key]

                st.markdown("---")
                st.markdown("<div style='direction:rtl; font-weight:600; margin-bottom:8px;'>💬 שאל שאלה או תקן את הניתוח</div>", unsafe_allow_html=True)
                for msg in chat_history:
                    bg = "#e8f0fe" if msg["role"] == "user" else "#f0f4f0"
                    icon = "🧑" if msg["role"] == "user" else "🤖"
                    st.markdown(f"<div style='direction:rtl; background:{bg}; border-radius:8px; padding:10px 14px; margin:6px 0;'>{icon} {msg['content']}</div>", unsafe_allow_html=True)

                with st.form(key=f"hform_{r['tender_id']}", clear_on_submit=True):
                    user_input = st.text_input("הודעה", placeholder="שאל שאלה על המכרז...", label_visibility="collapsed")
                    if st.form_submit_button("שלח ↵"):
                        if user_input.strip():
                            chat_history.append({"role": "user", "content": user_input.strip()})
                            with st.spinner("Claude חושב..."):
                                try:
                                    reply = chat_with_claude(r, chat_history, client)
                                except Exception as e:
                                    reply = f"שגיאה: {e}"
                            chat_history.append({"role": "assistant", "content": reply})
                            st.session_state.chats[chat_key] = chat_history
                            st.rerun()


# ── FAVORITES TAB ─────────────────────────────────────────────────────────────
with tab_favorites:
    favs = st.session_state.favorites
    if not favs:
        st.info("עדיין לא הוספת מועדפים. לחץ על ☆ בכל מכרז כדי להוסיפו לכאן.")
    else:
        history_all = load_history(current_user)
        fav_tenders = [r for r in history_all if r["tender_id"] in favs]
        if not fav_tenders:
            st.info("המכרזים המועדפים לא נמצאו בהיסטוריה.")
        else:
            st.markdown(f"**{len(fav_tenders)} מכרזים מועדפים**")
            st.markdown("---")
            for r in fav_tenders:
                rel = parse_relevance(r["analysis"])
                badge = relevance_badge(rel)
                pdf_icon = "✅ PDF" if r.get("has_pdf") else "⚠️ ללא PDF"
                title_short = r["title"][:90] + ("..." if len(r["title"]) > 90 else "")

                with st.expander(f"⭐ {badge}   |   {title_short}"):
                    mc1, mc2 = st.columns([3, 1])
                    with mc1:
                        if r.get("publisher"):
                            st.markdown(f"**מפרסם:** {r['publisher']}")
                        if r.get("publish_date"):
                            st.markdown(f"**תאריך פרסום:** {r['publish_date']}")
                        if r.get("update_date"):
                            st.markdown(f"**תאריך עדכון:** {r['update_date']}")
                        if r.get("deadline"):
                            st.markdown(f"**מועד הגשה:** {r['deadline']}")
                    with mc2:
                        star_button(r["tender_id"], "fav", current_user)
                        st.markdown(f"**{pdf_icon}**")
                        st.markdown(f"[🔗 לדף המכרז]({r['url']})")
                    st.markdown("---")
                    if r["analysis"] == "NO_PDF":
                        st.warning("לא נמצא PDF למכרז זה.")
                    else:
                        st.markdown(
                            f"<div style='direction:rtl; text-align:right; line-height:1.8;'>{r['analysis']}</div>",
                            unsafe_allow_html=True
                        )

                    chat_key = f"fav_chat_{r['tender_id']}"
                    if chat_key not in st.session_state.chats:
                        st.session_state.chats[chat_key] = []
                    chat_history = st.session_state.chats[chat_key]

                    st.markdown("---")
                    st.markdown("<div style='direction:rtl; font-weight:600; margin-bottom:8px;'>💬 שאל שאלה על המכרז</div>", unsafe_allow_html=True)
                    for msg in chat_history:
                        bg = "#e8f0fe" if msg["role"] == "user" else "#f0f4f0"
                        icon = "🧑" if msg["role"] == "user" else "🤖"
                        st.markdown(f"<div style='direction:rtl; background:{bg}; border-radius:8px; padding:10px 14px; margin:6px 0;'>{icon} {msg['content']}</div>", unsafe_allow_html=True)

                    with st.form(key=f"favform_{r['tender_id']}", clear_on_submit=True):
                        user_input = st.text_input("הודעה", placeholder="שאל שאלה על המכרז...", label_visibility="collapsed")
                        if st.form_submit_button("שלח ↵"):
                            if user_input.strip():
                                chat_history.append({"role": "user", "content": user_input.strip()})
                                with st.spinner("Claude חושב..."):
                                    try:
                                        reply = chat_with_claude(r, chat_history, client)
                                    except Exception as e:
                                        reply = f"שגיאה: {e}"
                                chat_history.append({"role": "assistant", "content": reply})
                                st.session_state.chats[chat_key] = chat_history
                                st.rerun()


# ── LEARNING TAB (admin only) ─────────────────────────────────────────────────
_show_learning = is_admin
if _show_learning:
 with tab_learning:
    st.markdown("<div style='direction:rtl;'>", unsafe_allow_html=True)
    st.markdown("### 🧠 מצב למידה")
    st.markdown("<div style='direction:rtl; color:#666; margin-bottom:16px;'>נתח מכרז, תן משוב, נתח מחדש — עד שהניתוח מדויק. בסיום שמור את התובנות למנוע.</div>", unsafe_allow_html=True)

    # Session state for learning tab
    if "learn_tender" not in st.session_state:
        st.session_state.learn_tender = None       # stores tender dict with pdf_text
    if "learn_result" not in st.session_state:
        st.session_state.learn_result = None       # current analysis result
    if "learn_feedback" not in st.session_state:
        st.session_state.learn_feedback = []       # list of feedback strings this session
    if "learn_iteration" not in st.session_state:
        st.session_state.learn_iteration = 0

    # URL input
    learn_url = st.text_input("קישור למכרז", placeholder="https://mr.gov.il/ilgstorefront/he/p/400...", key="learn_url_input")
    learn_btn = st.button("🔍 נתח מכרז", type="primary", key="learn_analyze_btn")

    if learn_btn and learn_url.strip():
        st.session_state.learn_feedback = []
        st.session_state.learn_iteration = 0
        settings = load_settings()
        url = learn_url.strip()
        from scraper import _extract_id_from_url
        tender_id = _extract_id_from_url(url)
        meta = {"tender_id": tender_id, "title": url, "url": url, "publish_date": "", "update_date": ""}

        with st.status("מנתח את המכרז...", expanded=True) as status:
            st.write("📄 מוריד PDF ומנתח...")
            try:
                tender = run_async_with_timeout(fetch_tender_detail(meta, settings), timeout=90)
                tender.raw_metadata["publish_date"] = ""
                tender.raw_metadata["update_date"] = ""
                if not tender.title or tender.title.startswith("http"):
                    tender.title = f"מכרז {tender_id}"

                # Store tender data (including pdf_text) for future re-analyses
                st.session_state.learn_tender = {
                    "tender_id": tender.tender_id,
                    "title": tender.title,
                    "url": tender.url,
                    "publisher": tender.publisher,
                    "deadline": tender.deadline,
                    "pdf_text": tender.pdf_text,
                    "has_pdf": bool(tender.pdf_text),
                }

                knowledge = load_knowledge()
                if not tender.pdf_text:
                    st.session_state.learn_result = {
                        "title": tender.title, "url": url,
                        "publisher": tender.publisher, "deadline": tender.deadline,
                        "has_pdf": False, "analysis": "NO_PDF"
                    }
                else:
                    st.write("🤖 שולח ל-Claude...")
                    st.session_state.learn_result = analyze_tender(tender, settings, client, knowledge=knowledge)
                st.session_state.learn_iteration = 1
                status.update(label="✅ ניתוח ראשוני הושלם", state="complete")
            except Exception as e:
                status.update(label=f"שגיאה: {e}", state="error")

    # Show current analysis + feedback controls
    if st.session_state.learn_result and st.session_state.learn_tender:
        r = st.session_state.learn_result
        t = st.session_state.learn_tender
        rel = parse_relevance(r.get("analysis", ""))
        badge = relevance_badge(rel)

        st.markdown("---")
        iter_label = f"ניתוח #{st.session_state.learn_iteration}" if st.session_state.learn_iteration > 1 else "ניתוח ראשוני"
        st.markdown(f"#### {iter_label} — {badge}   |   {r['title']}")

        lc1, lc2 = st.columns([3, 1])
        with lc1:
            if r.get("publisher"):
                st.markdown(f"**מפרסם:** {r['publisher']}")
            if r.get("deadline"):
                st.markdown(f"**מועד הגשה:** {r['deadline']}")
        with lc2:
            pdf_icon = "✅ PDF" if r.get("has_pdf") else "⚠️ ללא PDF"
            st.markdown(f"**{pdf_icon}**")
            st.markdown(f"[🔗 לדף המכרז]({r['url']})")

        st.markdown("---")
        if r.get("analysis") == "NO_PDF":
            st.warning("לא נמצא PDF — לא ניתן לנתח מחדש.")
        else:
            st.markdown(
                f"<div style='direction:rtl; text-align:right; line-height:1.8;'>{r['analysis']}</div>",
                unsafe_allow_html=True
            )

        # Show past feedback this session
        if st.session_state.learn_feedback:
            st.markdown("---")
            st.markdown("<div style='direction:rtl; font-weight:600;'>💬 משוב שניתן בסשן זה:</div>", unsafe_allow_html=True)
            for i, fb in enumerate(st.session_state.learn_feedback, 1):
                st.markdown(
                    f"<div style='direction:rtl; background:#fff8e1; border-radius:8px; padding:8px 12px; margin:4px 0;'>#{i}: {fb}</div>",
                    unsafe_allow_html=True
                )

        # Feedback input
        st.markdown("---")
        st.markdown("<div style='direction:rtl; font-weight:600; margin-bottom:8px;'>📝 מה לא מדויק? מה פספסנו?</div>", unsafe_allow_html=True)

        with st.form(key=f"learn_form_{st.session_state.learn_iteration}", clear_on_submit=True):
            feedback_input = st.text_area(
                "משוב",
                placeholder="לדוגמה: הרלוונטיות צריכה להיות גבוהה יותר כי אנחנו כבר עובדים עם הגוף הזה...",
                label_visibility="collapsed",
                height=100,
            )
            btn_col1, btn_col2 = st.columns([2, 1])
            with btn_col1:
                reanalyze_btn = st.form_submit_button("🔄 נתח מחדש עם המשוב", use_container_width=True)
            with btn_col2:
                save_btn = st.form_submit_button("💾 שמור תובנות", use_container_width=True, type="primary")

        if reanalyze_btn and feedback_input.strip():
            st.session_state.learn_feedback.append(feedback_input.strip())
            settings = load_settings()
            knowledge = load_knowledge()

            # Rebuild a Tender object with the stored pdf_text
            from scraper import Tender as TenderClass
            tender_obj = TenderClass(
                tender_id=t["tender_id"],
                title=t["title"],
                url=t["url"],
                publisher=t["publisher"],
                deadline=t["deadline"],
                pdf_text=t["pdf_text"],
                raw_metadata={"publish_date": "", "update_date": ""},
            )

            with st.spinner("🔄 מנתח מחדש עם המשוב..."):
                try:
                    new_result = analyze_tender(
                        tender_obj, settings, client,
                        knowledge=knowledge,
                        session_feedback=st.session_state.learn_feedback,
                    )
                    st.session_state.learn_result = new_result
                    st.session_state.learn_iteration += 1
                except Exception as e:
                    st.error(f"שגיאה: {e}")
            st.rerun()

        if save_btn:
            all_feedback = st.session_state.learn_feedback
            if feedback_input.strip():
                all_feedback = all_feedback + [feedback_input.strip()]
            if not all_feedback:
                st.warning("לא ניתן משוב עדיין — תן לפחות משוב אחד לפני השמירה.")
            else:
                with st.spinner("💾 מסכם תובנות ושומר..."):
                    try:
                        new_guidelines = distill_knowledge(t["title"], all_feedback, client)
                        existing = load_knowledge()
                        existing.extend(new_guidelines)
                        save_knowledge(existing)
                        if feedback_input.strip():
                            st.session_state.learn_feedback.append(feedback_input.strip())
                        st.success(f"✅ נשמרו {len(new_guidelines)} תובנות חדשות למנוע!")
                        st.markdown("<div style='direction:rtl;'>", unsafe_allow_html=True)
                        for g in new_guidelines:
                            st.markdown(f"- {g}")
                        st.markdown("</div>", unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"שגיאה בשמירה: {e}")

    # Show current knowledge base
    knowledge = load_knowledge()
    if knowledge:
        st.markdown("---")
        with st.expander(f"📚 בסיס הידע הנוכחי ({len(knowledge)} תובנות)"):
            for i, g in enumerate(knowledge, 1):
                col_g, col_del = st.columns([10, 1])
                with col_g:
                    st.markdown(f"<div style='direction:rtl;'>{i}. {g}</div>", unsafe_allow_html=True)
                with col_del:
                    if st.button("🗑", key=f"del_know_{i}"):
                        knowledge.pop(i - 1)
                        save_knowledge(knowledge)
                        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# ── SETTINGS TAB ──────────────────────────────────────────────────────────────
with tab_settings:
    settings = load_settings()
    st.markdown("<div style='direction:rtl;'>", unsafe_allow_html=True)
    st.markdown("### הגדרות סריקה")

    col1, col2 = st.columns(2)
    with col1:
        days_back_s = st.number_input("ימים אחורה לסריקה", min_value=1, max_value=90,
                                      value=settings["scraper"].get("days_back", 7))
        max_tenders_s = st.number_input("מקסימום מכרזים לריצה", min_value=1, max_value=500,
                                        value=settings["scraper"]["max_tenders_per_run"])
    with col2:
        budget_min_s = st.number_input("תקציב מינימלי שנתי (₪)", min_value=0,
                                       value=settings["budget"]["min_annual_ils"], step=100000)
        budget_max_s = st.number_input("תקציב מקסימלי שנתי (₪)", min_value=0,
                                       value=settings["budget"]["max_annual_ils"], step=1000000)

    st.markdown("### ענפים רלוונטיים")
    industries_text = st.text_area("ענף אחד בכל שורה", value="\n".join(settings["industries"]), height=160)

    st.markdown("### עלויות כוח אדם")
    lc1, lc2, lc3 = st.columns(3)
    with lc1:
        simple_monthly_s = st.number_input("שכר חודשי פשוט (₪)",
                                           value=settings["labor_costs"]["simple_monthly_ils"], step=500)
    with lc2:
        simple_hourly_s = st.number_input("שכר שעתי פשוט (₪)",
                                          value=settings["labor_costs"]["simple_hourly_ils"], step=1)
    with lc3:
        social_mult_s = st.number_input("מכפיל הוצאות סוציאליות",
                                        value=settings["labor_costs"]["social_expense_multiplier"],
                                        step=0.05, format="%.2f")

    st.markdown("</div>", unsafe_allow_html=True)

    if st.button("💾 שמור הגדרות", type="primary"):
        settings["scraper"]["days_back"] = int(days_back_s)
        settings["scraper"]["max_tenders_per_run"] = int(max_tenders_s)
        settings["budget"]["min_annual_ils"] = int(budget_min_s)
        settings["budget"]["max_annual_ils"] = int(budget_max_s)
        settings["industries"] = [l.strip() for l in industries_text.splitlines() if l.strip()]
        settings["labor_costs"]["simple_monthly_ils"] = int(simple_monthly_s)
        settings["labor_costs"]["simple_hourly_ils"] = int(simple_hourly_s)
        settings["labor_costs"]["social_expense_multiplier"] = float(social_mult_s)
        save_settings_file(settings)
        st.success("✅ ההגדרות נשמרו!")
