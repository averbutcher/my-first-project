import os
import tempfile
from datetime import datetime

import streamlit as st

from engine import (
    load_config, save_config,
    parse_message, parse_excel, compare, export_to_excel,
)

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="השוואת משמרות",
    page_icon="📊",
    layout="wide",
)

# ── RTL + visual styling ──────────────────────────────────────────────────────
st.markdown("""
<style>
  /* RTL direction for all text */
  html, body, [class*="css"] { direction: rtl; }

  textarea {
    direction: rtl !important;
    text-align: right !important;
    font-family: 'Segoe UI', Arial, sans-serif !important;
    font-size: 14px !important;
    line-height: 1.75 !important;
  }
  input[type="text"], input[type="number"] {
    direction: rtl !important;
    text-align: right !important;
  }

  /* Labels and headings right-aligned */
  label, p, li, h1, h2, h3, .stAlert { direction: rtl; text-align: right; }

  /* Sidebar header */
  section[data-testid="stSidebar"] h1,
  section[data-testid="stSidebar"] h2,
  section[data-testid="stSidebar"] h3 { text-align: right; }

  /* File uploader text */
  [data-testid="stFileUploadDropzone"] { direction: rtl; }

  /* Shrink excessive top padding */
  .block-container { padding-top: 1.5rem; }

  /* Result color rows */
  .ok-row    { background:#d4edda; padding:6px 10px; border-radius:5px; margin:3px 0; }
  .gap-row   { background:#fff3cd; padding:6px 10px; border-radius:5px; margin:3px 0; }
  .msg-row   { background:#fde8d4; padding:6px 10px; border-radius:5px; margin:3px 0; }
  .xl-row    { background:#ffd6d6; padding:6px 10px; border-radius:5px; margin:3px 0; }
  .row-text  { font-size:13px; font-family:'Segoe UI',Arial,sans-serif; }
</style>
""", unsafe_allow_html=True)

# ── Session-state init ────────────────────────────────────────────────────────
if 'cfg' not in st.session_state:
    st.session_state.cfg = load_config()

cfg = st.session_state.cfg

if 'alias_list' not in st.session_state:
    st.session_state.alias_list = list(cfg.get('aliases', {}).items())

if 'results' not in st.session_state:
    st.session_state.results = None

if 'output_bytes' not in st.session_state:
    st.session_state.output_bytes = None

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("הגדרות ⚙️")

    # Excel columns
    with st.expander("עמודות בקובץ האקסל", expanded=False):
        col_date  = st.text_input("תאריך",       value=cfg['excel_columns'].get('date',        'B'), max_chars=3)
        col_start = st.text_input("שעת התחלה",   value=cfg['excel_columns'].get('start_time',  'C'), max_chars=3)
        col_end   = st.text_input("שעת סיום",    value=cfg['excel_columns'].get('end_time',    'D'), max_chars=3)
        col_name  = st.text_input("שם עובד",     value=cfg['excel_columns'].get('worker_name', 'F'), max_chars=3)
        has_header = st.checkbox("שורת כותרת", value=cfg.get('excel_has_header', True))

    # Rules
    with st.expander("כללי השוואה", expanded=False):
        gap = st.number_input(
            "סף פער מקסימלי (דקות)",
            value=int(cfg['rules']['gap_threshold_minutes']),
            min_value=0, max_value=300, step=5,
        )
        default_start = st.text_input(
            "שעת התחלה ברירת מחדל (חסר באקסל)",
            value=cfg['rules']['default_start_time'],
            max_chars=5,
        )

    if st.button("שמור הגדרות", use_container_width=True):
        cfg['excel_columns'] = {
            'date':        col_date.strip().upper(),
            'start_time':  col_start.strip().upper(),
            'end_time':    col_end.strip().upper(),
            'worker_name': col_name.strip().upper(),
        }
        cfg['excel_has_header']               = has_header
        cfg['rules']['gap_threshold_minutes'] = gap
        cfg['rules']['default_start_time']    = default_start.strip()
        save_config(cfg)
        st.success("ההגדרות נשמרו!")

    st.divider()

    # Aliases
    st.subheader("כינויי שמות")
    st.caption("שם בהודעה = שם באקסל")

    to_delete = None
    for i, (msg_n, xl_n) in enumerate(st.session_state.alias_list):
        c1, c2, c3, c4 = st.columns([3, 0.4, 3, 1])
        with c1:
            st.session_state.alias_list[i] = (
                st.text_input("msg", value=msg_n, key=f"am_{i}", label_visibility="collapsed",
                              placeholder="שם בהודעה"),
                st.session_state.alias_list[i][1],
            )
        with c2:
            st.markdown("<p style='padding-top:8px;text-align:center'>=</p>", unsafe_allow_html=True)
        with c3:
            st.session_state.alias_list[i] = (
                st.session_state.alias_list[i][0],
                st.text_input("xl", value=xl_n, key=f"ax_{i}", label_visibility="collapsed",
                              placeholder="שם באקסל"),
            )
        with c4:
            if st.button("✕", key=f"adel_{i}"):
                to_delete = i

    if to_delete is not None:
        st.session_state.alias_list.pop(to_delete)
        st.rerun()

    if st.button("➕ הוסף כינוי", use_container_width=True):
        st.session_state.alias_list.append(("", ""))
        st.rerun()

    if st.button("שמור כינויים", use_container_width=True, type="primary"):
        aliases = {
            m.strip(): x.strip()
            for m, x in st.session_state.alias_list
            if m.strip() and x.strip()
        }
        cfg['aliases'] = aliases
        save_config(cfg)
        st.success("הכינויים נשמרו!")

    st.divider()

    # Legend
    st.markdown("""
**מקרא:**
<div style="font-size:13px; line-height:2">
  <span style="background:#d4edda; padding:2px 8px; border-radius:4px;">הכל תקין</span><br>
  <span style="background:#fff3cd; padding:2px 8px; border-radius:4px;">פער שעות</span><br>
  <span style="background:#fde8d4; padding:2px 8px; border-radius:4px;">חסר בהודעה</span><br>
  <span style="background:#ffd6d6; padding:2px 8px; border-radius:4px;">חסר באקסל</span>
</div>
""", unsafe_allow_html=True)


# ── Main area ─────────────────────────────────────────────────────────────────
st.title("השוואת משמרות 📊")

col_msg, col_xl = st.columns([3, 2])

with col_msg:
    st.subheader("הודעה מוואטסאפ")
    message = st.text_area(
        label="msg",
        height=280,
        placeholder="הדבק כאן את ההודעה מוואטסאפ...",
        label_visibility="collapsed",
    )

with col_xl:
    st.subheader("קובץ אקסל")
    excel_file = st.file_uploader(
        label="xl",
        type=["xlsx", "xls"],
        label_visibility="collapsed",
    )
    if excel_file:
        st.success(f"נטען: {excel_file.name}")

st.divider()

if st.button("▶  הרץ השוואה", type="primary", use_container_width=True):
    if not message.strip():
        st.error("אנא הדבק הודעה מוואטסאפ")
    elif excel_file is None:
        st.error("אנא העלה קובץ אקסל")
    else:
        with st.spinner("מעבד..."):
            try:
                # Write uploaded Excel to a temp file
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
                    tmp.write(excel_file.getvalue())
                    tmp_path = tmp.name

                msg_entries   = parse_message(message)
                excel_entries = parse_excel(tmp_path, cfg)
                os.unlink(tmp_path)

                if not msg_entries:
                    st.error("לא נמצאו עובדים בהודעה — בדוק את הפורמט (שם, מקום, שעות)")
                elif not excel_entries:
                    st.error("לא נמצאו שורות תקינות באקסל — בדוק הגדרות עמודות")
                else:
                    results = compare(msg_entries, excel_entries, cfg)

                    # Build output Excel in a temp file then read bytes
                    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as out_tmp:
                        out_path = out_tmp.name
                    export_to_excel(results, out_path)
                    with open(out_path, "rb") as fh:
                        output_bytes = fh.read()
                    os.unlink(out_path)

                    st.session_state.results      = results
                    st.session_state.output_bytes = output_bytes

            except Exception as e:
                st.error(f"שגיאה: {e}")

# ── Results ───────────────────────────────────────────────────────────────────
if st.session_state.output_bytes:
    st.success(f"הושלם! נמצאו {len(st.session_state.results)} שורות")

    st.download_button(
        label="⬇️  הורד קובץ פלט (Excel)",
        data=st.session_state.output_bytes,
        file_name=f"השוואת_משמרות_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True,
        type="primary",
    )

    # Color-coded preview
    st.subheader("תצוגה מקדימה")
    color_class = {
        'ok':            'ok-row',
        'gap':           'gap-row',
        'missing_msg':   'msg-row',
        'missing_excel': 'xl-row',
    }

    def fmt_time(t):
        return t.strftime("%H:%M") if hasattr(t, "strftime") else (str(t) if t else "")

    def fmt_date(d):
        if hasattr(d, "strftime"):
            return d.strftime("%d/%m/%Y")
        return str(d) if d else ""

    rows_html = ""
    for r in st.session_state.results:
        css = color_class.get(r['status'], '')
        rows_html += f"""
        <div class="{css} row-text">
          <strong>{r['worker_name']}</strong>
          &nbsp;|&nbsp; {r.get('workplace','') or '—'}
          &nbsp;|&nbsp; {fmt_date(r['date'])}
          &nbsp;|&nbsp; {fmt_time(r['start_time'])} – {fmt_time(r['end_time'])}
          &nbsp;|&nbsp; מכירות: {r.get('sales','') or '—'}
          &nbsp;|&nbsp; <em>{r['notes']}</em>
        </div>"""

    st.markdown(rows_html, unsafe_allow_html=True)

st.markdown("---")
st.caption("גרסה 1.1")
