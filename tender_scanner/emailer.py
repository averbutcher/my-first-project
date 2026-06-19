"""Send daily digest email via Gmail SMTP."""

import os
import smtplib
from datetime import date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def build_html_digest(analyses: list[dict], run_date: str) -> str:
    def relevance_color(text: str) -> str:
        if "גבוהה" in text:
            return "#1a7a1a"
        if "בינונית" in text:
            return "#b36b00"
        return "#8b0000"

    cards = []
    for a in analyses:
        analysis = a.get("analysis", "")
        # Quick color hint from analysis text
        color = relevance_color(analysis)
        pdf_badge = "✅ PDF" if a.get("has_pdf") else "⚠️ ללא PDF"
        card = f"""
        <div style="border:1px solid #ddd; border-radius:8px; padding:16px; margin-bottom:20px;
                    font-family:Arial,sans-serif; direction:rtl; text-align:right;">
          <h2 style="margin:0 0 8px; color:{color};">
            <a href="{a['url']}" style="color:{color}; text-decoration:none;">{a['title']}</a>
          </h2>
          <p style="margin:4px 0; color:#555; font-size:13px;">
            {a.get('publisher','') or 'מפרסם לא ידוע'}
            {' | פורסם: ' + a['publish_date'] if a.get('publish_date') else ''}
            {' | מועד הגשה: ' + a['deadline'] if a.get('deadline') else ''}
            &nbsp;|&nbsp; {pdf_badge}
          </p>
          <hr style="border:none; border-top:1px solid #eee; margin:12px 0;">
          <div style="white-space:pre-wrap; font-size:14px; line-height:1.6;">{analysis}</div>
        </div>"""
        cards.append(card)

    body = "\n".join(cards) if cards else "<p>לא נמצאו מכרזים חדשים היום.</p>"
    return f"""
    <html><body style="background:#f5f5f5; padding:20px;">
      <h1 style="font-family:Arial,sans-serif; direction:rtl; text-align:right; color:#1a1a2e;">
        סריקת מכרזים יומית — {run_date}
      </h1>
      <p style="font-family:Arial,sans-serif; direction:rtl; text-align:right; color:#555;">
        נמצאו {len(analyses)} מכרזים חדשים לניתוח:
      </p>
      {body}
      <p style="font-family:Arial,sans-serif; font-size:12px; color:#999; text-align:center; margin-top:30px;">
        Electra Target Tender Scanner
      </p>
    </body></html>"""


def send_digest(analyses: list[dict], settings: dict, app_password: str) -> None:
    email_cfg = settings["email"]
    recipient = email_cfg["recipient"]
    sender = email_cfg["sender"]
    run_date = date.today().strftime("%d/%m/%Y")
    subject = f"{email_cfg['subject_prefix']} {len(analyses)} מכרזים חדשים — {run_date}"

    html = build_html_digest(analyses, run_date)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html", "utf-8"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, app_password)
        server.sendmail(sender, [recipient], msg.as_string())

    print(f"[emailer] Digest sent to {recipient} with {len(analyses)} tenders.")
