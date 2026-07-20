"""Claude-powered tender analysis."""

import json
from typing import Optional

import anthropic

from scraper import Tender


SYSTEM_PROMPT = """אתה יועץ עסקי בכיר המנתח מכרזים ממשלתיים עבור חברת Electra Target.
החברה מתמחה ב: BPO, ניהול פרויקטים עתיר כוח אדם, לוגיסטיקה, בריאות, תחבורה, ניהול מתקנים ואדמיניסטרציה.

הנחות עלות כוח אדם:
- עבודה פשוטה: ₪8,000-10,000/חודש או ₪45-50/שעה × 1.3 הוצאות סוציאליות
- עבודה מיומנת: משתנה לפי ענף (בריאות ~₪14,000, מנהל לוגיסטי ~₪13,000, מנהל אדמין ~₪12,000)
- חוזים ארוכי טווח: חישוב שנתי"""

ANALYSIS_PROMPT_TEMPLATE = """
נתח את המכרז הבא עבור Electra Target.

כותרת: {title}
מפרסם: {publisher}
מועד הגשה: {deadline}
URL: {url}

תוכן המכרז (מה-PDF):
{pdf_text}

**חובה: השורה הראשונה של התשובה חייבת להיות בדיוק בפורמט הזה (ללא שום דבר לפניה):**
`רמת רלוונטיות: גבוהה` או `רמת רלוונטיות: בינונית` או `רמת רלוונטיות: נמוכה`

לאחר מכן ספק ניתוח מובנה עם הפרמטרים הבאים:

1. **סיכום** (3-4 משפטים): מה מבוקש, מי המפרסם, היקף עיקרי.
2. **רלוונטיות ל-Electra Target** (גבוהה / בינונית / נמוכה): הסבר מדוע.
3. **תחומים רלוונטיים**: אילו תחומי הפעילות של החברה מתאימים.
4. **הערכת היקף כספי**:
   - ערך שנתי משוער (₪)
   - בסיס לחישוב (כמות עובדים × עלות, או נפח שירות)
5. **כוח אדם נדרש**: הערכת מספר עובדים וסוג עבודה.
6. **אורך חוזה משוער**: שנים.
7. **אתגרים/סיכונים עיקריים**: עד 3 נקודות.
8. **המלצה**: האם להגיש הצעה? (כן / שקול / לא) + נימוק קצר.

ענה בעברית בלבד. היה ממוקד ומעשי.
"""


def _build_system(knowledge: list[str] | None, session_feedback: list[str] | None) -> str:
    system = SYSTEM_PROMPT
    if knowledge:
        system += "\n\nתובנות שנצברו מניסיון קודם עם Electra Target:\n" + "\n".join(f"- {g}" for g in knowledge)
    if session_feedback:
        system += "\n\nהערות המשתמש לניתוח זה (שקול אותן בניתוח — הן מגיעות ממי שמכיר את החברה היטב):\n" + "\n".join(f"- {f}" for f in session_feedback)
    return system


def analyze_tender(tender: Tender, settings: dict, client: anthropic.Anthropic,
                   knowledge: list[str] | None = None,
                   session_feedback: list[str] | None = None) -> dict:
    """Send tender to Claude and return structured analysis."""
    pdf_excerpt = tender.pdf_text[:30000] if tender.pdf_text else "(לא נמצא PDF)"

    prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        title=tender.title,
        publisher=tender.publisher or "לא ידוע",
        deadline=tender.deadline or "לא צוין",
        url=tender.url,
        pdf_text=pdf_excerpt,
    )

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=_build_system(knowledge, session_feedback),
            messages=[{"role": "user", "content": prompt}],
        )
        analysis_text = message.content[0].text
    except Exception as e:
        analysis_text = f"שגיאה בניתוח: {e}"

    return {
        "tender_id": tender.tender_id,
        "title": tender.title,
        "url": tender.url,
        "publisher": tender.publisher,
        "deadline": tender.deadline,
        "publish_date": tender.raw_metadata.get("publish_date", ""),
        "update_date": tender.raw_metadata.get("update_date", ""),
        "has_pdf": bool(tender.pdf_text),
        "analysis": analysis_text,
    }


def distill_knowledge(tender_title: str, feedback_list: list[str], client: anthropic.Anthropic) -> list[str]:
    """Ask Claude to distill session feedback into reusable guidelines."""
    feedback_text = "\n".join(f"- {f}" for f in feedback_list)
    prompt = f"""ניתחנו מכרז בשם: "{tender_title}"

במהלך הניתוח, המשתמש (מנהל בחברת Electra Target) נתן את המשוב הבא:
{feedback_text}

בהתבסס על המשוב, כתוב 2-4 תובנות עסקיות קצרות שיעזרו לנתח מכרזים עתידיים טוב יותר.
אלו לא כללים נוקשים — אלא הקשר, רקע ונסיון עסקי שמשקפים איך Electra Target חושבת.
כתוב בעברית. כל תובנה בשורה נפרדת. ללא מספור, ללא כותרות."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        lines = [l.strip().lstrip("- ").strip() for l in response.content[0].text.strip().splitlines()]
        return [l for l in lines if l]
    except Exception:
        return feedback_list
