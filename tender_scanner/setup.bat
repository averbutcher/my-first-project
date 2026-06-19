@echo off
echo === Tender Scanner Setup ===
echo.

python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium

echo.
echo Setup complete!
echo.
echo Next steps:
echo   1. Copy .env.example to .env
echo   2. Fill in ANTHROPIC_API_KEY and GMAIL_APP_PASSWORD in .env
echo   3. Run: python main.py
pause
