@echo off
cd /d "%~dp0"
echo Trying to start app...
python -m streamlit run app.py
echo.
echo If you see an error above, take a screenshot and share it.
pause
