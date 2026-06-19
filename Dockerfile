FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

COPY tender_scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tender_scanner/ .

RUN mkdir -p data/shared data/users

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--server.fileWatcherType=none"]
