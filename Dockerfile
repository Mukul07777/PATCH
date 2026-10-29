FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 1000 app && chown -R app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
# Serverless Endpoint: web app + API.  Serverless Job: override the command with
#   python -m patchpilot.cli <repo-or-case> https://github.com/org/repo
CMD ["uvicorn", "patchpilot.server:app", "--host", "0.0.0.0", "--port", "8000"]
