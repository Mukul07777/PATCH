FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Non-root user; everything the server writes (SQLite DB, secret.key, run logs, work dirs) lives in /data
RUN useradd --create-home --uid 1000 app && mkdir -p /data && chown -R app /app /data
ENV PATCHPILOT_DB=/data/patchpilot.db \
    PATCHPILOT_RUNS_DIR=/data/runs \
    HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT', '8000') + '/api/health', timeout=4)"
# Serverless Job / CI: override the command, e.g.
#   python -m patchpilot fix <repo-or-case> https://github.com/org/repo
#   python -m patchpilot scan /src --format sarif --output /src/patchpilot.sarif
# --port comes from $PORT (hosts such as Render and Railway assign it), default 8000
CMD ["python", "-m", "patchpilot", "serve", "--host", "0.0.0.0"]
