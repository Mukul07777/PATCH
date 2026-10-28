FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# Serverless Endpoint: web app + API.  Serverless Job: override the command with
#   python -m patchpilot.cli demo_repo https://github.com/org/repo
CMD ["uvicorn", "patchpilot.server:app", "--host", "0.0.0.0", "--port", "8000"]
