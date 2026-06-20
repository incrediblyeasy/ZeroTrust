FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY main.py /app/main.py

RUN mkdir -p /app/shared && touch /app/shared/__init__.py

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=15s \
  CMD curl -sf http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
