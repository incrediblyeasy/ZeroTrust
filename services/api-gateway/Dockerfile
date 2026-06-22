FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY main.py /app/main.py

RUN mkdir -p /app/shared && touch /app/shared/__init__.py

# Run as an unprivileged user (defence in depth: no root inside the container).
RUN useradd --system --uid 10001 --no-create-home appuser \
    && chown -R appuser:appuser /app

# Pre-create the audit-fallback dir owned by appuser. When the (empty) named
# volume is first mounted here, Docker copies this ownership into the volume, so
# the non-root process can write the durable fallback file. Without this the
# volume mounts as root and the fallback silently degrades to stdout.
RUN mkdir -p /var/log/ztac && chown -R appuser:appuser /var/log/ztac

USER appuser

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=15s \
  CMD curl -sf http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
