FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY pyproject.toml README.md /app/
COPY codex_remote_server /app/codex_remote_server

RUN pip install --no-cache-dir .

RUN mkdir -p /data && chown -R app:app /app /data

USER app

EXPOSE 8787
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3).read()"

ENTRYPOINT ["codex-remote-server"]
CMD ["--host", "0.0.0.0", "--port", "8787", "--db-path", "/data/relay.sqlite3"]
