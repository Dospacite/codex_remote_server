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

ENTRYPOINT ["codex-remote-server"]
CMD ["--host", "0.0.0.0", "--port", "8787", "--db-path", "/data/relay.sqlite3", "--public-base-url", "https://relay.example.com"]
