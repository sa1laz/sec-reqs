# Образ только с кодом: данные (cis.db, индекс HF) — на томе /data, в образ не попадают
# (тексты CIS — CC BY-NC-SA, датасет HF — gated).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SECREQS_DATA=/data CIS_DB=/data/cis.db \
    SECREQS_TRANSPORT=http SECREQS_HOST=0.0.0.0 SECREQS_PORT=8000

RUN pip install --no-cache-dir mcp==2.3.0 pyyaml==6.0.3 && useradd -u 10001 -m app && mkdir /data && chown app /data

WORKDIR /app
COPY secreqs/ secreqs/
COPY run_mcp.py ./

USER 10001
EXPOSE 8000
VOLUME /data
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["python", "run_mcp.py"]
