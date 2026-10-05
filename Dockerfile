FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    DATABASE_PATH=/data/sentineltrace.db THREAT_INTEL_FILE=/app/data/threat_intel.json \
    BEHIND_PROXY=1 PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY data/threat_intel.json ./data/threat_intel.json
COPY wsgi.py gunicorn.conf.py ./

# run as an unprivileged user; /data is the only writable location (mount a volume here)
RUN useradd --system --uid 10001 --home /app st && mkdir /data && chown st /data
USER st
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/healthz',timeout=3)" || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
