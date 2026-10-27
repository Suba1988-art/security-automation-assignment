# Build from the repository root: docker build -t vulntracker-api:local .
FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir --upgrade pip==24.3.1 \
    && pip install --no-cache-dir -r /srv/requirements.txt

COPY app/ /srv/app/
RUN useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /srv/data \
    && chown -R appuser:appuser /srv/app /srv/data

ENV DATABASE_URL=sqlite:////srv/data/vulntracker.db
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
