FROM python:3.11-slim-trixie@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded /uv /uvx /bin/

WORKDIR /srv

COPY pyproject.toml uv.lock ./
COPY app/ ./app/

RUN uv sync --locked --no-dev --no-editable \
    && rm -rf /root/.cache/uv

FROM python:3.11-slim-trixie@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79 AS runtime

RUN groupadd -r app \
    && useradd -r -g app app \
    && rm -rf /usr/local/lib/python3.11/site-packages/pip* \
              /usr/local/lib/python3.11/site-packages/setuptools* \
              /usr/local/lib/python3.11/site-packages/wheel*

WORKDIR /srv

COPY --from=builder /srv/.venv /srv/.venv
COPY app/ ./app/

ENV PATH="/srv/.venv/bin:$PATH"

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]