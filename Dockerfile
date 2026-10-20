# Sentrook scan service: `sentrook serve`, configured through SENTROOK_* environment variables
# (see sentrook/sentrook/serve/config.py).
#
#   docker build -t sentrook .
#   docker run --rm -p 8080:8080 -e SENTROOK_SCAN_AUTH_MODE=open sentrook

FROM ghcr.io/astral-sh/uv:0.9.9 AS uv

FROM python:3.12-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Dependencies first, so source changes reuse the layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY README.md LICENSE ./
COPY sentrook/sentrook sentrook/sentrook
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN groupadd --system --gid 10001 sentrook \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sentrook
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('SENTROOK_SCAN_PORT', '8080'), timeout=3)"]
CMD ["sentrook", "serve", "--host", "0.0.0.0"]
