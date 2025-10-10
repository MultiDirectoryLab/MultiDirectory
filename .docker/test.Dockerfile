# The builder image, used to build the virtual environment
FROM python:3.12.6-alpine3.19 AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_PROJECT_ENVIRONMENT=/venvs/.venv \
    UV_CACHE_DIR=/tmp/uv_cache \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

COPY pyproject.toml uv.lock ./

RUN set -eux; apk add --no-cache musl-dev krb5-libs libffi openssl libuv
RUN --mount=type=cache,target=$UV_CACHE_DIR uv sync --group test --locked --no-install-project

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.12.6-alpine3.19 AS runtime

WORKDIR /app
RUN set -eux; apk add --no-cache openldap-clients curl

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY app /app
COPY tests /app/tests
COPY pyproject.toml /
