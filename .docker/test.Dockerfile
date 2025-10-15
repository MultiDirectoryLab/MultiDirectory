# The builder image, used to build the virtual environment
FROM python:3.13.7-alpine3.21 AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

COPY pyproject.toml uv.lock ./

RUN set -eux; apk add --no-cache \
    musl-dev \
    krb5-dev \
    libffi-dev \
    openssl-dev \
    libuv \
    gcc

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --group test

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.13.7-alpine3.21 AS runtime

WORKDIR /app
RUN set -eux; apk add --no-cache openldap-clients openssl curl krb5-libs

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY app /app
COPY tests /app/tests
COPY pyproject.toml /

RUN adduser -D md && chown -R md:md /app /venvs
RUN mkdir -p /app/.pytest_cache && chown -R md:md /app/.pytest_cache
USER md