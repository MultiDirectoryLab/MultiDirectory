# The builder image, used to build the virtual environment
FROM python:3.12.6-alpine3.19 AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

COPY pyproject.toml uv.lock ./

RUN set -eux; apk add --no-cache build-base krb5-dev krb5-libs libffi-dev openssl-dev libuv
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --group linters

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.12.6-alpine3.19 AS runtime

WORKDIR /app
RUN set -eux;

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY app /app
COPY pyproject.toml ./

RUN adduser -D md && chown -R md:md /app /venvs
USER md