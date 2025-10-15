# The builder image, used to build the virtual environment
FROM python:3.12.6-alpine3.19 AS builder

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
    uv sync --locked --no-install-project --group dev

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.12.6-alpine3.19 AS runtime

WORKDIR /app
ARG VERSION

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    VERSION=${VERSION:-beta}

RUN set -eux; apk add --no-cache \
    netcat-openbsd

COPY app /app
COPY pyproject.toml /

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
RUN adduser -D md && chown -R md:md /app /venvs
RUN mkdir /LDAP_keytab && chown -R md:md /LDAP_keytab
USER md
