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
    uv sync --locked --no-install-project --group dev

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.13.7-alpine3.21 AS runtime

WORKDIR /app
ARG VERSION

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    VERSION=${VERSION:-beta}

RUN set -eux; apk add --no-cache krb5-libs curl openssl netcat-openbsd

COPY app /app
COPY pyproject.toml /

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
RUN adduser -D md && mkdir -p /certs \
                        /LDAP_keytab \
                        /DNS_server_file \
                        /DNS_server_configs \
                        /var/spool/krb5-sync \
                        /audit \
    && chown -R md:md /app \
                    /venvs \
                    /LDAP_keytab \
                    /certs \
                    /DNS_server_file \
                    /DNS_server_configs  \
                    /var/spool/krb5-sync \
                    /audit
USER md
