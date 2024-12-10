# The builder image, used to build the virtual environment
FROM python:3.12.6-bookworm AS builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

RUN python -m venv .venv
RUN pip install \
    fastapi \
    uvicorn \
    psycopg2-binary \
    psycopg \
    httpx \
    sqlalchemy==2.0.36


FROM python:3.12.6-slim-bookworm AS runtime
# mfa proxy server configuration

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

RUN set -eux; \
    apt-get update -y; \
    apt-get install \
    wamerican \
    libpq-dev \
    --no-install-recommends -y

RUN mkdir /server

COPY .mfa/mfa_proxy_server.py /server/
EXPOSE 8000
