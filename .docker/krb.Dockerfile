# The builder image, used to build the virtual environment
ARG VERSION

FROM python:3.12.6-bookworm AS builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

RUN python -m venv .venv
RUN pip install \
    fastapi \
    uvicorn \
    https://github.com/xianglei/python-kadmv/releases/download/0.1.7/python-kadmV-0.1.7.tar.gz


FROM ghcr.io/multidirectorylab/krb5_base:${VERSION} AS runtime

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY .kerberos/config_server.py /server/
EXPOSE 8000
