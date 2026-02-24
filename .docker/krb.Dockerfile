# The builder image, used to build the virtual environment
ARG VERSION

FROM python:3.12.6-bookworm AS builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs
COPY .kerberos/kadmin_local-0.1.1.tar.gz /

RUN python -m venv .venv
RUN pip install \
    fastapi \
    uvicorn \
    /kadmin_local-0.1.1.tar.gz


FROM ghcr.io/multidirectorylab/krb5_base:${VERSION} AS runtime

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY .kerberos/ /server/

WORKDIR /server

RUN chmod +x /server/entrypoint.sh

EXPOSE 8000
