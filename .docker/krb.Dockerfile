# The builder image, used to build the virtual environment
FROM python:3.12.4-bookworm as builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

RUN python -m venv .venv
RUN pip install \
    fastapi \
    uvicorn \
    https://github.com/xianglei/python-kadmv/releases/download/0.1.7/python-kadmV-0.1.7.tar.gz


FROM python:3.12.4-slim-bookworm as runtime
# kerberos server configuration

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf \
    KRB5_TRACE=/dev/stdout \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

RUN set -eux; \
    apt-get update -y; \
    apt-get install \
    krb5-kdc-ldap \
    krb5-pkinit \
    krb5-admin-server \
    wamerican \
    libsasl2-modules-gssapi-mit \
    --no-install-recommends -y

RUN rm -rf /var/lib/krb5kdc/principal;\
    mkdir -pv /var/kerberos/krb5kdc/principal;\
    mkdir -pv /var/log/kerberos/ \
    mkdir /etc/krb5.d \
    mkdir /etc/krb5kdc/ \
    chmod u=rwx,g=,o= /etc/krb5.d \
    touch /var/log/kerberos/krb5.log;\
    touch /var/log/kerberos/kadmin.log;\
    touch /var/log/kerberos/krb5lib.log;\
    mkdir /server;\
    mkdir /certs;\
    touch /etc/krb5.conf;\
    touch /etc/kdc.conf;

COPY .kerberos/config_server.py /server/
EXPOSE 8000
