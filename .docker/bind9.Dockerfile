FROM python:3.12.3-bookworm AS builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

RUN python -m venv .venv
RUN pip install \
    fastapi==0.115.12 \
    uvicorn==0.34.2 \
    pydantic==2.10.6 \
    jinja2==3.1.6 \
    dnspython==2.7.0

FROM ubuntu/bind9:latest AS runtime

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

RUN apt update
RUN apt install -y python3.12

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

RUN ln -sf /usr/bin/python3.12 /venvs/.venv/bin/python

COPY .dns/ /server/
WORKDIR /server

RUN chown bind:bind /opt

RUN mkdir /var/log/named && \
    touch /var/log/named/bind.log && \
    chown bind:bind /var/log/named && \
    chmod 755 /var/log/named  && \
    chmod 644 /var/log/named/bind.log

EXPOSE 8000

ENTRYPOINT [ "./entrypoint.sh" ]
