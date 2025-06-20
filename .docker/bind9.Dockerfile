FROM python:3.12.6-bookworm AS builder

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

RUN python -m venv .venv
RUN pip install \
    fastapi \
    uvicorn \
    pydantic \
    jinja2 \
    dnspython

FROM ubuntu/bind9:latest AS runtime

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt update 
RUN apt install -y python3.12

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

RUN ln -sf /usr/bin/python3.12 /venvs/.venv/bin/python

COPY .dns/ /server/
WORKDIR /server

RUN chown bind:bind /opt

EXPOSE 8000

ENTRYPOINT [ "./entrypoint.sh" ]
