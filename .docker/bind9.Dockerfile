FROM ubuntu/bind9:latest AS runtime

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/venvs/ \
    PATH="/venvs/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt update 
RUN apt install -y python3.12 python3-pip python3-venv
RUN mkdir /venvs
RUN python3 -m venv /venvs
RUN /venvs/bin/pip install fastapi \
                           uvicorn \
                           pydantic \
                           jinja2 \ 
                           dnspython

COPY .dns/ /server/
EXPOSE 8000
