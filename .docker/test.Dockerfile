FROM python:3.11-buster

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install -U pip
RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-root --no-interaction --no-ansi --with test
RUN apt-get update -y && apt-get install ldap-utils -y
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
COPY app /app
COPY tests /app/tests
COPY pyproject.toml /
