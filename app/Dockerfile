FROM python:3.11-buster

RUN apt-get install openssl
RUN mkdir -p /certs
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-root --no-interaction --no-ansi --without test,linters
COPY app /app
