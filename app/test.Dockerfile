FROM duffn/python-poetry:3.11-buster

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && poetry install --no-root --no-interaction --no-ansi --with test,linters
COPY app /app
