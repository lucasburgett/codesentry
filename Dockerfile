FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir semgrep

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && uv sync --no-dev --frozen

COPY app/ app/
COPY rules/ rules/
COPY static/ static/

ENV PATH="/app/.venv/bin:$PATH"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
