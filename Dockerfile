FROM python:3.11-slim

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 依赖
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev

# 源码
COPY config/ ./config/
COPY src/engine/ ./src/engine/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -sf http://127.0.0.1:8000/health || exit 1

CMD ["uv", "run", "uvicorn", "src.engine.server:app", "--host", "0.0.0.0", "--port", "8000"]
