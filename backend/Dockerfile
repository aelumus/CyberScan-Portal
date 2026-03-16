FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /tmp/requirements.txt

RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

COPY backend /app/backend
COPY Malware-Detection-and-Analysis-using-Machine-Learning-main/ML_model /app/Malware-Detection-and-Analysis-using-Machine-Learning-main/ML_model

RUN useradd --create-home --uid 10001 appuser && \
    mkdir -p /app/backend/uploads /app/data/uploads && \
    chown -R appuser:appuser /app

WORKDIR /app/backend

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]