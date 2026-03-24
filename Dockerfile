FROM python:3.12-slim AS base

LABEL maintainer="KubePath Contributors"
LABEL description="KubePath — Autonomous Cloud/K8s Lateral Movement Mapper"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY kubepath/ ./kubepath/
COPY frontend/ ./frontend/

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run the application
CMD ["uvicorn", "kubepath.main:app", "--host", "0.0.0.0", "--port", "8000"]
