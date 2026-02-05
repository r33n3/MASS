# Multi-stage Dockerfile for MASS
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ============================================
# Development stage
# ============================================
FROM base as development

# Copy requirements and README (needed for package metadata)
COPY pyproject.toml README.md ./

# Install dependencies (including dev dependencies)
RUN pip install -e ".[dev]"

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run with hot-reload
CMD ["uvicorn", "mass.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ============================================
# Production stage
# ============================================
FROM base as production

# Copy requirements and README (needed for package metadata)
COPY pyproject.toml README.md ./

# Install only production dependencies
RUN pip install .

# Copy application code (exclude dev files)
COPY src ./src
COPY alembic.ini ./

# Create non-root user
RUN useradd -m -u 1000 mass && \
    chown -R mass:mass /app

USER mass

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')"

# Run with gunicorn for production
CMD ["uvicorn", "mass.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
