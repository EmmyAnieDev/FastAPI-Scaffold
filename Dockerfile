# ============================
# Stage 1 — Build stage
# ============================
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build tools for compiling dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy poetry files and install dependencies
COPY pyproject.toml poetry.lock* /app/
RUN poetry config virtualenvs.create false
RUN poetry install --no-interaction --no-ansi

# Copy application code and install it (optional if you use poetry install --only-root)
COPY . .

# ============================
# Stage 2 — Runtime stage
# ============================
FROM python:3.11-slim AS runtime

# Create non-root user
RUN addgroup --system --gid 1001 fastapi && \
    adduser --system --uid 1001 --ingroup fastapi fastapi

WORKDIR /app

# Copy only installed packages and code from builder
COPY --from=builder /app /app

# Change ownership of the app directory
RUN chown -R fastapi:fastapi /app

# Switch to non-root user
USER fastapi

# Set env vars
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the app
CMD bash -c "uvicorn main:app --host 0.0.0.0 --port ${APP_PORT} --workers 4"
