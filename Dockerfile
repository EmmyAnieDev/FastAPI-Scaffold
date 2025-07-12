FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system --gid 1001 fastapi && \
    adduser --system --uid 1001 --ingroup fastapi fastapi

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy Poetry files
COPY pyproject.toml poetry.lock* /app/

# Configure poetry to not use virtualenvs
RUN poetry config virtualenvs.create false

# Install dependencies without installing the project
RUN poetry install --no-interaction --no-ansi --no-root

# Copy application code
COPY . .

# Install the project itself
RUN poetry install --no-interaction --no-ansi --only-root

# Change ownership of the app directory to the fastapi user
RUN chown -R fastapi:fastapi /app

# Switch to non-root user
USER fastapi

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose the port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the app with production settings
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]