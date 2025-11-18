FROM python:3.11-slim-bookworm

WORKDIR /app

# Install PostgreSQL client and dependencies with retry logic
RUN set -ex; \
    for i in 1 2 3; do \
        apt-get update && \
        apt-get install -y \
            libpq-dev \
            postgresql-client \
            gcc \
            curl \
            && rm -rf /var/lib/apt/lists/* \
            && break || sleep 5; \
    done

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make entrypoint script executable
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create necessary directories
RUN mkdir -p static logs instance

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app \
    && chown app:app /docker-entrypoint.sh

USER app

EXPOSE 5000

# Use custom entrypoint for database initialization
ENTRYPOINT ["/docker-entrypoint.sh"]

# Use Gunicorn for production WSGI server with PostgreSQL optimized settings
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "60", "--worker-class", "sync", "--worker-connections", "1000", "--max-requests", "1000", "--max-requests-jitter", "100", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "app:app"]