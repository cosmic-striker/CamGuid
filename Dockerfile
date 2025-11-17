FROM python:3.11-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create static directory if it doesn't exist
RUN mkdir -p static

# Create instance directory for database
RUN mkdir -p instance

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

EXPOSE 5000

# Use Gunicorn for production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]