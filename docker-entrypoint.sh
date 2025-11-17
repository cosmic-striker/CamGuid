#!/bin/bash
set -e

echo "=========================================="
echo "CamGuid Application Startup"
echo "=========================================="

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
max_attempts=30
attempt=0

until pg_isready -h "${POSTGRES_HOST:-db}" -p "${POSTGRES_PORT:-5432}" -U "${POSTGRES_USER:-camguid}" 2>/dev/null; do
    attempt=$((attempt+1))
    if [ $attempt -ge $max_attempts ]; then
        echo "ERROR: PostgreSQL did not become ready in time"
        exit 1
    fi
    echo "PostgreSQL is unavailable - waiting (attempt $attempt/$max_attempts)..."
    sleep 2
done

echo "✓ PostgreSQL is ready!"

# Run database migrations
echo ""
echo "Running database migrations..."
python3 -c "
from app import app, db
from flask_migrate import upgrade
import os

with app.app_context():
    # Check if migrations directory exists
    if os.path.exists('migrations'):
        try:
            upgrade()
            print('✓ Migrations applied successfully')
        except Exception as e:
            print(f'⚠️  Migration warning: {e}')
            print('Creating tables directly...')
            db.create_all()
    else:
        print('No migrations directory found, creating tables...')
        db.create_all()
        print('✓ Database tables created')
"

# Create admin user if not exists
echo ""
echo "Checking admin user..."
python3 -c "
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import os

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        default_password = os.getenv('DEFAULT_PASSWORD', 'Admin123!')
        admin = User(
            username='admin',
            password=generate_password_hash(default_password, method='pbkdf2:sha256'),
            role='admin',
            force_password_change=True
        )
        db.session.add(admin)
        db.session.commit()
        print('✓ Admin user created')
        print(f'  Username: admin')
        print(f'  Password: {default_password}')
        print('  ⚠️  Change password on first login!')
    else:
        print('✓ Admin user already exists')
"

echo ""
echo "=========================================="
echo "Starting Gunicorn server..."
echo "=========================================="
echo ""

# Start Gunicorn
exec "$@"
