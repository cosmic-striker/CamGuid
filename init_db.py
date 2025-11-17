#!/usr/bin/env python3
"""
Database initialization script for PostgreSQL migration.
This script handles database creation and initial setup.
"""

import os
import sys
import time
from app import app, db
from models import User, Camera, Event, AuditLog, CameraGroup
from werkzeug.security import generate_password_hash

def wait_for_db(max_retries=30, delay=2):
    """Wait for database to be ready"""
    from sqlalchemy import text
    
    print("Waiting for database to be ready...")
    for i in range(max_retries):
        try:
            with app.app_context():
                db.session.execute(text('SELECT 1'))
                print("✓ Database is ready!")
                return True
        except Exception as e:
            if i < max_retries - 1:
                print(f"Database not ready yet (attempt {i+1}/{max_retries}): {e}")
                time.sleep(delay)
            else:
                print(f"✗ Failed to connect to database after {max_retries} attempts")
                return False
    return False

def init_database():
    """Initialize database schema"""
    print("\n" + "="*60)
    print("CamGuid Database Initialization")
    print("="*60 + "\n")
    
    with app.app_context():
        # Wait for database
        if not wait_for_db():
            print("✗ Database initialization failed - database not available")
            sys.exit(1)
        
        try:
            # Drop all tables if they exist (use with caution!)
            if os.getenv('DROP_EXISTING_TABLES', 'False').lower() == 'true':
                print("⚠️  Dropping existing tables...")
                db.drop_all()
                print("✓ Existing tables dropped")
            
            # Create all tables
            print("Creating database tables...")
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Create default admin user
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                print("\nCreating default admin user...")
                default_password = os.getenv('ADMIN_DEFAULT_PASSWORD', 'Admin123!')
                admin = User(
                    username='admin',
                    password=generate_password_hash(default_password, method='pbkdf2:sha256'),
                    role='admin',
                    force_password_change=True
                )
                db.session.add(admin)
                db.session.commit()
                
                print("✓ Default admin user created")
                print(f"  Username: admin")
                print(f"  Password: {default_password}")
                print("  ⚠️  You will be required to change this password on first login!")
            else:
                print("\n✓ Admin user already exists")
            
            # Verify database setup
            print("\nVerifying database setup...")
            user_count = User.query.count()
            camera_count = Camera.query.count()
            
            print(f"✓ Users: {user_count}")
            print(f"✓ Cameras: {camera_count}")
            
            print("\n" + "="*60)
            print("Database initialization completed successfully!")
            print("="*60 + "\n")
            print("Next steps:")
            print("  1. Start the application: docker-compose up -d")
            print("  2. Access at: http://localhost:5000")
            print("  3. Login with admin credentials")
            print("  4. Change default password immediately")
            print("\n")
            
            return True
            
        except Exception as e:
            print(f"\n✗ Error during database initialization: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    success = init_database()
    sys.exit(0 if success else 1)
