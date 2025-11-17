"""
Database models for Camera Dashboard
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import base64

db = SQLAlchemy()

# Simple encryption for camera credentials (temporary - replace with proper encryption later)
def simple_encrypt(text):
    """Simple base64 encoding for now - replace with proper encryption"""
    if not text:
        return ""
    return base64.b64encode(text.encode()).decode()

def simple_decrypt(encoded_text):
    """Simple base64 decoding for now - replace with proper decryption"""
    if not encoded_text:
        return ""
    try:
        return base64.b64decode(encoded_text.encode()).decode()
    except:
        return ""

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='viewer')  # admin, operator, viewer
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)
    force_password_change = db.Column(db.Boolean, default=False)

class Camera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(15), nullable=False, index=True)
    url = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(100), default='default', index=True)
    status = db.Column(db.String(20), default='online', index=True)
    latitude = db.Column(db.Float, default=0.0)
    longitude = db.Column(db.Float, default=0.0)
    # Separate credential storage (encrypted in production)
    username = db.Column(db.String(100), nullable=True)
    password_encrypted = db.Column(db.Text, nullable=True)  # Encrypted password
    port = db.Column(db.Integer, default=554)

    def set_credentials(self, username, password):
        """Store camera credentials securely using encryption"""
        self.username = username
        if password:
            # Encrypt the password (temporary simple encryption)
            self.password_encrypted = simple_encrypt(password)

    def get_decrypted_password(self):
        """Decrypt and return the camera password"""
        if self.password_encrypted:
            try:
                return simple_decrypt(self.password_encrypted)
            except Exception:
                return None
        return None

    def get_rtsp_url(self):
        """Generate RTSP URL without exposing credentials in logs"""
        password = self.get_decrypted_password()
        if password:
            return f'rtsp://{self.username}:{password}@{self.ip}:{self.port}/stream'
        else:
            return f'rtsp://{self.ip}:{self.port}/stream'

class Event(db.Model):
    """Event logging for camera events"""
    id = db.Column(db.Integer, primary_key=True)
    camera_id = db.Column(db.Integer, db.ForeignKey('camera.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # motion, face, intrusion, etc.
    severity = db.Column(db.String(20), default='info', index=True)  # info, warning, critical
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: db.func.current_timestamp(), index=True)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class AuditLog(db.Model):
    """Audit trail for user actions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: db.func.current_timestamp(), index=True)
    details = db.Column(db.Text, nullable=True)

class CameraGroup(db.Model):
    """Camera groups for organization"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    icon = db.Column(db.String(50), default='fa-layer-group')
    created_at = db.Column(db.DateTime, default=lambda: db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=lambda: db.func.current_timestamp(), onupdate=lambda: db.func.current_timestamp())

    # Relationship with cameras (many-to-many)
    cameras = db.relationship('Camera', secondary='camera_group_association', backref=db.backref('groups', lazy='dynamic'))

# Association table for many-to-many relationship
camera_group_association = db.Table('camera_group_association',
    db.Column('camera_id', db.Integer, db.ForeignKey('camera.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('camera_group.id'), primary_key=True)
)
