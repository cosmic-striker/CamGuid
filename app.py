import os
import csv
import json
import threading
import socket
import time
import logging
import re
import secrets
import ipaddress
from functools import wraps
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User, Camera, Event, AuditLog, CameraGroup

# Import cv2 and numpy for video processing (installed via requirements.txt)
try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logging.warning("OpenCV not available - video streaming will use placeholder images")

load_dotenv()

# Load configuration from environment variables
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', 5000))
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
IP_RANGE = os.getenv('IP_RANGE', '192.168.1.0/24')
PORT = int(os.getenv('PORT', 554))
DEFAULT_USERNAME = os.getenv('DEFAULT_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('DEFAULT_PASSWORD')

# Generate secure SECRET_KEY if not provided
def get_or_create_secret_key():
    secret_file = 'instance/secret.key'
    if os.path.exists(secret_file):
        with open(secret_file, 'r') as f:
            return f.read().strip()
    else:
        os.makedirs('instance', exist_ok=True)
        secret_key = secrets.token_hex(32)
        with open(secret_file, 'w') as f:
            f.write(secret_key)
        return secret_key

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', get_or_create_secret_key())

# PostgreSQL Configuration
# Format: postgresql://user:password@host:port/database
# Default to PostgreSQL in production, SQLite for development fallback
default_db_uri = os.getenv('DATABASE_URL', os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://camguid:camguid_password@db:5432/camguid'))
app.config['SQLALCHEMY_DATABASE_URI'] = default_db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
    'max_overflow': 20
}
app.config['WTF_CSRF_ENABLED'] = os.getenv('WTF_CSRF_ENABLED', 'True').lower() == 'true'
app.config['WTF_CSRF_TIME_LIMIT'] = int(os.getenv('WTF_CSRF_TIME_LIMIT', 3600))
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']

# Session security
from datetime import datetime, timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 7200)))
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

# Request size limit (16MB)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))

csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access"""
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('login'))

# Initialize database with app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Configure logging
import logging
from logging.handlers import RotatingFileHandler

log_level = os.getenv('LOG_LEVEL', 'WARNING').upper()
numeric_level = getattr(logging, log_level, logging.WARNING)

# Create rotating file handler (max 10MB per file, keep 5 backup files)
log_file = os.getenv('LOG_FILE', 'camera_dashboard.log')
rotating_handler = RotatingFileHandler(
    log_file,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
rotating_handler.setLevel(numeric_level)
rotating_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=numeric_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        rotating_handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rate limiting (requires Flask-Limiter - install with: pip install Flask-Limiter)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[os.getenv('RATELIMIT_DEFAULT', "200 per day, 50 per hour")],
        storage_uri=os.getenv('RATELIMIT_STORAGE_URL', "memory://")
    )
except ImportError:
    limiter = None
    logger.warning('Flask-Limiter not installed. Rate limiting disabled.')



def log_audit(action, resource=None, resource_id=None, details=None):
    """Helper function to log audit events"""
    try:
        audit = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:200] if request.user_agent else None,
            details=details
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        logger.error(f'Audit logging failed: {e}')
        db.session.rollback()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Security headers
@app.after_request
def set_secure_headers(response):
    """Add security headers to all responses"""
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # HTTPS Strict Transport Security (only if HTTPS is enabled)
    if request.url.startswith('https://'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Remove server header
    response.headers.pop('Server', None)

    return response

# RBAC Decorators
def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    """Decorator to require operator or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role not in ['admin', 'operator']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Validation Functions
def validate_password(password):
    """Validate password complexity"""
    if not isinstance(password, str):
        return False, "Password must be a string"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_ip_address(ip_str):
    """Validate IP address format"""
    if not isinstance(ip_str, str) or not ip_str.strip():
        return False, "IP address is required"
    try:
        ipaddress.ip_address(ip_str.strip())
        return True, "Valid IP address"
    except ValueError:
        return False, "Invalid IP address format"

def validate_port(port):
    """Validate port number"""
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True, "Valid port"
        return False, "Port must be between 1 and 65535"
    except (ValueError, TypeError):
        return False, "Invalid port number"

def validate_username(username):
    """Validate username"""
    if not isinstance(username, str) or not username.strip():
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username contains invalid characters"
    return True, "Username is valid"

def sanitize_string(input_str, max_length=255):
    """Sanitize string input"""
    if not isinstance(input_str, str):
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>]', '', input_str.strip())
    return sanitized[:max_length] if max_length else sanitized

def create_admin_user():
    try:
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            # Create default admin user with secure initial password
            default_password = "Admin123!"
            hashed_password = generate_password_hash(default_password, method='pbkdf2:sha256')
            admin = User(
                username='admin',
                password=hashed_password,
                role='admin',
                force_password_change=True  # Force password change on first login
            )
            db.session.add(admin)
            db.session.commit()
            
            logger.warning('=' * 80)
            logger.warning('DEFAULT ADMIN USER CREATED')
            logger.warning(f'Username: admin')
            logger.warning(f'Default Password: {default_password}')
            logger.warning('PLEASE CHANGE THIS PASSWORD ON FIRST LOGIN!')
            logger.warning('=' * 80)
            
            # Save to file for first-time setup
            os.makedirs('instance', exist_ok=True)
            with open('instance/admin_credentials.txt', 'w') as f:
                f.write(f'Default Admin Credentials:\n')
                f.write(f'Username: admin\n')
                f.write(f'Password: {default_password}\n')
                f.write('\nIMPORTANT: Change this password immediately after first login!\n')
                f.write('DELETE THIS FILE AFTER CHANGING PASSWORD\n')
    except Exception as e:
        logger.error(f'Error checking/creating admin user: {e}')
        db.session.rollback()

def scan_network(start_ip, end_ip, port, timeout=1.0):
    """Scan network range for devices
    Args:
        start_ip: Starting IP address (e.g., '192.168.1.1')
        end_ip: Ending IP address (e.g., '192.168.1.254')
        port: Port to scan (0 or None for auto-detect common ports)
        timeout: Connection timeout in seconds
    """
    global scan_status
    cameras_found = 0
    
    # Validate IP addresses
    is_valid_start, msg_start = validate_ip_address(start_ip)
    is_valid_end, msg_end = validate_ip_address(end_ip)
    
    if not is_valid_start:
        logger.error(f'Invalid start IP: {start_ip}')
        return 0
    if not is_valid_end:
        logger.error(f'Invalid end IP: {end_ip}')
        return 0
    
    # Support multi-port scanning if port is 0 or None
    ports_to_scan = []
    if port is None or port == 0:
        # Common camera/device ports
        ports_to_scan = [554, 37777, 8000, 80, 8080, 8888, 7001, 7002]
        logger.warning(f'No specific port provided, scanning common ports: {ports_to_scan}')
    else:
        is_valid_port, msg_port = validate_port(port)
        if not is_valid_port:
            logger.error(f'Invalid port: {port}')
            return 0
        ports_to_scan = [int(port)]
    
    # Parse IP addresses
    start_parts = [int(p) for p in start_ip.split('.')]
    end_parts = [int(p) for p in end_ip.split('.')]
    
    logger.warning(f'Starting network scan from {start_ip} to {end_ip} on ports {ports_to_scan} with timeout {timeout}s. DEFAULT_PASSWORD set: {bool(DEFAULT_PASSWORD)}')
    
    # Generate IP list to scan
    ips_to_scan = []
    
    # Simple case: same network, different last octet
    if start_parts[:3] == end_parts[:3]:
        for i in range(start_parts[3], end_parts[3] + 1):
            ips_to_scan.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
    else:
        # Complex case: different networks
        for oct1 in range(start_parts[0], end_parts[0] + 1):
            for oct2 in range(start_parts[1] if oct1 == start_parts[0] else 0,
                            end_parts[1] + 1 if oct1 == end_parts[0] else 256):
                for oct3 in range(start_parts[2] if oct1 == start_parts[0] and oct2 == start_parts[1] else 0,
                                end_parts[2] + 1 if oct1 == end_parts[0] and oct2 == end_parts[1] else 256):
                    for oct4 in range(start_parts[3] if oct1 == start_parts[0] and oct2 == start_parts[1] and oct3 == start_parts[2] else 0,
                                    end_parts[3] + 1 if oct1 == end_parts[0] and oct2 == end_parts[1] and oct3 == end_parts[2] else 256):
                        ips_to_scan.append(f"{oct1}.{oct2}.{oct3}.{oct4}")
    
    scan_status['total'] = len(ips_to_scan) * len(ports_to_scan)
    scan_status['found'] = 0
    total_found = 0  # Track all devices found (new + existing)
    scan_count = 0  # Track scan progress
    
    logger.info(f'Scanning {len(ips_to_scan)} IP addresses from {start_ip} to {end_ip} on {len(ports_to_scan)} port(s): {ports_to_scan}')
    
    # Scan each IP on each port
    for idx, ip in enumerate(ips_to_scan):
        # Check if scan should stop
        if not scan_status['running']:
            logger.info('Scan stopped by user request')
            break
        
        device_found_on_ip = False
        found_port = None
        
        for scan_port in ports_to_scan:
            # Check if scan should stop
            if not scan_status['running']:
                break
                
            scan_count += 1
            scan_status['progress'] = scan_count
            
            # Log progress every 10%
            if scan_status['total'] > 10 and scan_count % max(1, scan_status['total'] // 10) == 0:
                percentage = int((scan_count / scan_status['total']) * 100)
                logger.warning(f'Scan progress: {percentage}% ({scan_count}/{scan_status["total"]})')
            
            # Skip remaining ports if device already found on this IP
            if device_found_on_ip:
                continue
            
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)  # Use configurable timeout
                result = sock.connect_ex((ip, int(scan_port)))
                
                if result == 0:
                    # Device found, check if camera already exists
                    existing = Camera.query.filter_by(ip=ip).first()
                    if not existing:
                        # CRITICAL SECURITY: Only add camera if we have credentials
                        if DEFAULT_PASSWORD is None or DEFAULT_PASSWORD == '':
                            logger.warning(f'Cannot add camera {ip}:{scan_port}: No DEFAULT_PASSWORD configured (is empty)')
                            sock.close()
                            device_found_on_ip = True
                            found_port = scan_port
                            continue
                        
                        # Create camera with basic info (without credentials in URL)
                        camera = Camera(
                            name=f'Camera {ip}',
                            ip=ip,
                            port=int(scan_port),
                            url=f'rtsp://{ip}:{scan_port}/stream',  # URL without credentials
                            location='default',
                            status='online'
                        )
                        # Store credentials securely using the encryption method
                        camera.set_credentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
                        db.session.add(camera)
                        cameras_found += 1
                        logger.warning(f"Found new device at {ip}:{scan_port} - added to database with credentials")
                    else:
                        existing.status = 'online'
                        existing.port = int(scan_port)
                        # Update credentials if they're missing
                        if not existing.password_encrypted and DEFAULT_PASSWORD:
                            existing.set_credentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
                            logger.warning(f"Updated existing device at {ip}:{scan_port} and added credentials")
                        else:
                            logger.warning(f"Updated existing device at {ip}:{scan_port}")
                    
                    # Mark device as found and record port
                    device_found_on_ip = True
                    found_port = scan_port
                    
                    # Increment total found count
                    total_found += 1
                    scan_status['found'] = total_found
                    
                    # Commit after each device found to ensure data is saved
                    try:
                        db.session.commit()
                    except Exception as e:
                        logger.error(f"Database error saving {ip}: {e}")
                        db.session.rollback()
                
            except socket.timeout:
                logger.debug(f"Timeout scanning {ip}:{scan_port}")
            except Exception as e:
                logger.debug(f"Error scanning {ip}:{scan_port}: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                # Small delay to prevent overwhelming the network
                time.sleep(0.01)
    
    # Final commit for any remaining changes
    try:
        db.session.commit()
        logger.warning(f'Network scan completed. Scanned {scan_status["progress"]}/{scan_status["total"]} addresses. Found {scan_status["found"]} devices ({cameras_found} new).')
    except Exception as e:
        logger.error(f"Database error during scan: {e}")
        db.session.rollback()
    
    return cameras_found

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") if limiter else lambda f: f
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Sanitize inputs
            username = sanitize_string(username, 50)
            password = sanitize_string(password, 128)
            
            # Validate inputs
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('login.html')
            
            # Validate username format
            is_valid_username, username_msg = validate_username(username)
            if not is_valid_username:
                flash(username_msg, 'error')
                logger.warning(f'Invalid username format attempt: {username}')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user:
                # Check if account is locked
                if user.failed_login_attempts >= 5:
                    flash('Account locked due to too many failed login attempts. Contact administrator.', 'error')
                    logger.warning(f'Locked account login attempt: {username}')
                    return render_template('login.html')
                
                if not user.is_active:
                    flash('Account is disabled', 'error')
                    return render_template('login.html')
                
                if check_password_hash(user.password, password):
                    # Reset failed attempts and update last login
                    user.failed_login_attempts = 0
                    user.last_login = datetime.utcnow()
                    
                    try:
                        db.session.commit()
                    except Exception as commit_error:
                        logger.error(f'Database commit error during login: {commit_error}')
                        db.session.rollback()
                    
                    # Log the user in
                    login_user(user, remember=request.form.get('remember', False))
                    logger.info(f'User {username} (role: {user.role}) logged in successfully. Force password change: {user.force_password_change}')
                    
                    # Check if password change is required
                    if user.force_password_change:
                        flash('You must change your password before continuing', 'warning')
                        return redirect(url_for('change_password'))
                    
                    return redirect(url_for('dashboard'))
                else:
                    # Increment failed attempts
                    user.failed_login_attempts += 1
                    db.session.commit()
                    logger.warning(f'Failed login attempt for user: {username} (attempt {user.failed_login_attempts})')
                    flash('Invalid username or password', 'error')
            else:
                logger.warning(f'Failed login attempt for non-existent user: {username}')
                flash('Invalid username or password', 'error')
        except Exception as e:
            logger.error(f'Login error: {e}')
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        try:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([new_password, confirm_password]):
                flash('New password and confirmation are required', 'error')
                return render_template('change_password.html')
            
            # Only check current password if not forced to change (i.e., not first login)
            if not current_user.force_password_change:
                if not current_password:
                    flash('Current password is required', 'error')
                    return render_template('change_password.html')
                if not check_password_hash(current_user.password, current_password):
                    flash('Current password is incorrect', 'error')
                    return render_template('change_password.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('change_password.html')
            
            # Validate password complexity
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, 'error')
                return render_template('change_password.html')
            
            # Update password and remove force change flag
            current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            current_user.force_password_change = False
            
            # Ensure changes are committed
            try:
                db.session.commit()
                logger.info(f'Password changed successfully for user: {current_user.username}')
                flash('Password changed successfully! You can now access the dashboard.', 'success')
                return redirect(url_for('dashboard'))
            except Exception as commit_error:
                db.session.rollback()
                logger.error(f'Database commit error while changing password: {commit_error}')
                flash('Error saving new password. Please try again.', 'error')
                return render_template('change_password.html')
        except Exception as e:
            logger.error(f'Error changing password: {e}')
            db.session.rollback()
            flash('An error occurred while changing password', 'error')
    
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    try:
        total_cameras = Camera.query.count()
        online_cameras = Camera.query.filter_by(status='online').count()
        offline_cameras = Camera.query.filter_by(status='offline').count()
        
        recent_cameras = Camera.query.order_by(Camera.id.desc()).limit(6).all()
        locations = db.session.query(Camera.location, db.func.count(Camera.id)).group_by(Camera.location).all()
        
        return render_template('dashboard_new.html',
            total_cameras=total_cameras,
            online_cameras=online_cameras,
            offline_cameras=offline_cameras,
            recent_cameras=recent_cameras,
            locations=locations
        )
    except Exception as e:
        logger.error(f'Dashboard error: {e}')
        flash('Error loading dashboard', 'error')
        return render_template('dashboard_new.html',
            total_cameras=0,
            online_cameras=0,
            offline_cameras=0,
            recent_cameras=[],
            locations=[]
        )

@app.route('/live-view')
@login_required
def live_view():
    try:
        # Get all cameras (limit to reasonable number for live view)
        cameras = Camera.query.order_by(Camera.status.desc(), Camera.name).limit(16).all()
        
        # Get unique locations for filtering
        locations = db.session.query(Camera.location).distinct().all()
        locations = sorted([loc[0] for loc in locations if loc[0]])
        
        return render_template('live_view_improved.html', 
                             cameras=cameras, 
                             locations=locations)
    except Exception as e:
        logger.error(f'Live View error: {e}')
        flash('Error loading live view', 'error')
        return render_template('live_view_improved.html', cameras=[], locations=[])

@app.route('/access-control')
@login_required
def access_control():
    return render_template('access_control.html')

@app.route('/video-wall')
@login_required
def video_wall():
    cameras = Camera.query.all()
    return render_template('video_wall.html', cameras=cameras)

@app.route('/allcam')
@login_required
def allcam():
    """All cameras with auto-rotation view"""
    return render_template('allcam.html')

@app.route('/events')
@login_required
def events():
    return render_template('events_improved.html')

@app.route('/attendance')
@login_required
def attendance():
    return render_template('attendance.html')

@app.route('/playback')
@login_required
def playback():
    cameras = Camera.query.all()
    return render_template('playback.html', cameras=cameras)

@app.route('/people-counting')
@login_required
def people_counting():
    return render_template('people_counting.html')

@app.route('/heat-map')
@login_required
def heat_map():
    cameras = Camera.query.all()
    return render_template('heat_map.html', cameras=cameras)

@app.route('/logs')
@login_required
def logs():
    return render_template('logs_improved.html')

@app.route('/devices')
@login_required
def devices():
    cameras = Camera.query.all()
    return render_template('devices_improved.html', cameras=cameras)

@app.route('/device-config/<int:device_id>')
@login_required
def device_config(device_id):
    camera = Camera.query.get_or_404(device_id)
    return render_template('device_config.html', camera=camera)

@app.route('/tour-task')
@login_required
def tour_task():
    cameras = Camera.query.all()
    return render_template('tour_task.html', cameras=cameras)

@app.route('/camera')
@login_required
def camera_scan():
    """Network scanner page"""
    return render_template('scan_improved.html')

# Global variable to track scan status
scan_status = {'running': False, 'progress': 0, 'total': 0, 'found': 0}

@app.route('/scan', methods=['POST'])
@login_required
@operator_required
def scan():
    global scan_status
    if scan_status['running']:
        return jsonify({'success': False, 'message': 'Scan already in progress'}), 400
    
    # Get custom IP range from request
    data = request.get_json() if request.is_json else {}
    
    # Support both formats: segmented IPs or simple IP range
    if 'start_ip' in data and 'end_ip' in data:
        start_ip = data['start_ip']
        end_ip = data['end_ip']
    elif 'ip_range' in data:
        # Parse from old format
        ip_range = data['ip_range']
        base_ip = '.'.join(ip_range.split('.')[:3])
        start_ip = f"{base_ip}.1"
        end_ip = f"{base_ip}.254"
    else:
        # Use default
        base_ip = '.'.join(IP_RANGE.split('.')[:3])
        start_ip = f"{base_ip}.1"
        end_ip = f"{base_ip}.254"
    
    custom_port = data.get('port', PORT)
    custom_timeout = data.get('timeout', 1.0)
    
    # Validate inputs
    is_valid_start, msg_start = validate_ip_address(start_ip)
    is_valid_end, msg_end = validate_ip_address(end_ip)
    
    if not is_valid_start:
        return jsonify({'success': False, 'message': f'Invalid start IP: {msg_start}'}), 400
    if not is_valid_end:
        return jsonify({'success': False, 'message': f'Invalid end IP: {msg_end}'}), 400
    
    # Allow port 0 for multi-port scanning
    if custom_port != 0:
        is_valid_port, msg_port = validate_port(custom_port)
        if not is_valid_port:
            return jsonify({'success': False, 'message': f'Invalid port: {msg_port}'}), 400
    
    # Validate timeout
    try:
        custom_timeout = float(custom_timeout)
        if custom_timeout < 0.1 or custom_timeout > 10.0:
            return jsonify({'success': False, 'message': 'Timeout must be between 0.1 and 10 seconds'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid timeout value'}), 400
    
    logger.info(f'Scan requested by {current_user.username}: {start_ip} to {end_ip} on port {custom_port}')
    
    def scan_async():
        ctx = app.app_context()
        ctx.push()
        try:
            scan_status['running'] = True
            scan_status['progress'] = 0
            scan_status['total'] = 0  # Will be set by scan_network
            scan_status['found'] = 0
            scan_network(start_ip, end_ip, custom_port, custom_timeout)
        except Exception as e:
            logger.error(f"Scan error: {e}")
        finally:
            scan_status['running'] = False
            ctx.pop()
    
    threading.Thread(target=scan_async, daemon=True).start()
    return jsonify({'success': True, 'message': 'Scan started'}), 200

@app.route('/scan_status', methods=['GET'])
@limiter.exempt if limiter else lambda f: f
@login_required
def scan_status_endpoint():
    return jsonify(scan_status)

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Test endpoint"""
    return jsonify({"message": "test works"})

@app.route('/api/scan_status', methods=['GET'])
@limiter.exempt if limiter else lambda f: f
def api_scan_status():
    """Public endpoint for scan status polling (no auth required for real-time updates)"""
    return jsonify(scan_status)

@app.route('/stop_scan', methods=['POST'])
@login_required
def stop_scan():
    """Stop the ongoing network scan"""
    global scan_status
    try:
        if scan_status['running']:
            scan_status['running'] = False
            logger.info(f'Network scan stopped by {current_user.username}')
            return jsonify({'success': True, 'message': 'Scan stopped successfully'})
        else:
            return jsonify({'success': False, 'message': 'No scan is currently running'})
    except Exception as e:
        logger.error(f'Error stopping scan: {str(e)}')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/discovered_devices', methods=['GET'])
@login_required
def get_discovered_devices():
    """Get list of discovered devices during scan"""
    try:
        cameras = Camera.query.all()
        devices = []
        for cam in cameras:
            # Generate MAC address based on IP (for display purposes)
            ip_parts = cam.ip.split('.')
            if len(ip_parts) == 4:
                mac = f"{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}:79:ad:c5:{int(ip_parts[3]):02x}"
            else:
                mac = "00:00:00:00:00:00"
            
            devices.append({
                'id': cam.id,
                'ip': cam.ip,
                'name': cam.name,
                'device_type': 'IPC' if 'IPC' in cam.name or 'Camera' in cam.name else 'NVR',
                'mac_address': mac,
                'port': PORT,
                'status': cam.status,
                'model': 'IPC-HFW2431S-S-S2' if 'IPC' in cam.name else 'DHI-NVR411',
                'channel': '1/0/0' if 'IPC' in cam.name else '16/0/2'
            })
        
        return jsonify({'devices': devices})
    except Exception as e:
        logger.error(f'Error getting discovered devices: {e}')
        return jsonify({'error': str(e)}), 500

from flask_swagger_ui import get_swaggerui_blueprint
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Swagger UI setup
SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Camera Dashboard API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
REQUEST_COUNT = Counter('flask_requests_total', 'Total number of requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('flask_request_duration_seconds', 'Request duration in seconds', ['method', 'endpoint'])
CAMERA_COUNT = Gauge('camera_total', 'Total number of cameras')
CAMERA_ONLINE_COUNT = Gauge('camera_online_total', 'Number of online cameras')
CAMERA_OFFLINE_COUNT = Gauge('camera_offline_total', 'Number of offline cameras')
DB_CONNECTION_COUNT = Gauge('db_connections_active', 'Number of active database connections')

@app.before_request
def before_request():
    """Track request start time for latency measurement"""
    request.start_time = time.time()

@app.after_request
def after_request(response):
    """Track request metrics after completion"""
    try:
        # Calculate request duration
        duration = time.time() - getattr(request, 'start_time', time.time())
        
        # Get endpoint name (simplified)
        endpoint = request.endpoint or 'unknown'
        
        # Update metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status=str(response.status_code)
        ).inc()
        
        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=endpoint
        ).observe(duration)
        
    except Exception as e:
        logger.debug(f'Failed to update request metrics: {e}')
    
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connectivity
        camera_count = Camera.query.count()
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'cameras': camera_count,
            'timestamp': time.time()
        }), 200
    except Exception as e:
        logger.error(f'Health check failed: {e}')
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': time.time()
        }), 500

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    try:
        # Update camera metrics
        total_cameras = Camera.query.count()
        online_cameras = Camera.query.filter_by(status='online').count()
        offline_cameras = Camera.query.filter_by(status='offline').count()
        
        CAMERA_COUNT.set(total_cameras)
        CAMERA_ONLINE_COUNT.set(online_cameras)
        CAMERA_OFFLINE_COUNT.set(offline_cameras)
        
        # Update database connection metrics (simplified)
        DB_CONNECTION_COUNT.set(1)  # In a real app, you'd track actual connection pool
        
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
    except Exception as e:
        logger.error(f'Metrics collection failed: {e}')
        return 'Metrics collection failed', 500

@app.route('/camera/<int:camera_id>')
@login_required
def camera(camera_id):
    cam = Camera.query.get_or_404(camera_id)
    return render_template('camera.html', camera=cam)

@app.route('/update_location/<int:camera_id>', methods=['POST'])
@login_required
def update_location(camera_id):
    cam = Camera.query.get_or_404(camera_id)
    new_location = request.form.get('location') or request.get_json().get('location') if request.is_json else None
    if new_location:
        cam.location = new_location
        db.session.commit()
        flash('Location updated successfully', 'success')
        return jsonify({'success': True}), 200
    return jsonify({'success': False}), 400

@app.route('/video_feed/<int:camera_id>')
@login_required
def video_feed(camera_id):
    cam = Camera.query.get_or_404(camera_id)
    # Use get_rtsp_url() to include credentials in the stream URL
    rtsp_url = cam.get_rtsp_url()
    return Response(generate_frames(rtsp_url), mimetype='multipart/x-mixed-replace; boundary=frame')

def generate_frames(rtsp_url):
    """Generate video frames from RTSP stream"""
    import io
    import cv2
    
    # Try to open the video stream
    cap = None
    try:
        logger.info(f"Attempting to connect to camera: {rtsp_url}")
        cap = cv2.VideoCapture(rtsp_url)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # Reduce buffer size for lower latency
        
        # Try to get credentials from URL if available
        if not cap.isOpened():
            logger.warning(f"Failed to open stream: {rtsp_url}")
            # Create placeholder image
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (640, 480), color=(64, 64, 64))
            draw = ImageDraw.Draw(img)
            draw.text((180, 220), 'Camera Connection Failed', fill=(255, 100, 100))
            draw.text((200, 250), 'Check camera credentials', fill=(200, 200, 200))
            
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG')
            frame_bytes = img_byte_arr.getvalue()
            
            while True:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                time.sleep(1)
        
        # Stream frames
        frame_count = 0
        while True:
            success, frame = cap.read()
            
            if not success:
                logger.warning(f"Failed to read frame from {rtsp_url}")
                # Create error placeholder
                from PIL import Image, ImageDraw
                img = Image.new('RGB', (640, 480), color=(64, 64, 64))
                draw = ImageDraw.Draw(img)
                draw.text((200, 220), 'Stream Interrupted', fill=(255, 100, 100))
                draw.text((220, 250), 'Reconnecting...', fill=(200, 200, 200))
                
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='JPEG')
                frame_bytes = img_byte_arr.getvalue()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                time.sleep(2)
                
                # Try to reconnect
                if cap:
                    cap.release()
                cap = cv2.VideoCapture(rtsp_url)
                continue
            
            # Encode frame as JPEG
            try:
                ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                if not ret:
                    continue
                    
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                
                frame_count += 1
                if frame_count % 100 == 0:
                    logger.debug(f"Streamed {frame_count} frames from {rtsp_url}")
                    
            except Exception as encode_error:
                logger.error(f"Frame encoding error: {encode_error}")
                continue
                
    except Exception as e:
        logger.error(f"Video stream error for {rtsp_url}: {e}")
        # Create error placeholder
        try:
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (640, 480), color=(64, 64, 64))
            draw = ImageDraw.Draw(img)
            draw.text((180, 220), 'Video Stream Error', fill=(255, 100, 100))
            draw.text((200, 250), str(e)[:40], fill=(200, 200, 200))
            
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG')
            frame_bytes = img_byte_arr.getvalue()
            
            while True:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                time.sleep(1)
        except:
            # Final fallback
            placeholder_text = b'Video stream unavailable'
            while True:
                yield (b'--frame\r\n'
                       b'Content-Type: text/plain\r\n\r\n' + placeholder_text + b'\r\n')
                time.sleep(1)
    finally:
        if cap:
            cap.release()

@app.route('/export_csv')
@login_required
def export_csv():
    cameras = Camera.query.all()
    def generate():
        yield 'Name,IP,URL,Location,Status\n'
        for cam in cameras:
            yield f"{cam.name},{cam.ip},{cam.url},{cam.location},{cam.status}\n"
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=cameras.csv'})

@app.route('/ptz/<int:camera_id>/<action>', methods=['POST'])
@login_required
def ptz_control(camera_id, action):
    cam = Camera.query.get_or_404(camera_id)
    
    # Mock PTZ control - in real implementation, use ONVIF or vendor API
    valid_actions = ['up', 'down', 'left', 'right', 'home', 'zoom_in', 'zoom_out']
    if action not in valid_actions:
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    
    # Simulate PTZ command
    print(f"PTZ command for camera {cam.name}: {action}")
    
    return jsonify({'success': True, 'message': f'PTZ {action} executed'})

@app.route('/analytics_data')
@login_required
def analytics_data():
    # Mock analytics data - in real implementation, query from DB
    motion_data = {
        'labels': ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
        'data': [12, 8, 15, 22, 18, 25]
    }
    people_data = {
        'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'data': [45, 52, 38, 61, 55, 32, 28]
    }
    events = [
        {'time': '14:30:22', 'camera': 'Camera 001', 'type': 'Motion', 'desc': 'Motion detected in parking area'},
        {'time': '14:25:15', 'camera': 'Camera 003', 'type': 'Intrusion', 'desc': 'Tripwire crossed at entrance'},
        {'time': '14:20:08', 'camera': 'Camera 005', 'type': 'Face', 'desc': 'Unknown face detected'},
        {'time': '14:15:33', 'camera': 'Camera 002', 'type': 'Counting', 'desc': 'Person entered (count: 45)'}
    ]
    return jsonify({'motion': motion_data, 'people': people_data, 'events': events})

@app.route('/delete_camera/<int:camera_id>', methods=['POST'])
@login_required
@operator_required
def delete_camera(camera_id):
    cam = Camera.query.get_or_404(camera_id)
    db.session.delete(cam)
    db.session.commit()
    logger.info(f'Camera {camera_id} deleted by {current_user.username}')
    flash('Camera deleted successfully', 'success')
    return jsonify({'success': True, 'message': 'Camera deleted'})

@app.route('/configure_camera/<int:camera_id>', methods=['GET', 'POST'])
@login_required
def configure_camera(camera_id):
    cam = Camera.query.get_or_404(camera_id)
    
    if request.method == 'POST':
        # Update camera configuration
        if 'location' in request.form:
            cam.location = request.form['location']
            db.session.commit()
        flash('Camera configuration updated successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('configure.html', camera=cam)

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    """Application settings page"""
    return render_template('settings.html',
        ip_range=IP_RANGE,
        port=PORT,
        app_host=APP_HOST,
        app_port=APP_PORT,
        debug=DEBUG,
        default_username=DEFAULT_USERNAME
    )

@app.route('/groups', methods=['GET'])
@login_required
def groups():
    """Camera groups management page"""
    return render_template('groups.html')

@app.route('/groups/<group_id>', methods=['GET'])
@login_required
def group_detail(group_id):
    """Individual group detail page"""
    try:
        group = CameraGroup.query.get_or_404(group_id)
        return render_template('group_detail.html', group=group)
    except Exception as e:
        logger.error(f'Group detail error: {e}')
        flash('Group not found', 'error')
        return redirect(url_for('groups'))

@app.route('/api/camera_groups', methods=['GET'])
@login_required
def get_camera_groups():
    """Get all camera groups"""
    try:
        groups = CameraGroup.query.all()
        total_cameras = Camera.query.count()
        ungrouped_cameras = Camera.query.filter(~Camera.groups.any()).count()
        locations = db.session.query(Camera.location).distinct().count()
        
        groups_data = []
        for group in groups:
            online_count = sum(1 for cam in group.cameras if cam.status == 'online')
            groups_data.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'location': group.location,
                'icon': group.icon,
                'camera_count': len(group.cameras),
                'online_count': online_count,
                'cameras': [{'id': cam.id, 'name': cam.name, 'status': cam.status} for cam in group.cameras]
            })
        
        return jsonify({
            'success': True,
            'groups': groups_data,
            'total_groups': len(groups),
            'total_cameras': total_cameras,
            'ungrouped': ungrouped_cameras,
            'locations': locations
        })
    except Exception as e:
        logger.error(f'Error fetching camera groups: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/camera_groups', methods=['POST'])
@login_required
def create_camera_group():
    """Create a new camera group"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        location = data.get('location', '').strip()
        icon = data.get('icon', 'fa-layer-group')
        camera_ids = data.get('cameras', [])
        
        if not name:
            return jsonify({'success': False, 'message': 'Group name is required'}), 400
        
        # Create group
        group = CameraGroup(
            name=name,
            description=description,
            location=location,
            icon=icon
        )
        db.session.add(group)
        db.session.flush()  # Get the group ID
        
        # Add cameras to group
        if camera_ids:
            cameras = Camera.query.filter(Camera.id.in_(camera_ids)).all()
            group.cameras.extend(cameras)
        
        db.session.commit()
        
        log_audit('group_create', 'group', group.id, name)
        return jsonify({'success': True, 'message': 'Group created successfully', 'group_id': group.id})
    except Exception as e:
        logger.error(f'Error creating camera group: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/camera_groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_camera_group(group_id):
    """Delete a camera group"""
    try:
        group = CameraGroup.query.get_or_404(group_id)
        group_name = group.name
        
        db.session.delete(group)
        db.session.commit()
        
        log_audit('group_delete', 'group', group_id, group_name)
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        logger.error(f'Error deleting camera group: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/camera_groups/<int:group_id>', methods=['PUT'])
@login_required
def update_camera_group(group_id):
    """Update a camera group"""
    try:
        group = CameraGroup.query.get_or_404(group_id)
        data = request.get_json()
        
        if 'name' in data:
            group.name = data['name'].strip()
        if 'description' in data:
            group.description = data['description'].strip()
        if 'location' in data:
            group.location = data['location'].strip()
        if 'icon' in data:
            group.icon = data['icon']
        if 'cameras' in data:
            camera_ids = data['cameras']
            cameras = Camera.query.filter(Camera.id.in_(camera_ids)).all()
            group.cameras = cameras
        
        db.session.commit()
        
        log_audit('group_update', 'group', group_id, group.name)
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    except Exception as e:
        logger.error(f'Error updating camera group: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/save_settings', methods=['POST'])
@login_required
@admin_required
def save_settings():
    try:
        logger.info(f"Settings saved: {request.form}")
        flash('Settings saved successfully', 'success')
        return redirect(url_for('settings'))
    except Exception as e:
        logger.error(f'Error saving settings: {e}')
        flash('Failed to save settings', 'error')
        return redirect(url_for('settings'))

@app.route('/clean_database', methods=['POST'])
@login_required
@admin_required
def clean_database():
    """
    Wipe all data from the database except admin user
    This is a destructive operation that cannot be undone
    """
    try:
        logger.warning(f"Database cleanup initiated by user: {current_user.username}")
        
        # Log the action
        log_audit(
            action='database_cleanup',
            resource='database',
            details='All data deleted except admin user'
        )
        
        # Delete all data in order (respecting foreign key constraints)
        # Delete camera group associations first
        db.session.execute(db.text('DELETE FROM camera_group_association'))
        
        # Delete events
        Event.query.delete()
        logger.info("Deleted all events")
        
        # Delete audit logs (except the current cleanup action)
        AuditLog.query.filter(AuditLog.action != 'database_cleanup').delete()
        logger.info("Deleted audit logs")
        
        # Delete camera groups
        CameraGroup.query.delete()
        logger.info("Deleted all camera groups")
        
        # Delete cameras
        Camera.query.delete()
        logger.info("Deleted all cameras")
        
        # Commit all deletions
        db.session.commit()
        
        logger.warning("Database cleanup completed successfully")
        
        return jsonify({
            'success': True,
            'message': 'Database cleaned successfully. All data has been deleted.'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error cleaning database: {e}')
        return jsonify({
            'success': False,
            'message': f'Failed to clean database: {str(e)}'
        }), 500

@app.route('/bulk_update_location', methods=['POST'])
@login_required
def bulk_update_location():
    """Update location for multiple cameras at once"""
    try:
        data = request.get_json()
        camera_ids = data.get('camera_ids', [])
        new_location = data.get('location', '')
        
        # Sanitize inputs
        new_location = sanitize_string(new_location, 100)
        
        # Validate inputs
        if not camera_ids:
            return jsonify({'success': False, 'message': 'No cameras selected'}), 400
        
        if not isinstance(camera_ids, list):
            return jsonify({'success': False, 'message': 'Camera IDs must be a list'}), 400
        
        if len(camera_ids) > 100:
            return jsonify({'success': False, 'message': 'Cannot update more than 100 cameras at once'}), 400
        
        if not new_location:
            return jsonify({'success': False, 'message': 'Location cannot be empty'}), 400
        
        # Validate camera IDs are integers
        try:
            camera_ids = [int(cid) for cid in camera_ids]
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid camera ID format'}), 400
        
        updated = 0
        for cam_id in camera_ids:
            cam = Camera.query.get(cam_id)
            if cam:
                cam.location = new_location
                updated += 1
        
        db.session.commit()
        logger.info(f'Bulk updated {updated} cameras to location: {new_location}')
        return jsonify({'success': True, 'updated': updated})
    except Exception as e:
        logger.error(f'Bulk update error: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/bulk_delete_cameras', methods=['POST'])
@login_required
@admin_required
def bulk_delete_cameras():
    """Delete multiple cameras at once"""
    try:
        data = request.get_json()
        camera_ids = data.get('camera_ids', [])
        
        # Validate inputs
        if not camera_ids:
            return jsonify({'success': False, 'message': 'No cameras selected'}), 400
        
        if not isinstance(camera_ids, list):
            return jsonify({'success': False, 'message': 'Camera IDs must be a list'}), 400
        
        if len(camera_ids) > 50:
            return jsonify({'success': False, 'message': 'Cannot delete more than 50 cameras at once'}), 400
        
        # Validate camera IDs are integers
        try:
            camera_ids = [int(cid) for cid in camera_ids]
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid camera ID format'}), 400
        
        deleted = 0
        for cam_id in camera_ids:
            cam = Camera.query.get(cam_id)
            if cam:
                db.session.delete(cam)
                deleted += 1
        
        db.session.commit()
        logger.info(f'Bulk deleted {deleted} cameras')
        flash(f'Successfully deleted {deleted} cameras', 'success')
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        logger.error(f'Bulk delete error: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_camera_positions', methods=['POST'])
@login_required
def update_camera_positions():
    try:
        data = request.get_json()
        updates = data.get('updates', [])
        
        # Validate inputs
        if not updates:
            return jsonify({'success': False, 'message': 'No updates provided'}), 400
        
        if not isinstance(updates, list):
            return jsonify({'success': False, 'message': 'Updates must be a list'}), 400
        
        if len(updates) > 100:
            return jsonify({'success': False, 'message': 'Cannot update more than 100 positions at once'}), 400
        
        # Validate each update
        for update in updates:
            if not isinstance(update, dict):
                return jsonify({'success': False, 'message': 'Each update must be an object'}), 400
            
            if 'id' not in update:
                return jsonify({'success': False, 'message': 'Camera ID is required for each update'}), 400
            
            try:
                camera_id = int(update['id'])
            except (ValueError, TypeError):
                return jsonify({'success': False, 'message': 'Invalid camera ID'}), 400
            
            # Validate latitude and longitude if provided
            if 'latitude' in update:
                try:
                    lat = float(update['latitude'])
                    if not (-90 <= lat <= 90):
                        return jsonify({'success': False, 'message': 'Latitude must be between -90 and 90'}), 400
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': 'Invalid latitude value'}), 400
            
            if 'longitude' in update:
                try:
                    lng = float(update['longitude'])
                    if not (-180 <= lng <= 180):
                        return jsonify({'success': False, 'message': 'Longitude must be between -180 and 180'}), 400
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': 'Invalid longitude value'}), 400
        
        # Apply updates
        for update in updates:
            cam = Camera.query.get(update['id'])
            if cam:
                if 'latitude' in update:
                    cam.latitude = update['latitude']
                if 'longitude' in update:
                    cam.longitude = update['longitude']
        
        db.session.commit()
        logger.info(f'Updated positions for {len(updates)} cameras')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating camera positions: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/add_camera', methods=['POST'])
@login_required
@operator_required
def add_camera():
    """Manually add a camera"""
    try:
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name', '').strip()
        ip = data.get('ip', '').strip()
        port = data.get('port', '554')
        username = data.get('username', DEFAULT_USERNAME)
        password = data.get('password', DEFAULT_PASSWORD)
        location = data.get('location', 'default')
        
        # CRITICAL SECURITY: Require explicit password if no default is set
        if DEFAULT_PASSWORD is None and not password:
            return jsonify({'success': False, 'message': 'Password is required (no default password configured)'}), 400
        
        # Sanitize inputs
        name = sanitize_string(name, 100)
        ip = sanitize_string(ip, 45)
        port = sanitize_string(port, 10)
        username = sanitize_string(username, 50)
        password = sanitize_string(password, 128)
        location = sanitize_string(location, 100)
        
        # Validation
        if not name or not ip:
            return jsonify({'success': False, 'message': 'Name and IP are required'}), 400
        
        # Validate IP address
        is_valid_ip, msg_ip = validate_ip_address(ip)
        if not is_valid_ip:
            return jsonify({'success': False, 'message': msg_ip}), 400
        
        # Validate port
        is_valid_port, msg_port = validate_port(port)
        if not is_valid_port:
            return jsonify({'success': False, 'message': msg_port}), 400
        
        # Validate username if provided
        if username and username != DEFAULT_USERNAME:
            is_valid_username, msg_username = validate_username(username)
            if not is_valid_username:
                return jsonify({'success': False, 'message': f'Invalid username: {msg_username}'}), 400
        
        # Check if camera already exists
        existing = Camera.query.filter_by(ip=ip).first()
        if existing:
            return jsonify({'success': False, 'message': 'Camera with this IP already exists'}), 400
        
        # Create RTSP URL (without credentials in the URL)
        rtsp_url = f'rtsp://{ip}:{port}/stream'
        
        # Add camera with secure credential storage
        camera = Camera(
            name=name,
            ip=ip,
            url=rtsp_url,
            location=location,
            status='online',
            port=int(port)
        )
        camera.set_credentials(username, password)
        db.session.add(camera)
        db.session.commit()
        
        logger.info(f'Manually added camera: {name} ({ip})')
        flash(f'Camera "{name}" added successfully', 'success')
        return jsonify({
            'success': True,
            'camera': {
                'id': camera.id,
                'name': camera.name,
                'ip': camera.ip,
                'location': camera.location
            }
        })
    except Exception as e:
        logger.error(f'Error adding camera: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_camera/<int:camera_id>', methods=['POST'])
@login_required
def update_camera(camera_id):
    """Update camera details"""
    try:
        cam = Camera.query.get_or_404(camera_id)
        data = request.get_json() if request.is_json else request.form
        
        if 'name' in data:
            cam.name = data['name'].strip()
        if 'location' in data:
            cam.location = data['location'].strip()
        if 'url' in data:
            cam.url = data['url'].strip()
        
        db.session.commit()
        logger.info(f'Updated camera {camera_id}: {cam.name}')
        flash('Camera updated successfully', 'success')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Error updating camera: {e}')
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cameras')
@login_required
def api_cameras():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        location = request.args.get('location', '')
        search = request.args.get('search', '')
        status = request.args.get('status', '')
        
        # Build query with filters
        query = Camera.query
        
        if location:
            query = query.filter(Camera.location == location)
        
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                db.or_(
                    Camera.name.like(search_term),
                    Camera.ip.like(search_term)
                )
            )
        
        if status:
            query = query.filter(Camera.status == status)
        
        cameras_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        cameras = cameras_pagination.items
    except Exception as e:
        logger.error(f'API cameras error: {e}')
        return jsonify({'error': str(e)}), 500
    
    cameras_data = [{
        'id': cam.id,
        'name': cam.name,
        'ip': cam.ip,
        'location': cam.location,
        'status': cam.status,
        'latitude': cam.latitude,
        'longitude': cam.longitude
    } for cam in cameras]
    
    return jsonify({
        'cameras': cameras_data,
        'pagination': {
            'page': cameras_pagination.page,
            'per_page': cameras_pagination.per_page,
            'total': cameras_pagination.total,
            'pages': cameras_pagination.pages,
            'has_next': cameras_pagination.has_next,
            'has_prev': cameras_pagination.has_prev,
            'next_num': cameras_pagination.next_num if cameras_pagination.has_next else None,
            'prev_num': cameras_pagination.prev_num if cameras_pagination.has_prev else None
        }
    })

@app.route('/api/statistics', methods=['GET'])
@login_required
def get_statistics():
    """Get dashboard statistics"""
    try:
        total_cameras = Camera.query.count()
        online_cameras = Camera.query.filter_by(status='online').count()
        offline_cameras = Camera.query.filter_by(status='offline').count()
        
        locations = db.session.query(
            Camera.location, 
            db.func.count(Camera.id)
        ).group_by(Camera.location).all()
        
        location_stats = [{'location': loc, 'count': count} for loc, count in locations]
        
        return jsonify({
            'total': total_cameras,
            'online': online_cameras,
            'offline': offline_cameras,
            'locations': location_stats
        })
    except Exception as e:
        logger.error(f'Statistics error: {e}')
        return jsonify({'error': str(e)}), 500

# ==================== MISSING API ENDPOINTS ====================

@app.route('/api/cameras/<int:camera_id>', methods=['GET'])
@login_required
def api_get_camera(camera_id):
    """Get single camera details"""
    try:
        camera = Camera.query.get_or_404(camera_id)
        return jsonify({
            'id': camera.id,
            'name': camera.name,
            'ip': camera.ip,
            'location': camera.location,
            'status': camera.status,
            'latitude': camera.latitude,
            'longitude': camera.longitude,
            'port': camera.port
        })
    except Exception as e:
        logger.error(f'Error getting camera: {e}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cameras/<int:camera_id>', methods=['PUT'])
@login_required
@operator_required
def api_update_camera_endpoint(camera_id):
    """Update camera via API"""
    try:
        camera = Camera.query.get_or_404(camera_id)
        data = request.get_json()
        
        # Sanitize and validate inputs
        if 'name' in data:
            name = sanitize_string(data['name'], 100)
            if not name:
                return jsonify({'error': 'Camera name cannot be empty'}), 400
            camera.name = name
        
        if 'location' in data:
            location = sanitize_string(data['location'], 100)
            camera.location = location
        
        if 'status' in data:
            status = sanitize_string(data['status'], 20)
            if status not in ['online', 'offline']:
                return jsonify({'error': 'Status must be online or offline'}), 400
            camera.status = status
        
        db.session.commit()
        log_audit('camera_update', 'camera', camera_id, json.dumps(data))
        
        return jsonify({'success': True, 'message': 'Camera updated'})
    except Exception as e:
        logger.error(f'Error updating camera: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cameras/<int:camera_id>', methods=['DELETE'])
@login_required
@operator_required
def api_delete_camera(camera_id):
    """Delete camera via API"""
    try:
        camera = Camera.query.get_or_404(camera_id)
        db.session.delete(camera)
        db.session.commit()
        log_audit('camera_delete', 'camera', camera_id)
        
        return jsonify({'success': True, 'message': 'Camera deleted'})
    except Exception as e:
        logger.error(f'Error deleting camera: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cameras/<int:camera_id>/test', methods=['POST'])
@login_required
def api_test_camera_connection(camera_id):
    """Test camera connection"""
    try:
        camera = Camera.query.get_or_404(camera_id)
        
        # Test TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((camera.ip, camera.port))
        sock.close()
        
        if result == 0:
            return jsonify({'success': True, 'status': 'online', 'message': 'Camera is reachable'})
        else:
            return jsonify({'success': False, 'status': 'offline', 'message': 'Camera is not reachable'})
    except Exception as e:
        logger.error(f'Error testing camera: {e}')
        return jsonify({'error': str(e)}), 500

# Events API
@app.route('/api/events', methods=['GET'])
@login_required
def api_get_events():
    """Get list of events"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        event_type = request.args.get('type', '')
        severity = request.args.get('severity', '')
        
        query = Event.query
        
        if event_type:
            query = query.filter(Event.event_type == event_type)
        if severity:
            query = query.filter(Event.severity == severity)
        
        events_pagination = query.order_by(Event.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        events_data = [{
            'id': event.id,
            'camera_id': event.camera_id,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'timestamp': event.timestamp.isoformat() if event.timestamp else None,
            'acknowledged': event.acknowledged
        } for event in events_pagination.items]
        
        return jsonify({
            'events': events_data,
            'pagination': {
                'page': events_pagination.page,
                'per_page': events_pagination.per_page,
                'total': events_pagination.total,
                'pages': events_pagination.pages
            }
        })
    except Exception as e:
        logger.error(f'Error getting events: {e}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events', methods=['POST'])
@login_required
def api_create_event():
    """Create new event"""
    try:
        data = request.get_json()
        
        # Sanitize inputs
        camera_id = data.get('camera_id')
        event_type = sanitize_string(data.get('event_type', 'general'), 50)
        severity = sanitize_string(data.get('severity', 'info'), 20)
        description = sanitize_string(data.get('description', ''), 500)
        
        # Validate inputs
        if camera_id is not None:
            try:
                camera_id = int(camera_id)
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid camera ID'}), 400
            
            # Check if camera exists
            camera = Camera.query.get(camera_id)
            if not camera:
                return jsonify({'error': 'Camera not found'}), 404
        
        if event_type not in ['motion', 'intrusion', 'face', 'counting', 'general']:
            return jsonify({'error': 'Invalid event type'}), 400
        
        if severity not in ['low', 'medium', 'high', 'critical', 'info']:
            return jsonify({'error': 'Invalid severity level'}), 400
        
        event = Event(
            camera_id=camera_id,
            event_type=event_type,
            severity=severity,
            description=description
        )
        db.session.add(event)
        db.session.commit()
        
        return jsonify({'success': True, 'event_id': event.id}), 201
    except Exception as e:
        logger.error(f'Error creating event: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
def api_get_event(event_id):
    """Get event details"""
    try:
        event = Event.query.get_or_404(event_id)
        return jsonify({
            'id': event.id,
            'camera_id': event.camera_id,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'timestamp': event.timestamp.isoformat() if event.timestamp else None,
            'acknowledged': event.acknowledged,
            'acknowledged_by': event.acknowledged_by
        })
    except Exception as e:
        logger.error(f'Error getting event: {e}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events/<int:event_id>/acknowledge', methods=['PUT'])
@login_required
def api_acknowledge_event(event_id):
    """Acknowledge an event"""
    try:
        event = Event.query.get_or_404(event_id)
        event.acknowledged = True
        event.acknowledged_by = current_user.id
        db.session.commit()
        
        log_audit('event_acknowledge', 'event', event_id)
        return jsonify({'success': True, 'message': 'Event acknowledged'})
    except Exception as e:
        logger.error(f'Error acknowledging event: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_event(event_id):
    """Delete an event"""
    try:
        event = Event.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        
        log_audit('event_delete', 'event', event_id)
        return jsonify({'success': True, 'message': 'Event deleted'})
    except Exception as e:
        logger.error(f'Error deleting event: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# Logs API
@app.route('/api/logs', methods=['GET'])
@login_required
@admin_required
def api_get_logs():
    """Get system logs"""
    try:
        lines = request.args.get('lines', 100, type=int)
        log_file = 'camera_dashboard.log'
        
        if not os.path.exists(log_file):
            return jsonify({'logs': []})
        
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        
        return jsonify({'logs': recent_lines})
    except Exception as e:
        logger.error(f'Error reading logs: {e}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/logs/audit', methods=['GET'])
@login_required
@admin_required
def api_get_audit_logs():
    """Get audit trail"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        logs_data = [{
            'id': log.id,
            'user_id': log.user_id,
            'action': log.action,
            'resource': log.resource,
            'resource_id': log.resource_id,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None,
            'details': log.details
        } for log in logs_pagination.items]
        
        return jsonify({
            'logs': logs_data,
            'pagination': {
                'page': logs_pagination.page,
                'per_page': logs_pagination.per_page,
                'total': logs_pagination.total,
                'pages': logs_pagination.pages
            }
        })
    except Exception as e:
        logger.error(f'Error getting audit logs: {e}')
        return jsonify({'error': 'Internal server error'}), 500

# Settings API
@app.route('/api/settings', methods=['GET'])
@login_required
@admin_required
def api_get_settings():
    """Get application settings"""
    try:
        settings = {
            'ip_range': IP_RANGE,
            'default_port': PORT,
            'app_host': APP_HOST,
            'app_port': APP_PORT,
            'debug': DEBUG
        }
        return jsonify(settings)
    except Exception as e:
        logger.error(f'Error getting settings: {e}')
        return jsonify({'error': 'Internal server error'}), 500

# User management API
@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def api_get_users():
    """Get list of users"""
    try:
        users = User.query.all()
        users_data = [{
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'is_active': user.is_active,
            'last_login': user.last_login.isoformat() if user.last_login else None
        } for user in users]
        
        return jsonify({'users': users_data})
    except Exception as e:
        logger.error(f'Error getting users: {e}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def api_create_user():
    """Create new user"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'viewer')
        
        # Sanitize inputs
        username = sanitize_string(username, 50)
        password = sanitize_string(password, 128)
        role = sanitize_string(role, 20)
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Validate username
        is_valid_username, msg_username = validate_username(username)
        if not is_valid_username:
            return jsonify({'error': msg_username}), 400
        
        # Validate password
        is_valid, msg = validate_password(password)
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Validate role
        if role not in ['admin', 'operator', 'viewer']:
            return jsonify({'error': 'Invalid role. Must be admin, operator, or viewer'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        user = User(
            username=username,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            role=role
        )
        db.session.add(user)
        db.session.commit()
        
        log_audit('user_create', 'user', user.id, username)
        return jsonify({'success': True, 'user_id': user.id}), 201
    except Exception as e:
        logger.error(f'Error creating user: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def api_update_user(user_id):
    """Update user"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'role' in data and data['role'] in ['admin', 'operator', 'viewer']:
            user.role = data['role']
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        
        db.session.commit()
        log_audit('user_update', 'user', user_id, json.dumps(data))
        
        return jsonify({'success': True, 'message': 'User updated'})
    except Exception as e:
        logger.error(f'Error updating user: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_user(user_id):
    """Delete user"""
    try:
        if user_id == current_user.id:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        user = User.query.get_or_404(user_id)
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        log_audit('user_delete', 'user', user_id, username)
        return jsonify({'success': True, 'message': 'User deleted'})
    except Exception as e:
        logger.error(f'Error deleting user: {e}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(400)
def bad_request_error(error):
    logger.warning(f'400 error: {request.url}')
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
        return jsonify({'error': 'Bad request', 'message': str(error)}), 400
    flash('Bad request', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(401)
def unauthorized_error(error):
    logger.warning(f'401 error: {request.url}')
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
        return jsonify({'error': 'Unauthorized'}), 401
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f'403 error: {request.url} - User: {current_user.username if current_user.is_authenticated else "Anonymous"}')
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
        return jsonify({'error': 'Forbidden - Insufficient permissions'}), 403
    flash('You do not have permission to access this resource', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f'404 error: {request.url}')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    # Don't show flash messages for common 404s like favicon, .well-known, etc.
    if not any(x in request.path for x in ['/favicon.ico', '/.well-known/', '/static/']):
        flash('Page not found', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(429)
def ratelimit_error(error):
    logger.warning(f'429 rate limit exceeded: {request.url} - IP: {request.remote_addr}')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    flash('Too many requests. Please try again later.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'500 error: {error}')
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    flash('An internal error occurred', 'error')
    return redirect(url_for('dashboard'))

def create_app(config_overrides=None):
    """Factory function to create Flask app for testing"""
    test_app = Flask(__name__)
    
    # Apply config overrides
    if config_overrides:
        test_app.config.update(config_overrides)
    else:
        # Use default config
        test_app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', get_or_create_secret_key())
        test_app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://camguid:camguid_password@db:5432/camguid'))
        test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        test_app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': 10,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'max_overflow': 20
        }
        test_app.config['WTF_CSRF_ENABLED'] = os.getenv('WTF_CSRF_ENABLED', 'True').lower() == 'true'
        test_app.config['WTF_CSRF_TIME_LIMIT'] = int(os.getenv('WTF_CSRF_TIME_LIMIT', 3600))
        test_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 7200)))
        test_app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
        test_app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
        test_app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
        test_app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # Set default database URI if not provided
    if 'SQLALCHEMY_DATABASE_URI' not in test_app.config:
        test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    # Initialize extensions
    db.init_app(test_app)
    csrf.init_app(test_app)
    login_manager.init_app(test_app)
    migrate.init_app(test_app, db)
    
    # Register blueprints and routes (simplified for testing)
    test_app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
    
    # Add all the routes from the main app
    # This is a simplified version - in practice you'd want to organize this better
    test_app.add_url_rule('/', 'dashboard', dashboard, methods=['GET'])
    test_app.add_url_rule('/login', 'login', login, methods=['GET', 'POST'])
    test_app.add_url_rule('/health', 'health_check', health_check, methods=['GET'])
    test_app.add_url_rule('/metrics', 'metrics', metrics, methods=['GET'])
    test_app.add_url_rule('/api/cameras', 'api_cameras', api_cameras, methods=['GET'])
    test_app.add_url_rule('/api/statistics', 'get_statistics', get_statistics, methods=['GET'])
    test_app.add_url_rule('/settings', 'settings', settings, methods=['GET'])
    
    return test_app

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    logger.info(f'Starting Camera Dashboard on {APP_HOST}:{APP_PORT}')
    app.run(host=APP_HOST, port=APP_PORT, debug=DEBUG)