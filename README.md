# CamGuid - Enterprise Surveillance Dashboard

[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/postgresql-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=Prometheus&logoColor=white)](https://prometheus.io)
[![Grafana](https://img.shields.io/badge/grafana-%23F46800.svg?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com)

A comprehensive, enterprise-grade web-based surveillance system with advanced monitoring, analytics, and management features. Built with modern technologies and production-ready architecture.

## 📊 Project Overview

**CamGuid** is a full-featured Video Management System (VMS) that provides centralized control and monitoring of IP cameras, NVRs, and surveillance devices. It offers enterprise-level features comparable to commercial solutions like Milestone XProtect and Genetec Security Center.

### 🏗️ Architecture Highlights

- **Backend**: Flask 2.3.3 with SQLAlchemy ORM
- **Database**: PostgreSQL 15 with connection pooling and health checks
- **Security**: Fernet AES-128 encryption, CSRF protection, RBAC
- **Monitoring**: Prometheus metrics with Grafana dashboards
- **Deployment**: Docker containerization with Nginx reverse proxy
- **Testing**: Comprehensive pytest suite with 9 test cases
- **Documentation**: Swagger/OpenAPI 2.0 API documentation

---

## 🚀 Key Features

### 📹 Core Surveillance Features

- **Live Video Streaming**: Real-time camera feeds with PTZ controls
- **Multi-View Layouts**: 1, 4, 9, 16, and 64 camera simultaneous viewing
- **Video Playback**: Historical footage review with timeline navigation
- **Network Discovery**: Auto-scan and add IP cameras to the network
- **Device Management**: Centralized configuration of hundreds of devices

### 🎛️ Advanced Analytics & Intelligence

- **Motion Detection**: Real-time alerts with configurable sensitivity
- **People Counting**: Automated foot traffic analysis with heat maps
- **Intrusion Detection**: Tripwire and zone-based security alerts
- **Event Management**: Centralized event logging and notifications
- **Behavior Analytics**: Abnormal activity detection and reporting

### 🗺️ Smart Features

- **E-Map Integration**: Floor plan visualization with camera positioning
- **Camera Groups**: Organize devices by location or function
- **Tour Management**: Automated camera cycling for continuous monitoring
- **Video Wall**: Custom multi-monitor display configurations
- **Access Control**: Integrated user management and permissions

### 🔒 Enterprise Security

- **Encrypted Credentials**: Fernet AES-128 encryption for camera passwords
- **Role-Based Access**: Granular permissions (Admin, Operator, Viewer)
- **Audit Logging**: Complete activity tracking and compliance reporting
- **Session Security**: Secure session management with configurable timeouts
- **Rate Limiting**: Protection against brute force and DoS attacks

### 📊 Monitoring & Operations

- **Prometheus Metrics**: Real-time system monitoring and alerting
- **Grafana Dashboards**: Visual analytics and performance monitoring
- **Log Rotation**: Automatic log file management (10MB, 5 backups)
- **Health Checks**: Automated container and service monitoring
- **API Documentation**: Interactive Swagger UI for all endpoints

### 🎨 Modern User Interface

- **Responsive Design**: Optimized for desktop, tablet, and mobile devices
- **Dark/Light Themes**: Customizable interface with modern aesthetics
- **Real-time Updates**: Live status indicators and notifications
- **Touch-Friendly**: Optimized for control room touchscreens
- **Intuitive Navigation**: Collapsible sidebar with organized menu structure

---

## 🛠️ Technical Stack

### Backend Framework
- **Flask 2.3.3**: Lightweight WSGI web framework
- **SQLAlchemy 3.0.5**: Advanced ORM with PostgreSQL dialect
- **Flask-Login 0.6.3**: User session management
- **Flask-WTF 1.2.1**: CSRF protection and form handling

### Database & Storage
- **PostgreSQL 15**: Enterprise-grade relational database
- **Connection Pooling**: 10-20 connections with health checks
- **Database Migrations**: Flask-Migrate for schema management
- **Backup Integration**: Automated backup and restore capabilities

### Security & Encryption
- **Cryptography 41.0.7**: Fernet AES-128 symmetric encryption
- **bcrypt 4.0.1**: Password hashing with PBKDF2
- **Werkzeug 2.3.7**: Secure password utilities
- **CSRF Protection**: Flask-WTF cross-site request forgery prevention

### Monitoring & Observability
- **Prometheus Client 0.19.0**: Application metrics collection
- **Grafana**: Real-time dashboards and alerting
- **Logging**: RotatingFileHandler with structured JSON logs
- **Health Checks**: Automated service monitoring endpoints

### Testing & Quality
- **pytest 7.4.3**: Comprehensive test framework
- **unittest**: Built-in Python testing utilities
- **Test Coverage**: 9 test cases covering models, validation, and API endpoints
- **CI/CD Ready**: Automated testing pipeline support

### API & Documentation
- **RESTful API**: 64+ endpoints with JSON responses
- **Swagger UI 4.11.1**: Interactive API documentation
- **OpenAPI 2.0**: Complete API specification
- **Rate Limiting**: Flask-Limiter with configurable thresholds

### Containerization & Deployment
- **Docker**: Multi-stage builds with security hardening
- **Docker Compose**: Development and production configurations
- **Nginx**: Reverse proxy with SSL termination and caching
- **Gunicorn**: Production WSGI server with optimized worker configuration

### Frontend Technologies
- **Bootstrap 5**: Responsive CSS framework
- **FontAwesome 6**: Comprehensive icon library
- **JavaScript ES6+**: Modern client-side scripting
- **HTML5**: Semantic markup with accessibility features
- **CSS3**: Custom styling with CSS variables and animations

---

## 📋 System Requirements

### Minimum Requirements
- **CPU**: Dual-core 2.4GHz processor
- **RAM**: 4GB system memory
- **Storage**: 20GB available disk space
- **Network**: 100Mbps Ethernet connection
- **OS**: Windows 10+, Ubuntu 18.04+, macOS 10.14+

### Recommended Specifications
- **CPU**: Quad-core 3.0GHz+ processor
- **RAM**: 8GB+ system memory
- **Storage**: SSD with 100GB+ available space
- **Network**: Gigabit Ethernet connection
- **Display**: 1920x1080 resolution or higher

### Browser Compatibility
- ✅ **Chrome 90+**
- ✅ **Firefox 88+**
- ✅ **Safari 14+**
- ✅ **Edge 90+**
- ❌ **Internet Explorer** (not supported)

---

## 🚀 Quick Start

### Option 1: Docker Deployment (Recommended)

#### Development Setup
```bash
# Clone repository
git clone https://github.com/cosmic-striker/CamGuid.git
cd CamGuid

# Configure environment
cp .env.example .env
# Edit .env with your secure passwords

# Start services
docker-compose up -d

# Initialize database
docker-compose exec camera-dashboard python init_db.py

# Access application
# URL: http://localhost:5000
# Login: admin / Admin123!
```

#### Production Setup
```bash
# Pull and start production environment
docker-compose -f docker-compose.prod.yml up -d

# Initialize database
docker-compose -f docker-compose.prod.yml exec camera-dashboard python init_db.py

# Access application
# URL: http://localhost (via Nginx)
# Login: admin / Admin123!
```

### Option 2: Manual Installation

#### Prerequisites
```bash
# Install Python 3.11+
python --version

# Install PostgreSQL 15
sudo apt-get install postgresql-15 postgresql-contrib-15

# Create database
sudo -u postgres createdb camguid
sudo -u postgres createuser camguid
```

#### Setup Steps
```bash
# Clone and setup
git clone https://github.com/cosmic-striker/CamGuid.git
cd CamGuid

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with database credentials

# Initialize database
python init_db.py

# Start application
python app.py

# Access at http://localhost:5000
```

---

## 🔐 Security Configuration

### Default Admin Credentials
```
Username: admin
Password: Admin123!
```
> **⚠️ CRITICAL**: You will be required to change this password immediately on first login!

### Security Features
- **Password Complexity**: Minimum 8 characters with uppercase, lowercase, numbers, and special characters
- **Session Management**: 2-hour session timeout with secure cookies
- **CSRF Protection**: Cross-site request forgery prevention on all forms
- **Rate Limiting**: 200 requests/day, 50/hour per IP address
- **Audit Logging**: Complete activity tracking for compliance
- **Encrypted Storage**: Fernet AES-128 encryption for camera credentials

### Environment Variables
```bash
# Database Configuration
DATABASE_URL=postgresql://camguid:secure_password@db:5432/camguid
POSTGRES_DB=camguid
POSTGRES_USER=camguid
POSTGRES_PASSWORD=your_secure_password

# Security Settings
SECRET_KEY=your_64_character_secret_key
ADMIN_DEFAULT_PASSWORD=your_secure_admin_password

# Application Settings
IP_RANGE=192.168.1.0/24
PORT=554
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=your_secure_camera_password

# Monitoring
LOG_LEVEL=WARNING
LOG_FILE=camera_dashboard.log
```

---

## 📊 Monitoring & Metrics

### Prometheus Metrics
The application exposes comprehensive metrics at `/metrics`:

- **Request Metrics**: Total requests, latency, error rates by endpoint
- **Camera Metrics**: Total cameras, online/offline counts
- **Database Metrics**: Connection pool status, query performance
- **System Metrics**: Memory usage, CPU utilization

### Grafana Dashboard
Pre-configured dashboard includes:
- **Request Analytics**: Response times and throughput
- **Camera Health**: Device status and connectivity
- **System Performance**: Resource utilization graphs
- **Error Tracking**: Application error rates and types

### Log Management
- **Automatic Rotation**: 10MB files with 5 backup rotations
- **Structured Logging**: JSON format for log aggregation
- **Multiple Handlers**: Console and file output
- **Configurable Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL

---

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_app.py -v

# Run with coverage
python -m pytest --cov=app --cov-report=html
```

### Test Coverage
- **Models**: User, Camera, Event, AuditLog, CameraGroup
- **Validation**: Password, IP address, username validation
- **API Endpoints**: Health check, metrics, authentication
- **Encryption**: Fernet encryption/decryption functionality

### Test Results
```
==================================== test session starts ====================================
collected 9 items

tests/test_app.py::TestModels::test_camera_creation PASSED
tests/test_app.py::TestModels::test_camera_encryption PASSED
tests/test_app.py::TestModels::test_user_creation PASSED
tests/test_app.py::TestValidationFunctions::test_validate_ip_address PASSED
tests/test_app.py::TestValidationFunctions::test_validate_password PASSED
tests/test_app.py::TestValidationFunctions::test_validate_username PASSED
tests/test_app.py::TestAPIEndpoints::test_health_check PASSED
tests/test_app.py::TestAPIEndpoints::test_login_required_endpoints PASSED
tests/test_app.py::TestAPIEndpoints::test_metrics_endpoint PASSED

============================== 9 passed, 2 warnings in 2.25s ===============================
```

---

## 📚 API Documentation

### Swagger UI
Interactive API documentation available at:
- **Development**: http://localhost:5000/api/docs
- **Production**: http://localhost/api/docs

### Key API Endpoints

#### Authentication
- `POST /login` - User authentication
- `POST /logout` - User logout
- `POST /change_password` - Password change

#### Camera Management
- `GET /api/cameras` - List all cameras
- `POST /api/cameras` - Add new camera
- `PUT /api/cameras/{id}` - Update camera
- `DELETE /api/cameras/{id}` - Delete camera

#### Monitoring
- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics
- `GET /api/statistics` - Dashboard statistics

#### Analytics
- `GET /api/events` - Security events
- `POST /api/events` - Create event
- `GET /api/logs` - System logs

### API Features
- **RESTful Design**: Consistent HTTP methods and status codes
- **JSON Responses**: Structured data with error handling
- **Rate Limiting**: Protected against abuse
- **Authentication**: Bearer token or session-based auth
- **Pagination**: Large dataset handling
- **Filtering**: Query parameter-based filtering

---

## 🐳 Docker Architecture

### Development Container
```yaml
camera-dashboard:
  build: .
  ports:
    - "5000:5000"
  environment:
    - FLASK_ENV=development
  volumes:
    - ./logs:/app/logs
```

### Production Container
```yaml
camera-dashboard:
  image: ${DOCKERHUB_USERNAME}/campy:latest
  environment:
    - FLASK_ENV=production
  depends_on:
    db:
      condition: service_healthy

nginx:
  image: nginx:alpine
  ports:
    - "80:80"
  volumes:
    - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

### Container Features
- **Multi-stage Builds**: Optimized image size and security
- **Non-root User**: Security hardening with dedicated app user
- **Health Checks**: Automated container monitoring
- **Log Rotation**: Container-level log management
- **Resource Limits**: CPU and memory constraints

---

## 🔧 Configuration Files

### Core Configuration
- `.env` - Environment variables and secrets
- `docker-compose.yml` - Development environment
- `docker-compose.prod.yml` - Production environment
- `nginx/nginx.conf` - Reverse proxy configuration
- `pytest.ini` - Test configuration

### Application Structure
```
CamGuid/
├── app.py                 # Main Flask application
├── models.py             # Database models
├── init_db.py            # Database initialization
├── requirements.txt      # Python dependencies
├── Dockerfile           # Container build instructions
├── docker-compose.yml   # Development stack
├── docker-compose.prod.yml  # Production stack
├── nginx/
│   └── nginx.conf       # Reverse proxy config
├── static/              # Static assets (CSS, JS, images)
├── templates/           # Jinja2 templates
│   ├── *.html          # Page templates
│   └── partials/       # Reusable components
├── tests/               # Test suite
│   └── test_app.py     # Unit tests
├── logs/                # Application logs
├── instance/            # Instance-specific data
└── prometheus.yml       # Monitoring configuration
```

---

## 📈 Performance & Scalability

### Database Performance
- **Connection Pooling**: 10-20 concurrent connections
- **Query Optimization**: Indexed queries with SQLAlchemy
- **Health Checks**: Automatic connection validation
- **Migration Support**: Zero-downtime schema updates

### Application Performance
- **Gunicorn Workers**: 4 workers with 2 threads each
- **Request Timeout**: 60-second configurable timeout
- **Static File Caching**: 1-year cache headers for assets
- **Gzip Compression**: Optimized content delivery

### Monitoring Performance
- **Metrics Collection**: Low-overhead Prometheus integration
- **Log Rotation**: Prevents disk space exhaustion
- **Memory Management**: Efficient session and cache handling

---

## 🔄 Migration & Upgrades

### From SQLite to PostgreSQL
```bash
# Export existing data
python -c "
from app import app, db
from models import Camera
import json

with app.app_context():
    cameras = Camera.query.all()
    data = [{
        'name': c.name,
        'ip': c.ip,
        'port': c.port,
        'location': c.location,
        'status': c.status
    } for c in cameras]
    
    with open('cameras_export.json', 'w') as f:
        json.dump(data, f, indent=2)
"

# Switch to PostgreSQL
docker-compose -f docker-compose.prod.yml up -d
docker-compose -f docker-compose.prod.yml exec camera-dashboard python init_db.py

# Import data
python -c "
from app import app, db
from models import Camera
import json

with app.app_context():
    with open('cameras_export.json', 'r') as f:
        data = json.load(f)
    
    for item in data:
        camera = Camera(**item)
        db.session.add(camera)
    
    db.session.commit()
"
```

### Version Upgrades
1. **Backup Database**: `pg_dump camguid > backup.sql`
2. **Stop Services**: `docker-compose down`
3. **Update Images**: `docker-compose pull`
4. **Run Migrations**: `docker-compose exec camera-dashboard flask db upgrade`
5. **Restart Services**: `docker-compose up -d`

---

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check PostgreSQL status
docker-compose ps

# View database logs
docker-compose logs db

# Test connection
docker-compose exec db psql -U camguid -d camguid -c "SELECT version();"
```

#### Application Won't Start
```bash
# Check application logs
docker-compose logs camera-dashboard

# Test health endpoint
curl http://localhost:5000/health

# Check environment variables
docker-compose exec camera-dashboard env | grep -E "(DATABASE|SECRET)"
```

#### Camera Connection Issues
```bash
# Test camera connectivity
telnet <camera_ip> 554

# Check RTSP stream
ffplay rtsp://<camera_ip>:554/stream
```

### Log Locations
- **Application Logs**: `./logs/camera_dashboard.log`
- **Docker Logs**: `docker-compose logs -f`
- **Nginx Logs**: `docker-compose -f docker-compose.prod.yml logs nginx`

---

## 🤝 Contributing

### Development Setup
```bash
# Fork and clone
git clone https://github.com/your-username/CamGuid.git
cd CamGuid

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Setup pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
python -m pytest tests/ -v
```

### Code Standards
- **PEP 8**: Python style guide compliance
- **Type Hints**: Type annotations for better code clarity
- **Docstrings**: Comprehensive function documentation
- **Testing**: 100% test coverage for new features
- **Security**: Input validation and sanitization

### Pull Request Process
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Flask Framework**: Lightweight and flexible web framework
- **PostgreSQL**: Robust and scalable database solution
- **Bootstrap**: Responsive frontend framework
- **Prometheus/Grafana**: Industry-standard monitoring stack
- **Open Source Community**: Libraries and tools that made this possible

---

## 📞 Support & Contact

### Documentation
- **[API Documentation](http://localhost:5000/api/docs)** - Interactive API reference
- **[Migration Guide](MIGRATION_GUIDE.md)** - Database migration instructions
- **[Frontend Analysis](FRONTEND_ANALYSIS_REPORT.md)** - UI/UX documentation

### Community
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Community questions and answers
- **Documentation Wiki**: Extended guides and tutorials

### Professional Support
For enterprise deployments and custom development:
- **Email**: support@camguid.dev
- **Documentation**: https://docs.camguid.dev
- **Enterprise Features**: Custom integrations and advanced analytics

---

## 🏆 Recent Achievements

### ✅ Security Enhancements (November 2025)
- **Fernet Encryption**: Upgraded from Base64 to AES-128 encryption
- **Log Rotation**: Implemented automatic log file management
- **Prometheus Monitoring**: Added comprehensive metrics collection
- **Unit Testing**: Created complete test suite with 9 test cases
- **API Documentation**: Integrated Swagger UI for all endpoints

### ✅ Production Readiness
- **Docker Optimization**: Multi-stage builds with security hardening
- **Nginx Integration**: Reverse proxy with SSL and caching
- **Health Checks**: Automated service monitoring
- **Resource Limits**: CPU and memory constraints
- **Backup Integration**: Automated database backups

### ✅ Code Quality
- **Test Coverage**: 9 comprehensive test cases
- **Code Standards**: PEP 8 compliance and type hints
- **Documentation**: Complete API and user documentation
- **Security Audit**: Input validation and sanitization
- **Performance Optimization**: Connection pooling and caching

---

*CamGuid - Enterprise Surveillance Made Simple* 🚀

**Last Updated**: November 17, 2025  
**Version**: 2.0.0  
**Status**: Production Ready ✅"# CamGuid" 
