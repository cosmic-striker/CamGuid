# Smart Surveillance Dashboard

A comprehensive web-based surveillance system inspired by CamGuid (Smart Professional Surveillance System) with advanced monitoring, analytics, and management features.

## 🚀 CamGuid Features Implemented

### **📹 Live View & Multi-Monitor**
- **Real-time Camera Feeds**: Live streaming from all connected cameras
- **Multi-View Layouts**: 1, 4, 9, 16, and 64 camera views simultaneously
- **PTZ Controls**: Pan, tilt, zoom, and preset controls for compatible cameras
- **Video Wall**: Configurable multi-camera display layouts

### **🎬 Video Playback**
- **Historical Playback**: Review recorded footage by camera and time
- **Playback Controls**: Play, pause, stop, and speed control (0.25x to 4x)
- **Timeline Navigation**: Jump to specific dates and times
- **Export Clips**: Save video segments for evidence

### **📊 Intelligent Video Analytics (IVS)**
- **Motion Detection**: Real-time motion alerts with sensitivity settings
- **People Counting**: Track foot traffic with heat maps
- **Intrusion Detection**: Tripwire and zone-based alerts
- **Face Detection**: AI-powered facial recognition
- **Behavior Analytics**: Abnormal activity detection
- **Event Dashboard**: Centralized event monitoring and logging

### **🗺️ E-Map Integration**
- **Floor Plan Upload**: Import building layouts and maps
- **Camera Positioning**: Place camera icons on maps
- **Zone Monitoring**: Visual representation of camera coverage areas
- **Quick Navigation**: Click map positions to view camera feeds

### **⚙️ Device Management**
- **Centralized Control**: Manage hundreds of IP cameras, NVRs, and devices
- **Device Discovery**: Auto-scan and add devices to the network
- **Configuration**: Remote camera settings and firmware updates
- **Health Monitoring**: Device status and connectivity alerts
- **Bulk Operations**: Configure multiple devices simultaneously

### **🔐 Access Control Integration**
- **User Management**: Role-based access permissions
- **Time Attendance**: Employee check-in/out tracking
- **Door Control**: Remote door access management
- **Audit Logs**: Access event logging and reporting

### **🎛️ Video Wall & Control Room**
- **Wall Configuration**: Create custom video wall layouts
- **Multi-Monitor Support**: Control multiple displays
- **Tour Management**: Automated camera cycling
- **Emergency Modes**: Instant alarm response layouts

### **🔒 Security & Backup**
- **Encrypted Streaming**: Secure video transmission
- **Role-Based Access**: Granular permission control
- **Scheduled Backups**: Automated footage archiving
- **Data Encryption**: Secure storage and transmission
- **Audit Trails**: Complete activity logging

## 🎨 Modern UI/UX

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Dark/Light Themes**: Customizable interface themes
- **Intuitive Navigation**: Sidebar with collapsible groups
- **Real-time Updates**: Live status indicators and alerts
- **Touch-Friendly**: Optimized for touchscreens and control rooms

## 🛠️ Technical Features

- **Web-Based**: No client software installation required
- **Cross-Platform**: Works on Windows, macOS, Linux
- **RESTful API**: Integration with third-party systems
- **Docker Support**: Containerized deployment
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login with session management

## 📋 System Requirements

- **Browser**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **Network**: Stable Ethernet connection
- **Storage**: SSD recommended for video storage
- **RAM**: 8GB minimum, 16GB recommended
- **CPU**: Multi-core processor for video processing

## 🚀 Getting Started

1. **Setup Environment**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Application**:
   ```bash
   python app.py
   ```

3. **Access Dashboard**:
   - URL: `http://localhost:5000`
   - **First Login**: `admin` / `Admin123!`
   - ⚠️ **You will be required to change the password immediately**

4. **Add Cameras**:
   - Use "Scan Network" to auto-discover cameras
   - Or manually add camera IPs and credentials

## 🔑 Default Admin Credentials

**Username**: `admin`  
**Password**: `Admin123!`

> **⚠️ IMPORTANT**: You will be required to change this password on your first login for security reasons.

### First-Time Setup

1. Run the application:
   ```powershell
   python app.py
   ```

2. Open your browser to `http://localhost:5000`

3. Login with:
   - **Username**: `admin`
   - **Password**: `Admin123!`

4. You will be redirected to change your password immediately.

5. Create a strong password that meets the requirements:
   - Minimum 8 characters
   - At least 1 uppercase letter
   - At least 1 lowercase letter
   - At least 1 number
   - At least 1 special character (!@#$%^&*(),.?":{}|<>)

### If You Forget Your Password

If you need to reset the admin password:

1. Stop the application
2. Delete the database:
   ```powershell
   Remove-Item instance/cameras.db
   ```
3. Restart the application - it will recreate the admin user with the default password

## 📖 Usage Guide

### **Live Monitoring**
- Navigate to "Live View" section
- Switch between Grid and Multi-View modes
- Select layout (1, 4, 9, 16, 64 views)
- Add cameras to multi-view display
- Use PTZ controls for camera movement

### **Video Playback**
- Go to "Playback" section
- Select camera and date/time
- Use playback controls and speed adjustment
- Export important video clips

### **Analytics Dashboard**
- View motion detection charts
- Monitor people counting statistics
- Review recent security events
- Configure alert thresholds

### **E-Map Setup**
- Upload floor plan images
- Position camera icons on the map
- Click cameras for instant viewing
- Monitor coverage areas visually

### **Device Management**
- View all connected devices
- Configure camera settings
- Monitor device health
- Update firmware remotely

## 🔧 Configuration

Edit `.env` file for customization:
```
IP_RANGE=192.168.1.0/24
PORT=554
SECRET_KEY=your-secret-key
```

## 🐳 Docker Deployment

> **🚀 NEW: Automated Deployment Available!**  
> CamPy now supports automated Docker image builds and easy rehosting.  
> See **[DEPLOYMENT.md](DEPLOYMENT.md)** for the complete rehosting guide.

### Quick Deploy (Recommended)

Using pre-built images from Docker Hub:

**Linux/Mac:**
```bash
# One-time setup
cp .env.example .env
# Edit .env with your configuration

# Deploy (pulls latest image)
chmod +x deploy.sh
./deploy.sh prod
```

**Windows:**
```powershell
# One-time setup
Copy-Item .env.example .env
# Edit .env with your configuration

# Deploy (pulls latest image)
.\deploy.ps1 -Mode prod
```

### Manual Docker Deployment

#### Development Setup
```bash
# Pull and start development environment
docker-compose up -d

# View logs
docker-compose logs -f
```

#### Production Setup
```bash
# Pull and start production environment with Nginx reverse proxy
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Stop production environment
docker-compose -f docker-compose.prod.yml down
```

### Production Features
- **Gunicorn WSGI Server**: Production-ready WSGI server with optimized worker configuration
- **Nginx Reverse Proxy**: Load balancing, SSL termination, and static file serving
- **Health Checks**: Automatic container health monitoring
- **Logging**: Structured JSON logging with log rotation
- **Security Headers**: XSS protection, content security policy, and frame options
- **Gzip Compression**: Optimized content delivery
- **Auto-Build**: GitHub Actions automatically builds images on code push

### Access URLs
- **Production**: http://localhost (via Nginx on port 80)
- **Direct Flask**: http://localhost:5000 (for debugging)

### Documentation
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide with rehosting instructions
- **[DOCKER_QUICK_REF.md](DOCKER_QUICK_REF.md)** - Quick command reference
- **[REHOSTING_CHECKLIST.md](REHOSTING_CHECKLIST.md)** - Step-by-step deployment checklist
- **Health Check**: http://localhost/health

### Environment Variables
Edit `.env` file for customization:
```
IP_RANGE=192.168.1.0/24
PORT=554
SECRET_KEY=your-secret-key
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=your-admin-password
```

### Testing Docker Setup
Run the included test script to validate your Docker deployment:
```bash
# Windows
test_docker_setup.bat

# Linux/Mac
./test_docker_setup.sh
```

## 📞 Support

This dashboard provides enterprise-grade surveillance management with features comparable to commercial VMS systems like CamGuid, Milestone XProtect, and Genetec Security Center.

## 📈 Roadmap

- [ ] AI-powered object detection
- [ ] Advanced facial recognition
- [ ] License plate recognition
- [ ] Mobile app companion
- [ ] Cloud storage integration
- [ ] API documentation
- [ ] Multi-user collaboration"# CamGuid" 
