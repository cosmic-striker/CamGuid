# Camera Dashboard Installation Script
Write-Host "=== Camera Dashboard Installation ===" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found. Please install Python 3.9 or higher." -ForegroundColor Red
    exit 1
}

# Create virtual environment
Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
if (Test-Path ".venv") {
    Write-Host "✓ Virtual environment already exists" -ForegroundColor Green
} else {
    python -m venv .venv
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "`nActivating virtual environment..." -ForegroundColor Yellow
.\.venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host "`nUpgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install requirements
Write-Host "`nInstalling dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Check if database exists
Write-Host "`nChecking database..." -ForegroundColor Yellow
if (Test-Path "instance\cameras.db") {
    Write-Host "✓ Database already exists" -ForegroundColor Green
} else {
    Write-Host "Creating database..." -ForegroundColor Yellow
    python -c "from app import app, db; app.app_context().push(); db.create_all(); print('✓ Database created')"
}

# Generate secure secret key
Write-Host "`nGenerating secure secret key..." -ForegroundColor Yellow
$secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
$envContent = Get-Content .env -Raw
$envContent = $envContent -replace 'SECRET_KEY=.*', "SECRET_KEY=$secretKey"
Set-Content .env -Value $envContent
Write-Host "✓ Secure secret key generated" -ForegroundColor Green

Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the application:" -ForegroundColor Yellow
Write-Host "  1. Activate virtual environment: .\.venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  2. Run: python app.py" -ForegroundColor White
Write-Host ""
Write-Host "Default login credentials:" -ForegroundColor Yellow
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: admin" -ForegroundColor White
Write-Host ""
Write-Host "Access the dashboard at: http://localhost:5000" -ForegroundColor Cyan
Write-Host ""
