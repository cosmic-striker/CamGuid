# CamPy Deployment Script for Windows (PowerShell)
# This script pulls the latest Docker image and restarts the containers

param(
    [string]$Mode = "dev"
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "CamPy Docker Deployment Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Load environment variables if .env exists
if (Test-Path .env) {
    Write-Host "✓ Loading environment variables from .env file" -ForegroundColor Green
    Get-Content .env | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]*)\s*=\s*(.+)\s*$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
} else {
    Write-Host "⚠ Warning: .env file not found. Using defaults." -ForegroundColor Yellow
}

# Check if DOCKERHUB_USERNAME is set
$dockerUsername = $env:DOCKERHUB_USERNAME
if (-not $dockerUsername) {
    Write-Host "⚠ DOCKERHUB_USERNAME not set in .env file" -ForegroundColor Red
    Write-Host "Please set it in .env or run: `$env:DOCKERHUB_USERNAME='your-username'" -ForegroundColor Red
    exit 1
}

Write-Host "Docker Hub Username: $dockerUsername" -ForegroundColor White
Write-Host ""

# Determine which compose file to use
$composeFile = "docker-compose.yml"
if ($Mode -eq "prod" -or $Mode -eq "production") {
    $composeFile = "docker-compose.prod.yml"
    Write-Host "Using production configuration: $composeFile" -ForegroundColor Yellow
} else {
    Write-Host "Using development configuration: $composeFile" -ForegroundColor Yellow
}
Write-Host ""

# Pull latest image
Write-Host "📥 Pulling latest Docker image..." -ForegroundColor Cyan
docker pull "$dockerUsername/campy:latest"

# Stop existing containers
Write-Host ""
Write-Host "🛑 Stopping existing containers..." -ForegroundColor Cyan
docker-compose -f $composeFile down

# Start containers with latest image
Write-Host ""
Write-Host "🚀 Starting containers with latest image..." -ForegroundColor Cyan
docker-compose -f $composeFile up -d

# Wait for containers to be healthy
Write-Host ""
Write-Host "⏳ Waiting for containers to be healthy..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

# Show container status
Write-Host ""
Write-Host "📊 Container Status:" -ForegroundColor Cyan
docker-compose -f $composeFile ps

# Show logs
Write-Host ""
Write-Host "📜 Recent logs:" -ForegroundColor Cyan
docker-compose -f $composeFile logs --tail=50

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "✅ Deployment Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access your application at:" -ForegroundColor White
if ($composeFile -eq "docker-compose.prod.yml") {
    Write-Host "  http://localhost (port 80 via nginx)" -ForegroundColor White
    Write-Host "  https://localhost (port 443 via nginx)" -ForegroundColor White
}
Write-Host "  http://localhost:5000 (direct to app)" -ForegroundColor White
Write-Host ""
Write-Host "To view logs: docker-compose -f $composeFile logs -f" -ForegroundColor Gray
Write-Host "To stop: docker-compose -f $composeFile down" -ForegroundColor Gray
Write-Host ""
