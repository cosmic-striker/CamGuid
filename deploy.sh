#!/bin/bash
# CamPy Deployment Script for Linux/Mac
# This script pulls the latest Docker image and restarts the containers

set -e

echo "=========================================="
echo "CamPy Docker Deployment Script"
echo "=========================================="
echo ""

# Load environment variables if .env exists
if [ -f .env ]; then
    echo "✓ Loading environment variables from .env file"
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "⚠ Warning: .env file not found. Using defaults."
fi

# Check if DOCKERHUB_USERNAME is set
if [ -z "$DOCKERHUB_USERNAME" ]; then
    echo "⚠ DOCKERHUB_USERNAME not set in .env file"
    echo "Please set it in .env or export it: export DOCKERHUB_USERNAME=your-username"
    exit 1
fi

echo "Docker Hub Username: $DOCKERHUB_USERNAME"
echo ""

# Determine which compose file to use
COMPOSE_FILE="docker-compose.yml"
if [ "$1" == "prod" ] || [ "$1" == "production" ]; then
    COMPOSE_FILE="docker-compose.prod.yml"
    echo "Using production configuration: $COMPOSE_FILE"
else
    echo "Using development configuration: $COMPOSE_FILE"
fi
echo ""

# Pull latest image
echo "📥 Pulling latest Docker image..."
docker pull ${DOCKERHUB_USERNAME}/campy:latest

# Stop existing containers
echo ""
echo "🛑 Stopping existing containers..."
docker-compose -f $COMPOSE_FILE down

# Start containers with latest image
echo ""
echo "🚀 Starting containers with latest image..."
docker-compose -f $COMPOSE_FILE up -d

# Wait for containers to be healthy
echo ""
echo "⏳ Waiting for containers to be healthy..."
sleep 5

# Show container status
echo ""
echo "📊 Container Status:"
docker-compose -f $COMPOSE_FILE ps

# Show logs
echo ""
echo "📜 Recent logs:"
docker-compose -f $COMPOSE_FILE logs --tail=50

echo ""
echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo ""
echo "Access your application at:"
if [ "$COMPOSE_FILE" == "docker-compose.prod.yml" ]; then
    echo "  http://localhost (port 80 via nginx)"
    echo "  https://localhost (port 443 via nginx)"
fi
echo "  http://localhost:5000 (direct to app)"
echo ""
echo "To view logs: docker-compose -f $COMPOSE_FILE logs -f"
echo "To stop: docker-compose -f $COMPOSE_FILE down"
echo ""
