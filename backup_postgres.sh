#!/bin/bash
#
# PostgreSQL Backup Script for CamGuid
# Creates timestamped backups of the PostgreSQL database
#

# Configuration
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="camguid_backup_${TIMESTAMP}.sql"
POSTGRES_USER="${POSTGRES_USER:-camguid}"
POSTGRES_DB="${POSTGRES_DB:-camguid}"
CONTAINER_NAME="camguid-postgres"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "CamGuid PostgreSQL Backup"
echo "=========================================="

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

# Check if container is running
if ! docker ps | grep -q "${CONTAINER_NAME}"; then
    echo -e "${RED}✗ Error: PostgreSQL container '${CONTAINER_NAME}' is not running${NC}"
    exit 1
fi

# Perform backup
echo "Creating backup..."
docker exec -t "${CONTAINER_NAME}" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" > "${BACKUP_DIR}/${BACKUP_FILE}"

if [ $? -eq 0 ]; then
    # Compress backup
    echo "Compressing backup..."
    gzip "${BACKUP_DIR}/${BACKUP_FILE}"
    
    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}.gz" | cut -f1)
    echo -e "${GREEN}✓ Backup created successfully${NC}"
    echo "  File: ${BACKUP_DIR}/${BACKUP_FILE}.gz"
    echo "  Size: ${BACKUP_SIZE}"
    
    # Remove old backups (keep last 7 days)
    echo ""
    echo "Cleaning old backups (keeping last 7 days)..."
    find "${BACKUP_DIR}" -name "camguid_backup_*.sql.gz" -mtime +7 -delete
    
    BACKUP_COUNT=$(ls -1 "${BACKUP_DIR}"/camguid_backup_*.sql.gz 2>/dev/null | wc -l)
    echo -e "${GREEN}✓ Cleanup complete (${BACKUP_COUNT} backups retained)${NC}"
else
    echo -e "${RED}✗ Backup failed${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo "Backup Complete"
echo "=========================================="
