#!/bin/bash
#
# PostgreSQL Restore Script for CamGuid
# Restores database from backup file
#

# Configuration
BACKUP_DIR="./backups"
POSTGRES_USER="${POSTGRES_USER:-camguid}"
POSTGRES_DB="${POSTGRES_DB:-camguid}"
CONTAINER_NAME="camguid-postgres"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "CamGuid PostgreSQL Restore"
echo "=========================================="

# List available backups
echo ""
echo "Available backups:"
echo "------------------"
ls -lh "${BACKUP_DIR}"/camguid_backup_*.sql.gz 2>/dev/null | awk '{print $9, "(" $5 ")"}'

# Check if any backups exist
if [ ! "$(ls -A ${BACKUP_DIR}/camguid_backup_*.sql.gz 2>/dev/null)" ]; then
    echo -e "${RED}✗ No backup files found in ${BACKUP_DIR}${NC}"
    exit 1
fi

echo ""
read -p "Enter backup filename to restore (or 'latest' for most recent): " BACKUP_CHOICE

# Determine backup file
if [ "${BACKUP_CHOICE}" = "latest" ]; then
    BACKUP_FILE=$(ls -t "${BACKUP_DIR}"/camguid_backup_*.sql.gz | head -1)
    echo "Selected: ${BACKUP_FILE}"
else
    BACKUP_FILE="${BACKUP_DIR}/${BACKUP_CHOICE}"
fi

# Check if file exists
if [ ! -f "${BACKUP_FILE}" ]; then
    echo -e "${RED}✗ Backup file not found: ${BACKUP_FILE}${NC}"
    exit 1
fi

# Warning
echo ""
echo -e "${YELLOW}⚠️  WARNING: This will DELETE all current data in the database!${NC}"
read -p "Type 'YES' to continue: " CONFIRM

if [ "${CONFIRM}" != "YES" ]; then
    echo "Restore cancelled."
    exit 0
fi

# Check if container is running
if ! docker ps | grep -q "${CONTAINER_NAME}"; then
    echo -e "${RED}✗ Error: PostgreSQL container '${CONTAINER_NAME}' is not running${NC}"
    exit 1
fi

# Decompress if needed
TEMP_FILE="/tmp/restore_temp.sql"
if [[ "${BACKUP_FILE}" == *.gz ]]; then
    echo "Decompressing backup..."
    gunzip -c "${BACKUP_FILE}" > "${TEMP_FILE}"
else
    cp "${BACKUP_FILE}" "${TEMP_FILE}"
fi

# Stop application
echo ""
echo "Stopping application..."
docker-compose stop camera-dashboard

# Drop and recreate database
echo "Recreating database..."
docker exec -t "${CONTAINER_NAME}" psql -U "${POSTGRES_USER}" -c "DROP DATABASE IF EXISTS ${POSTGRES_DB};"
docker exec -t "${CONTAINER_NAME}" psql -U "${POSTGRES_USER}" -c "CREATE DATABASE ${POSTGRES_DB};"

# Restore backup
echo "Restoring backup..."
cat "${TEMP_FILE}" | docker exec -i "${CONTAINER_NAME}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database restored successfully${NC}"
    
    # Cleanup
    rm -f "${TEMP_FILE}"
    
    # Restart application
    echo ""
    echo "Restarting application..."
    docker-compose start camera-dashboard
    
    echo ""
    echo -e "${GREEN}✓ Restore complete!${NC}"
    echo "Application should be available at http://localhost:5000"
else
    echo -e "${RED}✗ Restore failed${NC}"
    rm -f "${TEMP_FILE}"
    exit 1
fi

echo ""
echo "=========================================="
echo "Restore Complete"
echo "=========================================="
