# PostgreSQL Migration Guide

This guide helps you migrate from SQLite to PostgreSQL.

## 🚀 Fresh Installation (Recommended)

If you're setting up a new instance:

1. **Update configuration**:
   ```bash
   cp .env.example .env
   # Edit .env and set secure passwords
   ```

2. **Start services**:
   ```bash
   docker-compose up -d
   ```

3. **Initialize database**:
   ```bash
   docker-compose exec camera-dashboard python init_db.py
   ```

4. **Access application**:
   - URL: http://localhost:5000
   - Login: admin / Admin123!
   - Change password on first login

## 📦 Migrating Existing SQLite Data

If you have existing camera data in SQLite:

### Option 1: Manual Migration (Small Datasets)

1. **Export data from SQLite**:
   ```python
   # Export cameras
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
   
   print(f'Exported {len(data)} cameras')
   "
   ```

2. **Switch to PostgreSQL**:
   ```bash
   docker-compose up -d
   docker-compose exec camera-dashboard python init_db.py
   ```

3. **Import data**:
   ```python
   # Import cameras
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
       print(f'Imported {len(data)} cameras')
   "
   ```

### Option 2: Using pgloader (Large Datasets)

1. **Install pgloader**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install pgloader
   
   # macOS
   brew install pgloader
   ```

2. **Create migration script** (`migrate.load`):
   ```
   LOAD DATABASE
        FROM sqlite:///path/to/instance/cameras.db
        INTO postgresql://camguid:password@localhost:5432/camguid
   
   WITH include drop, create tables, create indexes, reset sequences
   
   SET work_mem to '16MB', maintenance_work_mem to '512 MB';
   ```

3. **Run migration**:
   ```bash
   pgloader migrate.load
   ```

## 🔍 Verification

After migration, verify your data:

```bash
# Check database
docker-compose exec db psql -U camguid -d camguid -c "
SELECT 
    (SELECT COUNT(*) FROM camera) as cameras,
    (SELECT COUNT(*) FROM \"user\") as users,
    (SELECT COUNT(*) FROM event) as events,
    (SELECT COUNT(*) FROM camera_group) as groups;
"
```

Expected output:
```
 cameras | users | events | groups 
---------+-------+--------+--------
      15 |     1 |      0 |      0
```

## 🔧 Troubleshooting

### Connection Issues

```bash
# Check PostgreSQL is running
docker-compose ps

# View PostgreSQL logs
docker-compose logs db

# Test connection
docker-compose exec db psql -U camguid -d camguid -c "SELECT version();"
```

### Database Reset

```bash
# Complete reset (WARNING: deletes all data)
docker-compose down -v
docker-compose up -d
docker-compose exec camera-dashboard python init_db.py
```

### Performance Tuning

For production, edit PostgreSQL settings in `docker-compose.prod.yml`:

```yaml
db:
  environment:
    POSTGRES_INITDB_ARGS: "-c shared_buffers=256MB -c max_connections=200"
```

## 📊 Performance Comparison

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Concurrent Writes | Limited | Excellent |
| Connection Pooling | N/A | Yes (10-20) |
| Max Database Size | 281 TB | Unlimited |
| ACID Compliance | Yes | Yes |
| Backup/Restore | File copy | pg_dump/pg_restore |
| Replication | No | Yes |
| Best For | Development | Production |

## 🎯 Next Steps

1. ✅ Migrate to PostgreSQL
2. ✅ Test all features
3. ✅ Set up backups
4. ✅ Monitor performance
5. ✅ Configure replication (optional)

## 📚 Additional Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [SQLAlchemy PostgreSQL Dialect](https://docs.sqlalchemy.org/en/14/dialects/postgresql.html)
- [Docker PostgreSQL](https://hub.docker.com/_/postgres)
