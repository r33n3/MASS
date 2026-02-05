# MASS Local Development Setup

This guide covers setting up MASS for local development and testing using Docker.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start Options](#quick-start-options)
3. [Option 1: Lightweight Setup (SQLite)](#option-1-lightweight-setup-sqlite)
4. [Option 2: Full Setup (PostgreSQL + Redis)](#option-2-full-setup-postgresql--redis)
5. [Managing the Environment](#managing-the-environment)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
- **Docker Compose** v2.0+
- **Git**

Verify installation:
```bash
docker --version
docker-compose --version
```

---

## Quick Start Options

MASS provides two Docker Compose configurations:

| Setup | Database | Cache | Queue | Best For |
|-------|----------|-------|-------|----------|
| **Lite** | SQLite (file) | None | In-memory | Quick testing, development |
| **Full** | PostgreSQL | Redis | Redis | Production-like testing |

---

## Option 1: Lightweight Setup (SQLite)

Perfect for quick testing without external dependencies.

### 1. Start the Lite Environment

```bash
# Start with SQLite
docker-compose -f docker-compose.lite.yml up
```

### 2. Verify it's Running

```bash
# Check the API health
curl http://localhost:8000/health

# Or open in browser
# http://localhost:8000/docs
```

### 3. Stop the Environment

```bash
docker-compose -f docker-compose.lite.yml down
```

### What You Get

- ✅ MASS API running on port 8000
- ✅ SQLite database (stored in `./data/mass.db`)
- ✅ In-memory job queue
- ✅ API documentation at http://localhost:8000/docs
- ✅ Fast startup, minimal resource usage

### Limitations

- ❌ No Redis caching
- ❌ No distributed job queue
- ❌ Single process only
- ❌ Not suitable for load testing

---

## Option 2: Full Setup (PostgreSQL + Redis)

Production-like environment with PostgreSQL and Redis.

### 1. Create Environment File

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env if needed (optional for local testing)
```

### 2. Start the Full Environment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api
```

### 3. Verify Services

```bash
# Check all services are running
docker-compose ps

# Should show:
# - mass-postgres (port 5432)
# - mass-redis (port 6379)
# - mass-api (port 8000)
```

### 4. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **MASS API** | http://localhost:8000 | - |
| **API Docs** | http://localhost:8000/docs | - |
| **PostgreSQL** | localhost:5432 | user: `mass`, pass: `mass` |
| **Redis** | localhost:6379 | - |

### 5. Optional: Management Tools

Start pgAdmin and Redis Commander for database/cache management:

```bash
# Start with management tools
docker-compose --profile tools up -d

# Access tools:
# - pgAdmin: http://localhost:5050 (admin@mass.local / admin)
# - Redis Commander: http://localhost:8081
```

### 6. Stop the Environment

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

### What You Get

- ✅ MASS API on port 8000
- ✅ PostgreSQL database on port 5432
- ✅ Redis cache/queue on port 6379
- ✅ Database migrations run automatically
- ✅ Hot-reload for code changes
- ✅ Production-like environment
- ✅ Optional management UIs

---

## Managing the Environment

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Run Database Migrations

```bash
# Migrations run automatically on startup, but you can run manually:
docker-compose run --rm migrate
```

### Access Service Shells

```bash
# API container shell
docker-compose exec api bash

# PostgreSQL shell
docker-compose exec postgres psql -U mass -d mass

# Redis CLI
docker-compose exec redis redis-cli
```

### Rebuild After Code Changes

```bash
# Rebuild the API container
docker-compose build api

# Restart with new build
docker-compose up -d --build api
```

### Run Background Workers

```bash
# Start worker for scan processing
docker-compose --profile workers up -d worker
```

---

## Testing

### Using the API

```bash
# Check API health
curl http://localhost:8000/health

# Example: Create a scan (once authenticated)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "deployment_id": "dep_test",
    "profile": "standard"
  }'
```

### Running Tests

```bash
# Run tests inside the container
docker-compose exec api pytest

# Run with coverage
docker-compose exec api pytest --cov=mass --cov-report=html

# Run specific test
docker-compose exec api pytest tests/test_api.py
```

### Python SDK Testing

```python
# From your host machine or container
from mass_sdk import MassClient

client = MassClient(
    base_url="http://localhost:8000",
    api_key="your-api-key"
)

# Test the connection
health = client.health.check()
print(health)
```

---

## Configuration

### Environment Variables

All configuration is via environment variables. See [.env.example](.env.example) for full list.

**Key Variables:**

```bash
# Database
MASS_DB_URL=postgresql+asyncpg://mass:mass@postgres:5432/mass

# Redis
MASS_REDIS_URL=redis://redis:6379/0

# API
MASS_API_PORT=8000
MASS_DEBUG=true

# AI Provider Keys (optional)
MASS_OPENAI_API_KEY=sk-xxx
MASS_ANTHROPIC_API_KEY=sk-ant-xxx
```

### Switching Between SQLite and PostgreSQL

**Use SQLite:**
```bash
MASS_DB_URL=sqlite+aiosqlite:///./data/mass.db
```

**Use PostgreSQL:**
```bash
MASS_DB_URL=postgresql+asyncpg://mass:mass@postgres:5432/mass
```

---

## Troubleshooting

### Port Already in Use

```bash
# Change ports in docker-compose.yml or .env
# Example: Use port 8001 instead of 8000
ports:
  - "8001:8000"
```

### Database Connection Errors

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Reset database
docker-compose down -v
docker-compose up -d
```

### Redis Connection Errors

```bash
# Check Redis is running
docker-compose exec redis redis-cli ping
# Should return: PONG

# Restart Redis
docker-compose restart redis
```

### API Won't Start

```bash
# Check API logs
docker-compose logs api

# Common issues:
# 1. Database not ready - wait a few seconds and retry
# 2. Migration failures - check database connection
# 3. Port in use - change port in docker-compose.yml
```

### Clean Slate

```bash
# Remove everything and start fresh
docker-compose down -v
rm -rf data/
docker-compose up -d --build
```

### Container Shows as Unhealthy

```bash
# Check specific health status
docker inspect mass-postgres | grep -A 10 Health
docker inspect mass-redis | grep -A 10 Health

# Wait for services to become healthy
docker-compose up -d
sleep 10
docker-compose ps
```

---

## Development Workflow

### Typical Development Flow

```bash
# 1. Start environment (first time or after clean)
docker-compose up -d

# 2. Make code changes in ./src
# (Hot-reload will restart the API automatically)

# 3. View logs to verify changes
docker-compose logs -f api

# 4. Run tests
docker-compose exec api pytest

# 5. Stop when done
docker-compose down
```

### Volume Mounts

The following directories are mounted for live editing:

- `./src` → `/app/src` (API code)
- `./tests` → `/app/tests` (Test code)
- `./data` → `/app/data` (SQLite DB, storage)

Changes to these files are immediately reflected in the container.

---

## Next Steps

After getting the environment running:

1. **Read the [API Documentation](http://localhost:8000/docs)**
2. **Check [CONTRIBUTING.md](CONTRIBUTING.md)** for contribution guidelines
3. **Review [README.md](README.md)** for feature overview
4. **Explore the [docs/](docs/)** directory for detailed guides

---

## Quick Reference

```bash
# Lite Setup (SQLite)
docker-compose -f docker-compose.lite.yml up

# Full Setup (PostgreSQL + Redis)
docker-compose up -d

# With Management Tools
docker-compose --profile tools up -d

# With Workers
docker-compose --profile workers up -d

# View Logs
docker-compose logs -f api

# Run Tests
docker-compose exec api pytest

# Stop Everything
docker-compose down

# Nuclear Option (delete all data)
docker-compose down -v && rm -rf data/
```

---

## Cost Comparison

| Setup | Local (Docker) | AWS Equivalent |
|-------|----------------|----------------|
| **Lite** | Free | ~$15/month (single EC2) |
| **Full** | Free | ~$67/month (RDS + ElastiCache + Fargate) |

Local Docker development is completely free! 🎉
