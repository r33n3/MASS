# Installation

## Requirements

- Python 3.10 or higher
- PostgreSQL 14+ (for production)
- Redis 7+ (for caching and queues)

## Quick Install

Install MASS from PyPI:

```bash
pip install mass
```

## Development Install

For development, clone the repository and install with dev dependencies:

```bash
git clone https://github.com/r33n3/MASS.git
cd MASS
pip install -e ".[dev]"
pre-commit install
```

## Docker Install

Run MASS using Docker Compose:

```bash
git clone https://github.com/r33n3/MASS.git
cd MASS
docker-compose up -d
```

## Verify Installation

Verify the installation:

```bash
mass --version
```

Or start the API server:

```bash
uvicorn mass.api.main:create_app --factory
```
