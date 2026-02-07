# MASS Quick Start Script for Windows PowerShell
# This script helps you quickly start MASS in different configurations

# Function to display banner
function Show-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════╗
║   MASS - Model & Application Security Suite      ║
║   Local Development Environment                  ║
╚══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

# Function to check if Docker is running
function Test-Docker {
    try {
        docker info | Out-Null
        return $true
    }
    catch {
        Write-Host "Error: Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
        return $false
    }
}

# Function to create .env if it doesn't exist
function Initialize-Environment {
    if (-not (Test-Path .env)) {
        Write-Host "Creating .env file from template..." -ForegroundColor Yellow
        Copy-Item .env.example .env
        Write-Host "✓ .env file created" -ForegroundColor Green
    }
}

# Function to start lite setup
function Start-Lite {
    Write-Host "Starting MASS in Lite Mode (SQLite)..." -ForegroundColor Blue
    docker-compose -f docker-compose.lite.yml up -d
    Write-Host "✓ MASS Lite is starting!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Access the API at: " -NoNewline -ForegroundColor Blue
    Write-Host "http://localhost:8000"
    Write-Host "API Docs: " -NoNewline -ForegroundColor Blue
    Write-Host "http://localhost:8000/docs"
}

# Function to start full setup
function Start-Full {
    Write-Host "Starting MASS in Full Mode (PostgreSQL + Redis)..." -ForegroundColor Blue
    docker-compose up -d
    Write-Host "✓ MASS Full is starting!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Services:" -ForegroundColor Blue
    Write-Host "  - API: http://localhost:8000"
    Write-Host "  - API Docs: http://localhost:8000/docs"
    Write-Host "  - PostgreSQL: localhost:5432 (user: mass, pass: mass)"
    Write-Host "  - Redis: localhost:6379"
}

# Function to start with tools
function Start-WithTools {
    Write-Host "Starting MASS with Management Tools..." -ForegroundColor Blue
    docker-compose --profile tools up -d
    Write-Host "✓ MASS with tools is starting!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Services:" -ForegroundColor Blue
    Write-Host "  - API: http://localhost:8000"
    Write-Host "  - API Docs: http://localhost:8000/docs"
    Write-Host "  - pgAdmin: http://localhost:5050 (admin@mass.local / admin)"
    Write-Host "  - Redis Commander: http://localhost:8081"
}

# Function to show logs
function Show-Logs {
    Write-Host "Showing logs (Ctrl+C to exit)..." -ForegroundColor Blue
    docker-compose logs -f
}

# Function to stop services
function Stop-Services {
    Write-Host "Stopping MASS services..." -ForegroundColor Yellow
    docker-compose down
    docker-compose -f docker-compose.lite.yml down
    Write-Host "✓ Services stopped" -ForegroundColor Green
}

# Function to show status
function Show-Status {
    Write-Host "Service Status:" -ForegroundColor Blue
    docker-compose ps
}

# Function to show menu
function Show-Menu {
    Write-Host ""
    Write-Host "Choose a setup option:"
    Write-Host ""
    Write-Host "  1) Lite Mode     - Quick testing with SQLite (fastest)"
    Write-Host "  2) Full Mode     - PostgreSQL + Redis (production-like)"
    Write-Host "  3) With Tools    - Full mode + pgAdmin + Redis Commander"
    Write-Host "  4) Show Logs     - View service logs"
    Write-Host "  5) Status        - Check service status"
    Write-Host "  6) Stop All      - Stop all services"
    Write-Host "  7) Exit"
    Write-Host ""
    $choice = Read-Host "Enter choice [1-7]"
    return $choice
}

# Main script
Show-Banner

# Check Docker
if (-not (Test-Docker)) {
    exit 1
}

# Setup environment
Initialize-Environment

# Handle command line arguments
if ($args.Count -gt 0) {
    switch ($args[0].ToLower()) {
        "lite" { Start-Lite }
        "full" { Start-Full }
        "tools" { Start-WithTools }
        "logs" { Show-Logs }
        "status" { Show-Status }
        "stop" { Stop-Services }
        default {
            Write-Host "Usage: .\start.ps1 [lite|full|tools|logs|status|stop]"
            exit 1
        }
    }
}
else {
    # Interactive menu
    while ($true) {
        $choice = Show-Menu
        switch ($choice) {
            "1" { Start-Lite }
            "2" { Start-Full }
            "3" { Start-WithTools }
            "4" { Show-Logs }
            "5" { Show-Status }
            "6" { Stop-Services }
            "7" {
                Write-Host "Goodbye!" -ForegroundColor Green
                exit 0
            }
            default { Write-Host "Invalid option" -ForegroundColor Red }
        }
    }
}
