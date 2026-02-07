#!/bin/bash
# MASS Quick Start Script
# This script helps you quickly start MASS in different configurations

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════╗
║   MASS - Model & Application Security Suite      ║
║   Local Development Environment                  ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
        exit 1
    fi
}

# Function to create .env if it doesn't exist
setup_env() {
    if [ ! -f .env ]; then
        echo -e "${YELLOW}Creating .env file from template...${NC}"
        cp .env.example .env
        echo -e "${GREEN}✓ .env file created${NC}"
    fi
}

# Function to start lite setup
start_lite() {
    echo -e "${BLUE}Starting MASS in Lite Mode (SQLite)...${NC}"
    docker-compose -f docker-compose.lite.yml up -d
    echo -e "${GREEN}✓ MASS Lite is starting!${NC}"
    echo ""
    echo -e "${BLUE}Access the API at:${NC} http://localhost:8000"
    echo -e "${BLUE}API Docs:${NC} http://localhost:8000/docs"
}

# Function to start full setup
start_full() {
    echo -e "${BLUE}Starting MASS in Full Mode (PostgreSQL + Redis)...${NC}"
    docker-compose up -d
    echo -e "${GREEN}✓ MASS Full is starting!${NC}"
    echo ""
    echo -e "${BLUE}Services:${NC}"
    echo "  - API: http://localhost:8000"
    echo "  - API Docs: http://localhost:8000/docs"
    echo "  - PostgreSQL: localhost:5432 (user: mass, pass: mass)"
    echo "  - Redis: localhost:6379"
}

# Function to start with tools
start_tools() {
    echo -e "${BLUE}Starting MASS with Management Tools...${NC}"
    docker-compose --profile tools up -d
    echo -e "${GREEN}✓ MASS with tools is starting!${NC}"
    echo ""
    echo -e "${BLUE}Services:${NC}"
    echo "  - API: http://localhost:8000"
    echo "  - API Docs: http://localhost:8000/docs"
    echo "  - pgAdmin: http://localhost:5050 (admin@mass.local / admin)"
    echo "  - Redis Commander: http://localhost:8081"
}

# Function to show logs
show_logs() {
    echo -e "${BLUE}Showing logs (Ctrl+C to exit)...${NC}"
    docker-compose logs -f
}

# Function to stop services
stop_services() {
    echo -e "${YELLOW}Stopping MASS services...${NC}"
    docker-compose down
    docker-compose -f docker-compose.lite.yml down
    echo -e "${GREEN}✓ Services stopped${NC}"
}

# Function to show status
show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    docker-compose ps
}

# Main menu
show_menu() {
    echo ""
    echo "Choose a setup option:"
    echo ""
    echo "  1) Lite Mode     - Quick testing with SQLite (fastest)"
    echo "  2) Full Mode     - PostgreSQL + Redis (production-like)"
    echo "  3) With Tools    - Full mode + pgAdmin + Redis Commander"
    echo "  4) Show Logs     - View service logs"
    echo "  5) Status        - Check service status"
    echo "  6) Stop All      - Stop all services"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
}

# Check Docker first
check_docker

# Setup .env
setup_env

# Show menu if no arguments
if [ $# -eq 0 ]; then
    while true; do
        show_menu
        case $choice in
            1) start_lite ;;
            2) start_full ;;
            3) start_tools ;;
            4) show_logs ;;
            5) show_status ;;
            6) stop_services ;;
            7) echo "Goodbye!"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
    done
else
    # Handle command line arguments
    case $1 in
        lite) start_lite ;;
        full) start_full ;;
        tools) start_tools ;;
        logs) show_logs ;;
        status) show_status ;;
        stop) stop_services ;;
        *)
            echo "Usage: $0 [lite|full|tools|logs|status|stop]"
            exit 1
            ;;
    esac
fi
