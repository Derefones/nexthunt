#!/bin/bash
# NextHunt Framework - Quickstart Script
# Complete setup and test in one command

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

quickstart() {
    echo "🚀 NextHunt Framework Quickstart"
    echo "================================"
    echo
    
    # Check prerequisites
    if ! command -v docker &>/dev/null; then
        print_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! docker info &>/dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    # Step 1: Setup
    print_status "Step 1: Setting up NextHunt framework..."
    if ! ./nexthunt-setup.sh setup; then
        print_error "Setup failed"
        exit 1
    fi
    
    # Step 2: Start services
    print_status "Step 2: Starting services..."
    cd nexthunt || {
        print_error "Failed to enter nexthunt directory"
        exit 1
    }
    
    # Check if already running
    if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q .; then
        print_warning "Services already running, stopping first..."
        ./stop.sh || true
        sleep 5
    fi
    
    if ! ./start.sh; then
        print_error "Failed to start services"
        exit 1
    fi
    
    # Step 3: Wait for services
    print_status "Step 3: Waiting for services to be ready..."
    local max_wait=120
    local waited=0
    
    while [[ $waited -lt $max_wait ]]; do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
        ((waited += 2))
        echo -n "."
    done
    echo
    
    if [[ $waited -ge $max_wait ]]; then
        print_error "Services failed to start within ${max_wait}s"
        echo "Check logs with: docker compose logs"
        exit 1
    fi
    
    # Step 4: Test services
    print_status "Step 4: Testing services..."
    test_services
    
    # Step 5: Show results
    print_success "🎉 NextHunt Framework is ready!"
    echo
    echo "Access Points:"
    echo "- API Gateway: http://localhost:8000"
    echo "- Health Check: http://localhost:8000/health"
    echo "- Grafana (if enabled): http://localhost:3000"
    echo "- Prometheus (if enabled): http://localhost:9090"
    echo
    echo "Quick Commands:"
    echo "- View logs: docker compose logs -f [service-name]"
    echo "- Stop framework: ./stop.sh"
    echo "- Add service: ./add-service.sh <name> <port> <language>"
    echo "- Framework status: docker compose ps"
    echo
    echo "Try these test commands:"
    echo "curl http://localhost:8000/health"
    echo "curl http://localhost:8000/"
}

demo_attack_simulation() {
    print_status "Running attack simulation demo..."
    
    print_status "1. Performing reconnaissance..."
    curl -s -X POST http://localhost:8080/api/v1/recon \
      -H "Content-Type: application/json" \
      -d '{"target": "demo-target.local", "techniques": ["subdomain-enum", "port-scan"]}' | jq . || true
    
    sleep 2
    
    print_status "2. Gathering intelligence..."
    curl -s -X POST http://localhost:8081/api/v1/intel \
      -H "Content-Type: application/json" \
      -d '{"target": "demo-target.local"}' | jq . || true
    
    sleep 2
    
    print_status "3. Running vulnerability scan..."
    curl -s -X POST http://localhost:8084/api/v1/scan \
      -H "Content-Type: application/json" \
      -d '{"target": "demo-target.local", "scan_type": "comprehensive"}' | jq . || true
    
    sleep 2
    
    print_status "4. Generating security report..."
    curl -s -X POST http://localhost:8085/api/v1/report \
      -H "Content-Type: application/json" \
      -d '{"target": "demo-target.local", "format": "pdf"}' | jq . || true
    
    print_success "Demo attack simulation completed!"
}

test_services() {
    local failed=0
    
    # Test API Gateway
    if curl -s http://localhost:8000/health | grep -q "healthy"; then
        print_success "API Gateway: OK"
    else
        print_error "API Gateway: FAILED"
        ((failed++))
    fi
    
    # Test database connectivity
    if docker compose exec -T postgres pg_isready -U nexthunt >/dev/null 2>&1; then
        print_success "Database: OK"
    else
        print_error "Database: FAILED"
        ((failed++))
    fi
    
    # Test Redis
    if docker compose exec -T redis redis-cli --no-auth-warning ping 2>/dev/null | grep -q "PONG"; then
        print_success "Redis: OK"
    else
        print_error "Redis: FAILED"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        print_warning "$failed critical services failed"
        echo "Framework may not work properly"
    fi
}

cleanup_demo() {
    echo
    print_status "Cleaning up demo environment..."
    if [[ -d "nexthunt" ]]; then
        cd nexthunt
        ./stop.sh || true
    fi
    print_success "Demo environment cleaned up"
}

show_usage() {
    cat << 'EOF'
NextHunt Framework Quickstart

Usage:
  ./quickstart.sh              - Complete setup and start
  ./quickstart.sh demo         - Setup + demo
  ./quickstart.sh test         - Test existing installation
  ./quickstart.sh cleanup      - Stop all services
  ./quickstart.sh help         - Show this help

Examples:
  ./quickstart.sh              # Full setup
  ./quickstart.sh demo         # Setup + demo
  ./quickstart.sh test         # Test current setup
EOF
}

# Main execution
case "${1:-start}" in
    "start"|"")
        quickstart
        ;;
    "demo")
        quickstart
        demo_attack_simulation
        ;;
    "test")
        if [[ -d "nexthunt" ]]; then
            cd nexthunt
            test_services
        else
            print_error "NextHunt not found. Run './quickstart.sh' first"
            exit 1
        fi
        ;;
    "cleanup")
        if [[ -d "nexthunt" ]]; then
            cleanup_demo
        else
            print_warning "No installation found to cleanup"
        fi
        ;;
    "help")
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
esac
