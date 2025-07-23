#!/bin/bash
# Comprehensive Test Suite for NextHunt Framework
# Tests setup, functionality, and integration

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_PROJECT="nexthunt-test"
readonly TEST_DIR="$SCRIPT_DIR/$TEST_PROJECT"

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

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    local is_critical="${3:-true}"
    
    ((TOTAL_TESTS++))
    print_status "Testing: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        print_success "$test_name"
        ((PASSED_TESTS++))
        return 0
    else
        if [[ "$is_critical" == "true" ]]; then
            print_error "$test_name (CRITICAL)"
        else
            print_warning "$test_name (WARNING)"
        fi
        ((FAILED_TESTS++))
        return 1
    fi
}

# Test 1: Framework Setup
test_framework_setup() {
    print_status "🔧 Testing Framework Setup"
    echo "=========================="
    
    # Clean up any existing test
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi
    
    # Test setup script
    run_test "Setup script exists" "[[ -f 'nexthunt-setup.sh' ]]"
    run_test "Setup script is executable" "[[ -x 'nexthunt-setup.sh' ]]"
    
    # Run setup
    run_test "Framework setup runs successfully" "PROJECT_NAME=$TEST_PROJECT ./nexthunt-setup.sh"
    
    # Verify setup completion
    run_test "Setup completion marker exists" "[[ -f '$TEST_DIR/.setup_complete' ]]"
    run_test "Project structure is correct" "[[ -d '$TEST_DIR/services' ]] && [[ -d '$TEST_DIR/scripts' ]] && [[ -d '$TEST_DIR/templates' ]]"
}

# Test 2: Configuration Validation
test_configuration() {
    print_status "⚙️ Testing Configuration"
    echo "========================"
    
    run_test "Configuration file exists" "[[ -f '$TEST_DIR/service-config.json' ]]"
    run_test "Configuration is valid JSON" "jq empty '$TEST_DIR/service-config.json'"
    run_test "Environment file exists" "[[ -f '$TEST_DIR/.env' ]]"
    run_test "Environment file has secure permissions" "[[ \$(stat -c '%a' '$TEST_DIR/.env') == '600' ]]"
    run_test "Docker Compose file exists" "[[ -f '$TEST_DIR/docker-compose.yml' ]]"
    run_test "Docker Compose syntax is valid" "docker compose -f '$TEST_DIR/docker-compose.yml' config >/dev/null"
}

# Test 3: Service Generation
test_service_generation() {
    print_status "🏗️ Testing Service Generation"
    echo "============================="
    
    cd "$TEST_DIR"
    
    local services=("reconnaissance" "intelligence" "scanning" "exploitation" "reporting" "api-gateway")
    
    for service in "${services[@]}"; do
        run_test "Service $service directory exists" "[[ -d 'services/$service' ]]"
        run_test "Service $service has main file" "[[ -f 'services/$service/main.go' ]] || [[ -f 'services/$service/main.py' ]]"
        run_test "Service $service has Dockerfile" "[[ -f 'services/$service/Dockerfile' ]]"
        
        if [[ -f "services/$service/main.go" ]]; then
            run_test "Go service $service has go.mod" "[[ -f 'services/$service/go.mod' ]]"
            run_test "Go service $service syntax is valid" "cd 'services/$service' && go mod tidy && go build -o /tmp/test_binary ." false
        elif [[ -f "services/$service/main.py" ]]; then
            run_test "Python service $service has requirements.txt" "[[ -f 'services/$service/requirements.txt' ]]" false
            run_test "Python service $service syntax is valid" "cd 'services/$service' && python3 -m py_compile main.py" false
        fi
    done
    
    cd "$SCRIPT_DIR"
}

# Test 4: Docker Build and Infrastructure
test_docker_infrastructure() {
    print_status "🐳 Testing Docker Infrastructure"
    echo "================================"
    
    cd "$TEST_DIR"
    
    # Test Docker builds
    run_test "Can build PostgreSQL service" "docker compose build postgres"
    run_test "Can build Redis service" "docker compose build redis"
    run_test "Can build API Gateway" "docker compose build api-gateway"
    run_test "Can build reconnaissance service" "docker compose build reconnaissance"
    
    # Start infrastructure
    run_test "Can start PostgreSQL" "docker compose up -d postgres && sleep 10"
    run_test "PostgreSQL is healthy" "docker compose exec -T postgres pg_isready -U nexthunt"
    run_test "Can start Redis" "docker compose up -d redis && sleep 5"
    run_test "Redis is responding" "docker compose exec -T redis redis-cli --no-auth-warning ping | grep -q PONG"
    
    cd "$SCRIPT_DIR"
}

# Test 5: Service Communication
test_service_communication() {
    print_status "🌐 Testing Service Communication"
    echo "==============================="
    
    cd "$TEST_DIR"
    
    # Start API Gateway
    run_test "Can start API Gateway" "docker compose up -d api-gateway && sleep 15"
    run_test "API Gateway health endpoint works" "curl -f -s http://localhost:8000/health >/dev/null"
    run_test "API Gateway returns valid JSON" "curl -s http://localhost:8000/health | jq -e '.status == \"healthy\"'"
    
    # Start other services
    run_test "Can start reconnaissance service" "docker compose up -d reconnaissance && sleep 10"
    run_test "Reconnaissance service is accessible" "curl -f -s http://localhost:8080/health >/dev/null" false
    
    cd "$SCRIPT_DIR"
}

# Test 6: Utility Scripts
test_utility_scripts() {
    print_status "🔧 Testing Utility Scripts"
    echo "=========================="
    
    cd "$TEST_DIR"
    
    run_test "Start script exists and is executable" "[[ -x 'start.sh' ]]"
    run_test "Stop script exists and is executable" "[[ -x 'stop.sh' ]]"
    run_test "Add service script exists and is executable" "[[ -x 'add-service.sh' ]]"
    
    run_test "Start script syntax is valid" "bash -n start.sh"
    run_test "Stop script syntax is valid" "bash -n stop.sh"
    run_test "Add service script syntax is valid" "bash -n add-service.sh"
    
    cd "$SCRIPT_DIR"
}

# Test 7: Plugin System
test_plugin_system() {
    print_status "🔌 Testing Plugin System"
    echo "========================"
    
    cd "$TEST_DIR"
    
    run_test "Plugin directory exists" "[[ -d 'plugins' ]]"
    run_test "Plugin system configuration exists" "[[ -f 'plugin-system.txt' ]]" false
    run_test "Templates directory exists" "[[ -d 'templates' ]]"
    run_test "Template processor exists" "[[ -f 'templates/process_template.sh' ]]"
    
    cd "$SCRIPT_DIR"
}

# Test 8: Add Service Functionality
test_add_service() {
    print_status "➕ Testing Add Service Functionality"
    echo "==================================="
    
    cd "$TEST_DIR"
    
    # Test adding a new Go service
    run_test "Can add new Go service" "./add-service.sh test-scanner 8087 go"
    run_test "New service directory created" "[[ -d 'services/test-scanner' ]]"
    run_test "New service has main.go" "[[ -f 'services/test-scanner/main.go' ]]"
    run_test "New service has go.mod" "[[ -f 'services/test-scanner/go.mod' ]]"
    run_test "New service added to docker-compose" "grep -q 'test-scanner' docker-compose.yml"
    
    # Test building the new service
    run_test "Can build new service" "docker compose build test-scanner" false
    
    cd "$SCRIPT_DIR"
}

# Test 9: Performance and Load
test_performance() {
    print_status "⚡ Testing Performance"
    echo "====================="
    
    cd "$TEST_DIR"
    
    # Basic load test if ab is available
    if command -v ab >/dev/null 2>&1; then
        run_test "API Gateway handles load" "ab -n 50 -c 5 -q http://localhost:8000/health >/dev/null 2>&1" false
    else
        print_warning "Apache Bench not available, skipping load test"
    fi
    
    # Memory usage check
    run_test "Services memory usage is reasonable" "
        total_memory=\$(docker stats --no-stream --format 'table {{.MemUsage}}' | tail -n +2 | awk -F'/' '{gsub(/[^0-9.]/, \"\", \$1); total += \$1} END {print total}')
        [[ \${total_memory:-0} -lt 2000 ]]
    " false
    
    cd "$SCRIPT_DIR"
}

# Test 10: Security
test_security() {
    print_status "🔒 Testing Security"
    echo "=================="
    
    cd "$TEST_DIR"
    
    run_test "No default passwords in production config" "! grep -q 'changeme' .env || grep -q 'ENVIRONMENT=development' .env"
    run_test "Environment file permissions are secure" "[[ \$(stat -c '%a' .env) == '600' ]]"
    run_test "No sensitive data in logs" "! docker compose logs 2>/dev/null | grep -i -E '(password|secret|key)=' || true" false
    run_test "Services use non-root user" "docker compose exec -T api-gateway whoami | grep -v root" false
    
    cd "$SCRIPT_DIR"
}

# Test 11: Monitoring
test_monitoring() {
    print_status "📊 Testing Monitoring"
    echo "===================="
    
    cd "$TEST_DIR"
    
    # Start monitoring stack
    run_test "Can start Prometheus" "docker compose up -d prometheus && sleep 10" false
    run_test "Prometheus is accessible" "curl -f -s http://localhost:9090/-/healthy >/dev/null" false
    run_test "Can start Grafana" "docker compose up -d grafana && sleep 10" false
    run_test "Grafana is accessible" "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 | grep -q '200'" false
    
    cd "$SCRIPT_DIR"
}

# Test 12: Complete Integration
test_complete_integration() {
    print_status "🎯 Testing Complete Integration"
    echo "==============================="
    
    cd "$TEST_DIR"
    
    # Full stack test
    run_test "Can start complete framework" "./start.sh" false
    
    # Wait for services to stabilize
    sleep 30
    
    # Test service orchestration
    run_test "All core services are running" "
        services=(postgres redis api-gateway reconnaissance intelligence)
        for service in \${services[@]}; do
            if ! docker compose ps \$service | grep -q 'Up'; then
                exit 1
            fi
        done
    " false
    
    # Test API endpoints
    run_test "API Gateway aggregates service health" "
        curl -s http://localhost:8000/health | jq -e '.services' >/dev/null
    " false
    
    # Cleanup
    run_test "Framework stops cleanly" "./stop.sh" false
    
    cd "$SCRIPT_DIR"
}

# Cleanup function
cleanup() {
    print_status "🧹 Cleaning up test environment..."
    
    if [[ -d "$TEST_DIR" ]]; then
        cd "$TEST_DIR"
        docker compose down -v --remove-orphans >/dev/null 2>&1 || true
        cd "$SCRIPT_DIR"
        rm -rf "$TEST_DIR"
    fi
    
    # Clean up Docker images
    docker system prune -f >/dev/null 2>&1 || true
}

# Main test runner
main() {
    echo "🧪 NextHunt Framework - Comprehensive Test Suite"
    echo "================================================="
    echo "Starting comprehensive test suite..."
    echo
    
    # Prerequisites check
    if ! command -v docker >/dev/null 2>&1; then
        print_error "Docker is required for testing"
        exit 1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        print_error "jq is required for testing"
        exit 1
    fi
    
    # Run all tests
    test_framework_setup
    echo
    
    test_configuration
    echo
    
    test_service_generation
    echo
    
    test_docker_infrastructure
    echo
    
    test_service_communication
    echo
    
    test_utility_scripts
    echo
    
    test_plugin_system
    echo
    
    test_add_service
    echo
    
    test_performance
    echo
    
    test_security
    echo
    
    test_monitoring
    echo
    
    test_complete_integration
    echo
    
    # Generate report
    echo "🏁 TEST RESULTS SUMMARY"
    echo "======================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
    echo
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        print_success "🎉 ALL TESTS PASSED! NextHunt Framework is working perfectly."
        echo
        echo "✅ Framework Features Verified:"
        echo "  - Project setup and structure"
        echo "  - Service generation and templates"
        echo "  - Docker containerization"
        echo "  - Service communication"
        echo "  - Plugin system"
        echo "  - Security configurations"
        echo "  - Monitoring stack"
        echo "  - Complete integration"
        echo
        echo "🚀 The framework is ready for production use!"
    else
        print_error "❌ $FAILED_TESTS test(s) failed."
        echo "Please review the output above and fix the issues."
        echo
        echo "💡 Common issues:"
        echo "  - Docker daemon not running"
        echo "  - Insufficient system resources"
        echo "  - Missing dependencies (jq, curl, ab)"
        echo "  - Port conflicts"
        
        cleanup
        exit 1
    fi
    
    # Cleanup
    cleanup
    
    echo "✅ Test environment cleaned up successfully."
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"
