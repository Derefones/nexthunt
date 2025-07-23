#!/bin/bash
# Core Validation Functions for NextHunt Framework
# Shared validation logic to prevent duplication

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

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TEST_RESULTS=()

# Enhanced test result function
test_result() {
    local test_name="$1"
    local result="$2"
    local error_msg="${3:-}"
    local execution_time="${4:-0}"
    
    ((TOTAL_TESTS++))
    if [[ $result -eq 0 ]]; then
        print_success "$test_name"
        ((PASSED_TESTS++))
        TEST_RESULTS+=("PASS|$test_name|$execution_time|")
    else
        print_error "$test_name"
        if [[ -n "$error_msg" ]]; then
            echo "  └─ Error: $error_msg"
        fi
        ((FAILED_TESTS++))
        TEST_RESULTS+=("FAIL|$test_name|$execution_time|$error_msg")
    fi
    
    return $result
}

# Docker validation
validate_docker() {
    print_status "Validating Docker environment..."
    
    # Check if Docker is installed
    if ! command -v docker >/dev/null 2>&1; then
        test_result "Docker is installed" 1 "Docker command not found"
        return 1
    fi
    test_result "Docker is installed" 0
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        test_result "Docker daemon is running" 1 "Cannot connect to Docker daemon"
        return 1
    fi
    test_result "Docker daemon is running" 0
    
    # Check Docker Compose
    if docker compose version >/dev/null 2>&1; then
        test_result "Docker Compose v2 is available" 0
    elif command -v docker-compose >/dev/null 2>&1; then
        test_result "Docker Compose v1 is available" 0
        print_warning "Consider upgrading to Docker Compose v2"
    else
        test_result "Docker Compose is available" 1 "Neither 'docker compose' nor 'docker-compose' found"
        return 1
    fi
    
    return 0
}

# File structure validation
validate_file_structure() {
    print_status "Validating file structure..."
    
    local required_files=(
        "docker-compose.yml"
        ".env"
        "start.sh"
        "stop.sh"
        "add-service.sh"
    )
    
    local required_dirs=(
        "services"
        "config"
        "scripts"
        "plugins"
    )
    
    # Check required files
    local missing_files=0
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            test_result "File exists: $file" 0
        else
            test_result "File exists: $file" 1 "File not found"
            ((missing_files++))
        fi
    done
    
    # Check required directories
    local missing_dirs=0
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            test_result "Directory exists: $dir" 0
        else
            test_result "Directory exists: $dir" 1 "Directory not found"
            ((missing_dirs++))
        fi
    done
    
    # Check script permissions
    for script in start.sh stop.sh add-service.sh; do
        if [[ -f "$script" ]]; then
            if [[ -x "$script" ]]; then
                test_result "Script is executable: $script" 0
            else
                test_result "Script is executable: $script" 1 "Script not executable"
            fi
        fi
    done
    
    return $((missing_files + missing_dirs))
}

# Configuration validation
validate_configuration() {
    print_status "Validating configuration files..."
    
    # Check .env file
    if [[ -f ".env" ]]; then
        test_result "Environment file exists" 0
        
        # Check permissions
        local perms=$(stat -c '%a' .env 2>/dev/null || stat -f '%A' .env 2>/dev/null || echo "")
        if [[ "$perms" == "600" ]]; then
            test_result "Environment file has secure permissions" 0
        else
            test_result "Environment file has secure permissions" 1 "Permissions are $perms, should be 600"
        fi
        
        # Check for required variables
        local required_vars=("POSTGRES_PASSWORD" "REDIS_PASSWORD" "JWT_SECRET")
        for var in "${required_vars[@]}"; do
            if grep -q "^$var=" .env; then
                test_result "Environment variable set: $var" 0
            else
                test_result "Environment variable set: $var" 1 "Variable not found in .env"
            fi
        done
    else
        test_result "Environment file exists" 1 "File not found"
        return 1
    fi
    
    # Check Docker Compose syntax
    if command -v docker >/dev/null 2>&1; then
        if docker compose config >/dev/null 2>&1; then
            test_result "Docker Compose configuration is valid" 0
        else
            test_result "Docker Compose configuration is valid" 1 "Invalid YAML syntax"
        fi
    fi
    
    # Check service-config.json if exists
    if [[ -f "service-config.json" ]]; then
        if command -v jq >/dev/null 2>&1; then
            if jq empty service-config.json >/dev/null 2>&1; then
                test_result "Service configuration JSON is valid" 0
            else
                test_result "Service configuration JSON is valid" 1 "Invalid JSON syntax"
            fi
        else
            print_warning "jq not available, skipping JSON validation"
        fi
    fi
    
    return 0
}

# Service validation
validate_services() {
    print_status "Validating service implementations..."
    
    local services_dir="services"
    local service_count=0
    local valid_services=0
    
    if [[ ! -d "$services_dir" ]]; then
        test_result "Services directory exists" 1 "Directory not found"
        return 1
    fi
    
    # Check each service
    for service_dir in "$services_dir"/*; do
        if [[ -d "$service_dir" ]]; then
            local service_name=$(basename "$service_dir")
            ((service_count++))
            
            # Check for required files
            local has_main=false
            local has_dockerfile=false
            
            if [[ -f "$service_dir/app.py" ]] || [[ -f "$service_dir/main.go" ]] || [[ -f "$service_dir/index.js" ]]; then
                has_main=true
            fi
            
            if [[ -f "$service_dir/Dockerfile" ]]; then
                has_dockerfile=true
            fi
            
            if [[ "$has_main" == "true" ]] && [[ "$has_dockerfile" == "true" ]]; then
                test_result "Service $service_name is properly structured" 0
                ((valid_services++))
            else
                local missing=""
                [[ "$has_main" == "false" ]] && missing="main file"
                [[ "$has_dockerfile" == "false" ]] && missing="$missing Dockerfile"
                test_result "Service $service_name is properly structured" 1 "Missing: $missing"
            fi
        fi
    done
    
    test_result "Found $service_count services, $valid_services valid" $([[ $valid_services -eq $service_count ]] && echo 0 || echo 1)
    
    return $([[ $valid_services -eq $service_count ]] && echo 0 || echo 1)
}

# Plugin system validation
validate_plugin_system() {
    print_status "Validating plugin system..."
    
    # Check plugin directories
    local plugin_dirs=("plugins" "plugins/runtime" "plugins/registry")
    for dir in "${plugin_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            test_result "Plugin directory exists: $dir" 0
        else
            test_result "Plugin directory exists: $dir" 1 "Directory not found"
        fi
    done
    
    # Check plugin scripts
    local plugin_scripts=("plugins/runtime/plugin_registry.py" "plugins/runtime/plugin_sandbox.py")
    for script in "${plugin_scripts[@]}"; do
        if [[ -f "$script" ]]; then
            test_result "Plugin script exists: $(basename "$script")" 0
            
            # Check Python syntax if Python is available
            if command -v python3 >/dev/null 2>&1; then
                if python3 -m py_compile "$script" 2>/dev/null; then
                    test_result "Plugin script syntax valid: $(basename "$script")" 0
                else
                    test_result "Plugin script syntax valid: $(basename "$script")" 1 "Syntax error"
                fi
            fi
        else
            test_result "Plugin script exists: $(basename "$script")" 1 "File not found"
        fi
    done
    
    return 0
}

# Security validation
validate_security() {
    print_status "Validating security configuration..."
    
    # Check for default passwords
    if [[ -f ".env" ]]; then
        if grep -q "changeme\|password\|123456" .env; then
            test_result "No default passwords in configuration" 1 "Default passwords detected"
        else
            test_result "No default passwords in configuration" 0
        fi
        
        # Check password strength
        local weak_passwords=0
        while IFS= read -r line; do
            if [[ "$line" =~ ^[A-Z_]+_PASSWORD= ]]; then
                local password=$(echo "$line" | cut -d'=' -f2)
                if [[ ${#password} -lt 16 ]]; then
                    ((weak_passwords++))
                fi
            fi
        done < .env
        
        if [[ $weak_passwords -eq 0 ]]; then
            test_result "Passwords meet minimum length requirements" 0
        else
            test_result "Passwords meet minimum length requirements" 1 "$weak_passwords passwords are too short"
        fi
    fi
    
    # Check file permissions
    local secure_files=(".env")
    for file in "${secure_files[@]}"; do
        if [[ -f "$file" ]]; then
            local perms=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%A' "$file" 2>/dev/null || echo "")
            if [[ "$perms" == "600" ]]; then
                test_result "File has secure permissions: $file" 0
            else
                test_result "File has secure permissions: $file" 1 "Permissions: $perms (should be 600)"
            fi
        fi
    done
    
    return 0
}

# Network validation
validate_network() {
    print_status "Validating network configuration..."
    
    # Check for port conflicts
    local ports=(8000 8080 8081 8083 8084 8085 3000 9090)
    local conflicts=0
    
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            test_result "Port $port is available" 1 "Port in use"
            ((conflicts++))
        else
            test_result "Port $port is available" 0
        fi
    done
    
    return $conflicts
}

# Generate validation report
generate_validation_report() {
    local report_file="validation-report.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S")
    
    print_status "Generating validation report: $report_file"
    
    cat > "$report_file" << EOF
{
  "timestamp": "$timestamp",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "success_rate": $((TOTAL_TESTS > 0 ? (PASSED_TESTS * 100) / TOTAL_TESTS : 0))
  },
  "results": [
EOF

    local first=true
    for result in "${TEST_RESULTS[@]}"; do
        IFS='|' read -r status name time error <<< "$result"
        
        if [[ "$first" != "true" ]]; then
            echo "," >> "$report_file"
        fi
        first=false
        
        cat >> "$report_file" << EOF
    {
      "name": "$name",
      "status": "$status",
      "execution_time": "$time",
      "error": "$error"
    }
EOF
    done
    
    cat >> "$report_file" << EOF
  ]
}
EOF
    
    print_success "Validation report generated: $report_file"
}

# Print summary
print_validation_summary() {
    local success_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    fi
    
    echo
    echo "📊 Validation Results Summary"
    echo "============================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "✅ Passed: $PASSED_TESTS"
    echo "❌ Failed: $FAILED_TESTS"
    echo "📈 Success Rate: $success_rate%"
    echo
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        print_success "🎉 All validations passed! Framework is ready."
        return 0
    else
        print_error "❌ $FAILED_TESTS validation(s) failed."
        echo
        echo "Common fixes:"
        echo "- Run: chmod +x *.sh"
        echo "- Run: chmod 600 .env"
        echo "- Check Docker is running: docker info"
        echo "- Validate syntax: docker compose config"
        return 1
    fi
}

# Main validation function
run_validation() {
    local validation_type="${1:-all}"
    
    case "$validation_type" in
        docker)
            validate_docker
            ;;
        files)
            validate_file_structure
            ;;
        config)
            validate_configuration
            ;;
        services)
            validate_services
            ;;
        plugins)
            validate_plugin_system
            ;;
        security)
            validate_security
            ;;
        network)
            validate_network
            ;;
        all)
            validate_docker
            validate_file_structure
            validate_configuration
            validate_services
            validate_plugin_system
            validate_security
            validate_network
            ;;
        *)
            print_error "Unknown validation type: $validation_type"
            echo "Available types: docker, files, config, services, plugins, security, network, all"
            return 1
            ;;
    esac
    
    return 0
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-all}" in
        --help|-h)
            echo "Usage: $0 [validation-type] [options]"
            echo "Types: docker, files, config, services, plugins, security, network, all"
            echo "Options: --report (generate JSON report)"
            ;;
        --report)
            run_validation "all"
            generate_validation_report
            print_validation_summary
            ;;
        *)
            run_validation "$1"
            print_validation_summary
            ;;
    esac
fi
