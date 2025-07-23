#!/bin/bash
# Modular Test Framework for NextHunt
# This provides shared test functions for all test suites

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
# Store test results for reporting
TEST_RESULTS=()

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Enhanced test result tracking with error capture and reporting
test_result() {
    local test_name=$1
    local result=$2
    local error_msg=${3:-""}
    local log_file=${4:-""}
    local start_time=${5:-$(date +%s%N)}
    local end_time=$(date +%s%N)
    local execution_time=$(( (end_time - start_time) / 1000000 )) # ms
    
    ((TOTAL_TESTS++))
    if [[ $result -eq 0 ]]; then
        print_success "$test_name"
        ((PASSED_TESTS++))
        # Store success result
        TEST_RESULTS+=("success|$test_name|$execution_time|")
    else
        print_error "$test_name"
        if [[ -n "$error_msg" ]]; then
            echo "  └─ Error: $error_msg"
        fi
        if [[ -n "$log_file" && -f "$log_file" ]]; then
            echo "  └─ Last 5 log lines:"
            tail -n 5 "$log_file" | sed 's/^/      /'
        fi
        ((FAILED_TESTS++))
        # Store failure result with error message
        TEST_RESULTS+=("failure|$test_name|$execution_time|${error_msg}")
    fi
    
    return $result
}

# Run command with timeout and capture output
run_test_command() {
    local cmd="$1"
    local timeout_sec="${2:-30}"
    local log_file="$(mktemp)"
    local exit_code=0
    
    # Use timeout if available
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_sec" bash -c "$cmd" >"$log_file" 2>&1 || exit_code=$?
    else
        # Fallback without timeout
        bash -c "$cmd" >"$log_file" 2>&1 || exit_code=$?
    fi
    
    echo "$exit_code:$log_file"
}

# Shared test functions that can be used across test suites
test_docker_availability() {
    print_status "Testing Docker availability..."
    
    # Check Docker daemon
    local cmd_result=$(run_test_command "docker info")
    local exit_code=$(echo "$cmd_result" | cut -d':' -f1)
    local log_file=$(echo "$cmd_result" | cut -d':' -f2)
    
    test_result "Docker daemon is running" "$exit_code" "Docker daemon not accessible" "$log_file"
    
    # Check Docker Compose
    cmd_result=$(run_test_command "docker compose version || docker-compose version")
    exit_code=$(echo "$cmd_result" | cut -d':' -f1)
    log_file=$(echo "$cmd_result" | cut -d':' -f2)
    
    test_result "Docker Compose is available" "$exit_code" "Docker Compose not found" "$log_file"
    
    return "$exit_code"
}

test_config_validation() {
    print_status "Testing configuration files..."
    local config_file="$1"
    local exit_code=0
    
    if [[ ! -f "$config_file" ]]; then
        test_result "Configuration file exists" 1 "File not found: $config_file"
        return 1
    fi
    
    # Validate JSON syntax
    local cmd_result=$(run_test_command "jq empty '$config_file'")
    exit_code=$(echo "$cmd_result" | cut -d':' -f1)
    local log_file=$(echo "$cmd_result" | cut -d':' -f2)
    
    test_result "Configuration has valid JSON syntax" "$exit_code" "Invalid JSON" "$log_file"
    
    return "$exit_code"
}

test_service_health() {
    local service_name="$1"
    local url="$2"
    local expected="${3:-healthy}"
    
    print_status "Testing $service_name health..."
    
    local cmd_result=$(run_test_command "curl -s '$url' | grep -q '$expected'")
    local exit_code=$(echo "$cmd_result" | cut -d':' -f1)
    local log_file=$(echo "$cmd_result" | cut -d':' -f2)
    
    test_result "$service_name is healthy" "$exit_code" "Health check failed" "$log_file"
    
    return "$exit_code"
}

# Generate JUnit XML report for CI/CD integration
generate_junit_report() {
    local report_file="nexthunt-test-report.xml"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S")
    
    print_status "Generating JUnit XML report: $report_file"
    
    # Create XML header
    cat > "$report_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="NextHunt Framework Tests" tests="$TOTAL_TESTS" failures="$FAILED_TESTS" errors="0" skipped="0" timestamp="$timestamp">
EOF
    
    # Add test cases
    for result in "${TEST_RESULTS[@]}"; do
        IFS='|' read -r status name time error <<< "$result"
        
        if [[ "$status" == "success" ]]; then
            cat >> "$report_file" << EOF
    <testcase name="$name" time="$time" />
EOF
        else
            cat >> "$report_file" << EOF
    <testcase name="$name" time="$time">
      <failure message="Test failed">$error</failure>
    </testcase>
EOF
        fi
    done
    
    # Close XML
    cat >> "$report_file" << EOF
  </testsuite>
</testsuites>
EOF
    
    print_success "JUnit XML report generated: $report_file"
}

# Function to print final test summary
print_test_summary() {
    local suite_name="$1"
    local success_rate=0
    
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    fi
    
    echo
    echo "📊 $suite_name Test Results"
    echo "============================"
    echo "Total Tests Executed: $TOTAL_TESTS"
    echo "✅ Passed: $PASSED_TESTS"
    echo "❌ Failed: $FAILED_TESTS"
    echo "📈 Success Rate: $success_rate%"
    echo
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        print_success "🎉 All tests passed successfully!"
        return 0
    else
        print_error "❌ $FAILED_TESTS test(s) failed!"
        return 1
    fi
}

# Check if script is sourced or executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    print_status "NextHunt Test Framework"
    echo "This script provides shared test functions and should be sourced by other test scripts."
    echo "Example usage:"
    echo "  source test-framework.sh"
    echo "  test_docker_availability"
    echo "  test_config_validation 'service-config.json'"
    echo "  print_test_summary 'My Test Suite'"
    echo "  generate_junit_report  # Creates XML report for CI/CD"
fi
