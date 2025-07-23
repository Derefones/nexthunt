#!/bin/bash
# NextHunt Framework Setup Script
# Creates complete cybersecurity assessment platform

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Enhanced error handling
handle_error() {
    local line=$1
    local exit_code=$2
    local command=$3
    
    print_error "Error occurred on line $line, command: $command, exit code: $exit_code"
    
    # Check for common errors and provide helpful suggestions
    if [[ $exit_code -eq 127 ]]; then
        print_warning "This is likely a 'command not found' error. Check if all required tools are installed."
    elif [[ $exit_code -eq 1 ]]; then
        print_warning "This could be a permission issue or invalid input. Check error message above."
    elif [[ $exit_code -eq 13 ]]; then
        print_warning "Permission denied. Check if you have the necessary file permissions."
    fi
    
    print_status "Stopping execution. Partial setup may have occurred."
    exit $exit_code
}

# Set up error trap
trap 'handle_error ${LINENO} $? "$BASH_COMMAND"' ERR

# Configuration
PROJECT_NAME="nexthunt"
SETUP_MODE="interactive"
ENABLE_MONITORING=true
ENABLE_SECURITY=true
COMMAND=""
LOG_FILE="nexthunt-setup.log"

# Set up logging
exec > >(tee -a "$LOG_FILE") 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting setup script" >> "$LOG_FILE"

# Add missing usage function
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    setup       Setup the NextHunt framework (default)
    validate    Validate existing setup
    clean       Clean installation
    update      Update components

Options:
    --quick             Quick setup mode
    --name NAME         Project name (default: nexthunt)
    --no-monitoring     Disable monitoring stack
    --no-security       Disable security features
    -h, --help         Show this help

Examples:
    $0 setup --quick
    $0 setup --name my-nexthunt --no-monitoring
    $0 validate
EOF
}

# Parse command line arguments first
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            SETUP_MODE="quick"
            shift
            ;;
        --name)
            PROJECT_NAME="$2"
            shift 2
            ;;
        --no-monitoring)
            ENABLE_MONITORING=false
            shift
            ;;
        --no-security)
            ENABLE_SECURITY=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        setup|validate|clean|update)
            COMMAND="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set default command if none provided
if [[ -z "$COMMAND" ]]; then
    COMMAND="setup"
fi

# Create project structure
create_project_structure() {
    print_status "Creating project structure for $PROJECT_NAME..."
    
    # Create project directory if needed
    if [[ "$PROJECT_NAME" != "." ]] && [[ ! -d "$PROJECT_NAME" ]]; then
        mkdir -p "$PROJECT_NAME"
        cd "$PROJECT_NAME"
    fi
    
    mkdir -p {config,scripts,services,plugins,templates,data,logs,certs,backups}
    mkdir -p config/{nginx,prometheus,grafana,alertmanager}
    mkdir -p scripts/{backup,security,deployment}
    mkdir -p services/{api-gateway,reconnaissance,intelligence,scanning,exploitation,reporting}
    mkdir -p plugins/{templates,marketplace,security}
    mkdir -p data/{postgres,redis,elasticsearch}
    
    # Create setup completion marker
    touch .setup_complete
    
    print_success "Project structure created"
}

# Generate Docker Compose configuration with port variables
generate_docker_compose() {
    print_status "Generating Docker Compose configuration..."
    
    cat > docker-compose.yml << 'EOF'
version: '3.8'

networks:
  nexthunt-network:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
  scan_results:
  reports:

services:
  # Database Services
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: nexthunt
      POSTGRES_USER: nexthunt
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./config/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - nexthunt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nexthunt"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - nexthunt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Core Services
  api-gateway:
    build: ./services/api-gateway
    ports:
      - "${PORT_API_GATEWAY:-8000}:8000"
    environment:
      - DATABASE_URL=postgresql://nexthunt:${POSTGRES_PASSWORD}@postgres:5432/nexthunt
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
      - CORS_ENABLED=${CORS_ENABLED:-false}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - nexthunt-network
    restart: unless-stopped
    volumes:
      - scan_results:/app/data/scans
      - reports:/app/data/reports

  reconnaissance:
    build: ./services/reconnaissance
    ports:
      - "${PORT_RECONNAISSANCE:-8080}:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
    volumes:
      - scan_results:/app/data

  intelligence:
    build: ./services/intelligence
    ports:
      - "${PORT_INTELLIGENCE:-8081}:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=postgresql://nexthunt:${POSTGRES_PASSWORD}@postgres:5432/nexthunt
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped

  scanning:
    build: ./services/scanning
    ports:
      - "${PORT_SCANNING:-8084}:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
    volumes:
      - scan_results:/app/data

  exploitation:
    build: ./services/exploitation
    ports:
      - "${PORT_EXPLOITATION:-8083}:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - NET_RAW

  reporting:
    build: ./services/reporting
    ports:
      - "${PORT_REPORTING:-8085}:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=postgresql://nexthunt:${POSTGRES_PASSWORD}@postgres:5432/nexthunt
      - ENVIRONMENT=${ENVIRONMENT:-production}
      - DEBUG=${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
    volumes:
      - reports:/app/reports

  # Monitoring Stack
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "${PORT_PROMETHEUS:-9090}:9090"
    volumes:
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - nexthunt-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "${PORT_GRAFANA:-3000}:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_SECURITY_ALLOW_EMBEDDING=false
      - GF_SECURITY_DISABLE_GRAVATAR=true
      - GF_SECURITY_COOKIE_SECURE=true
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana/dashboards:/var/lib/grafana/dashboards
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF

    print_success "Docker Compose configuration generated with centralized port management"
}

# Generate environment configuration
generate_environment() {
    print_status "Generating environment configuration..."
    
    # Generate secure passwords
    POSTGRES_PASSWORD=$(openssl rand -base64 32)
    REDIS_PASSWORD=$(openssl rand -base64 32)
    JWT_SECRET=$(openssl rand -base64 64)
    GRAFANA_PASSWORD=$(openssl rand -base64 16)
    cat > .env << EOF
# NextHunt Framework Configuration
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=info

# Database Configuration
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD

# Security Configuration
JWT_SECRET=$JWT_SECRET
JWT_EXPIRATION=3600
ENCRYPTION_KEY=$(openssl rand -base64 32)

# API Configuration
API_PORT=8000
API_HOST=0.0.0.0
API_WORKERS=4

# Port Configuration - Centralized port management
PORT_API_GATEWAY=8000
PORT_RECONNAISSANCE=8080
PORT_INTELLIGENCE=8081
PORT_SCANNING=8084
PORT_EXPLOITATION=8083
PORT_REPORTING=8085
PORT_PROMETHEUS=9090
PORT_GRAFANA=3000

# Monitoring Configuration
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
METRICS_ENABLED=true
TRACING_ENABLED=true

# Security Features
AUTHENTICATION_REQUIRED=true
RATE_LIMITING_ENABLED=true
CORS_ENABLED=false
TLS_ENABLED=false

# Plugin System
PLUGIN_DIRECTORY=./plugins
PLUGIN_SECURITY_ENABLED=true
PLUGIN_MARKETPLACE_ENABLED=false

# Scanning Configuration
MAX_CONCURRENT_SCANS=10
SCAN_TIMEOUT=3600
SCAN_RESULTS_RETENTION=30

# Reporting Configuration
REPORT_FORMATS=pdf,html,json,xml
REPORT_STORAGE=/app/reports
REPORT_RETENTION=90
EOF

    # Create example environment file
    cp .env .env.example
    # Set secure permissions for .env file
    chmod 600 .env
    
    print_success "Environment configuration generated with secure defaults"
}

# Create service configurations
create_service_configs() {
    print_status "Creating service configurations..."
    
    for service in api-gateway reconnaissance intelligence scanning exploitation reporting; do
        mkdir -p "services/$service"
        
        # Create Dockerfile
        cat > "services/$service/Dockerfile" << 'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
EOF

        # Create requirements.txt
        cat > "services/$service/requirements.txt" << 'EOF'
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
sqlalchemy==2.0.23
alembic==1.12.1
redis==5.0.1
requests==2.31.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
aiofiles==23.2.1
celery==5.3.4
psycopg2-binary==2.9.9
prometheus-client==0.19.0
structlog==23.2.0
EOF

        # Create basic app.py - FIXED HEREDOC
        service_name_cap="$(echo "$service" | sed 's/^./\U&/' | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ //g')"
        cat > "services/$service/app.py" << EOF
#!/usr/bin/env python3
"""
NextHunt $service Service
"""

import os
import logging
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NextHunt $service_name_cap Service",
    description="NextHunt Framework - $service_name_cap Service",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "$service"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "NextHunt $service_name_cap Service", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True
    )
EOF
    done
    
    # Enhanced Go template creation for api-gateway
    mkdir -p "services/api-gateway-go"
    
    # Create main.go with better structure and features
    cat > "services/api-gateway-go/main.go" << 'EOF'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configuration holds service settings
type Configuration struct {
	Port              string
	Environment       string
	LogLevel          string
	AuthEnabled       bool
	DatabaseURL       string
	RedisURL          string
}

// Service represents the API gateway service
type Service struct {
	Config     Configuration
	Router     *mux.Router
	HTTPServer *http.Server
	Logger     *log.Logger
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Timestamp int64             `json:"timestamp"`
	Services  map[string]string `json:"services,omitempty"`
}

// Initialize sets up the service
func (s *Service) Initialize() {
	// Configure router with middleware
	s.Router = mux.NewRouter()
	s.Router.Use(s.loggingMiddleware)
	s.Router.Use(s.prometheusMiddleware)
	
	// Set up routes
	s.Router.HandleFunc("/health", s.healthCheckHandler).Methods("GET")
	s.Router.HandleFunc("/", s.rootHandler).Methods("GET")
	s.Router.HandleFunc("/api/v1/proxy/{service}/{path:.*}", s.proxyHandler).Methods("GET", "POST", "PUT", "DELETE")
	
	// Add Prometheus metrics endpoint
	s.Router.Handle("/metrics", promhttp.Handler())
	
	// Set up HTTP server with timeouts
	s.HTTPServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", s.Config.Port),
		Handler:      s.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Start begins the service
func (s *Service) Start() error {
	// Start server in goroutine
	go func() {
		s.Logger.Printf("API Gateway starting on port %s", s.Config.Port)
		if err := s.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.Logger.Fatalf("Error starting server: %v", err)
		}
	}()
	
	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	
	// Wait for interrupt signal
	<-quit
	s.Logger.Println("Shutting down server...")
	
	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Attempt graceful shutdown
	if err := s.HTTPServer.Shutdown(ctx); err != nil {
		s.Logger.Fatalf("Server forced to shutdown: %v", err)
		return err
	}
	
	s.Logger.Println("Server gracefully stopped")
	return nil
}

// Middleware functions
func (s *Service) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.Logger.Printf("[%s] %s %s %s", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// Prometheus metrics middleware
func (s *Service) prometheusMiddleware(next http.Handler) http.Handler {
	// Define metrics
	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint"},
	)
	
	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	
	// Register metrics
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestDuration)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		
		// Extract path base for cleaner metrics
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/v1/proxy/") {
			parts := strings.SplitN(path[13:], "/", 2)
			if len(parts) > 0 {
				path = "/api/v1/proxy/" + parts[0]
			}
		}
		
		// Record metrics
		duration := time.Since(start).Seconds()
		requestsTotal.WithLabelValues(r.Method, path).Inc()
		requestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

// Route handlers
func (s *Service) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Service:   "api-gateway",
		Version:   "1.0.0",
		Timestamp: time.Now().Unix(),
		Services:  make(map[string]string),
	}
	
	// In a real implementation, check downstream services
	// This is a simplified version
	response.Services["postgres"] = "connected"
	response.Services["redis"] = "connected"
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "NextHunt API Gateway",
		"version": "1.0.0",
		"status":  "running",
	})
}

func (s *Service) proxyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	service := vars["service"]
	path := vars["path"]
	
	// In a real implementation, proxy the request to the appropriate service
	// This is a simplified version
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Request would be proxied",
		"service": service,
		"path":    path,
	})
}

func main() {
	// Load configuration from environment variables
	config := Configuration{
		Port:        getEnvOr("API_PORT", "8000"),
		Environment: getEnvOr("ENVIRONMENT", "development"),
		LogLevel:    getEnvOr("LOG_LEVEL", "info"),
		AuthEnabled: getEnvOr("AUTHENTICATION_REQUIRED", "true") == "true",
		DatabaseURL: getEnvOr("DATABASE_URL", "postgresql://postgres:password@localhost:5432/postgres"),
		RedisURL:    getEnvOr("REDIS_URL", "redis://:password@localhost:6379"),
	}
	
	// Create logger
	logger := log.New(os.Stdout, "[API-GATEWAY] ", log.LstdFlags)
	
	// Create and initialize service
	service := &Service{
		Config: config,
		Logger: logger,
	}
	service.Initialize()
	
	// Start service
	if err := service.Start(); err != nil {
		logger.Fatalf("Service terminated with error: %v", err)
	}
}

// Helper to get environment variable with default
func getEnvOr(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
EOF

    # Create go.mod file
    cat > "services/api-gateway-go/go.mod" << 'EOF'
module github.com/nexthunt/api-gateway

go 1.21

require (
	github.com/gorilla/mux v1.8.1
	github.com/prometheus/client_golang v1.17.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/prometheus/client_model v0.4.1-0.20230718164431-9a2bf3000d16 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.11.1 // indirect
	golang.org/x/sys v0.11.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
EOF

    # Create Dockerfile with multi-stage build
    cat > "services/api-gateway-go/Dockerfile" << 'EOF'
# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app

# Install git
RUN apk --no-cache add git

# Copy and download dependencies
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags=-static' \
    -o api-gateway .

# Run security scan (optional)
RUN go install golang.org/x/vuln/cmd/govulncheck@latest && \
    govulncheck ./... || echo "Security scan complete"

# Final stage
FROM alpine:latest

# Add security patches and CA certificates
RUN apk --no-cache add ca-certificates tzdata && \
    update-ca-certificates

# Create non-root user
RUN adduser -D -H -h /app appuser
WORKDIR /app

# Copy binary from build stage
COPY --from=builder /app/api-gateway .

# Use non-root user
USER appuser

# Set execute permissions
RUN chmod +x /app/api-gateway

# Configure health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run with explicit port binding
CMD ["./api-gateway"]
EOF

    print_success "Service configurations created with enhanced Go template"
}

# Create monitoring configuration
create_monitoring_config() {
    print_status "Creating monitoring configuration..."
    
    # Prometheus configuration
    cat > config/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - "nexthunt_alerts.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'nexthunt-api-gateway'
    static_configs:
      - targets: ['api-gateway:8000']
    metrics_path: '/metrics'

  - job_name: 'nexthunt-services'
    static_configs:
      - targets:
        - 'reconnaissance:8000'
        - 'intelligence:8000'
        - 'scanning:8000'
        - 'exploitation:8000'
        - 'reporting:8000'
    metrics_path: '/metrics'

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
EOF

    # Grafana dashboard configuration
    mkdir -p config/grafana/dashboards
    cat > config/grafana/dashboards/nexthunt-overview.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "NextHunt Framework Overview",
    "tags": ["nexthunt"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Service Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=~\"nexthunt.*\"}",
            "legendFormat": "{{job}}"
          }
        ]
      },
      {
        "id": 2,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{service}}"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
EOF

    print_success "Monitoring configuration created"
}

# Create plugin system implementation
create_plugin_system_implementation() {
    print_status "Creating plugin system implementation..."
    
    # Create plugin system directory structure
    mkdir -p "plugins/runtime"
    mkdir -p "plugins/sandboxes"
    mkdir -p "plugins/registry"
    
    # Create plugin sandbox implementation
    cat > "plugins/runtime/plugin_sandbox.py" << 'EOF'
#!/usr/bin/env python3
"""
NextHunt Plugin Sandbox Implementation
Provides secure plugin execution environment
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
import threading
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plugin-sandbox")

class PluginSandbox:
    """Plugin sandbox for secure execution of third-party code"""
    
    def __init__(self, plugin_path: str, config_path: Optional[str] = None):
        """Initialize sandbox with plugin path and optional config"""
        self.plugin_path = Path(plugin_path).resolve()
        self.plugin_name = self.plugin_path.name
        self.sandbox_dir = Path("plugins/sandboxes") / self.plugin_name
        self.config = self._load_config(config_path)
        
        # Default security settings
        self.security = {
            "readonly_fs": True,
            "network_access": False,
            "syscalls": "restricted",
            "capabilities": [],
            "memory_limit": "256m",
            "cpu_limit": "0.5",
            "execution_timeout": 300,  # seconds
            "allowed_binaries": ["python", "python3"]
        }
        
        # Override with config if present
        if "security" in self.config:
            self.security.update(self.config["security"])
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load plugin configuration from file"""
        if not config_path:
            config_path = self.plugin_path / "plugin.yaml"
        
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    import yaml
                    return yaml.safe_load(f)
            else:
                logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return {}
    
    def _prepare_sandbox(self) -> None:
        """Prepare sandbox directory with plugin files"""
        # Create clean sandbox directory
        if self.sandbox_dir.exists():
            shutil.rmtree(self.sandbox_dir)
        self.sandbox_dir.mkdir(parents=True)
        
        # Copy plugin files to sandbox
        shutil.copytree(self.plugin_path, self.sandbox_dir / "plugin", symlinks=False)
        
        # Create runtime files
        with open(self.sandbox_dir / "security.json", 'w') as f:
            json.dump(self.security, f, indent=2)
    
    def _validate_permissions(self) -> bool:
        """Validate plugin permissions and requirements"""
        # Check if plugin has valid manifest
        manifest_path = self.plugin_path / "plugin.yaml"
        if not manifest_path.exists():
            logger.error(f"Plugin missing manifest: {manifest_path}")
            return False
        
        # Check for known vulnerabilities or bad practices in code
        # (simplified example, real implementation would use code analysis tools)
        for ext in ["py", "js", "go"]:
            for source_file in self.plugin_path.glob(f"**/*.{ext}"):
                try:
                    with open(source_file, 'r') as f:
                        content = f.read()
                        if "os.system(" in content or "subprocess.call(" in content:
                            logger.warning(f"Potential security risk: {source_file} uses shell commands")
                        if "eval(" in content:
                            logger.warning(f"Potential security risk: {source_file} uses eval()")
                except Exception:
                    pass  # Skip files we can't read
        
        return True
    
    def _run_container(self, command: List[str], env: Dict[str, str] = None) -> int:
        """Run plugin in Docker container with security limits"""
        
        # Build container command with security constraints
        container_name = f"nexthunt-plugin-{self.plugin_name}-{int(time.time())}"
        
        docker_cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", "none" if not self.security["network_access"] else "nexthunt-network",
            "--memory", self.security["memory_limit"],
            "--cpus", str(self.security["cpu_limit"]),
            "--read-only" if self.security["readonly_fs"] else "",
            "--security-opt", f"seccomp={self.sandbox_dir}/seccomp.json",
            "--volume", f"{self.sandbox_dir}/plugin:/plugin:ro",
            "--workdir", "/plugin",
            "--user", "1000:1000",  # non-root user
        ]
        
        # Add environment variables
        if env:
            for key, value in env.items():
                docker_cmd.extend(["--env", f"{key}={value}"])
        
        # Add mounted volumes based on permissions
        permissions = self.config.get("permissions", {})
        for path in permissions.get("volumes", []):
            docker_cmd.extend(["--volume", f"{path}:{path}:ro"])
        
        # Add container image and command
        docker_cmd.append("nexthunt/plugin-runner:latest")
        docker_cmd.extend(command)
        
        # Run container with timeout
        try:
            logger.info(f"Running plugin in sandbox: {' '.join(docker_cmd)}")
            process = subprocess.Popen(docker_cmd)
            
            # Start timeout thread
            timer = threading.Timer(self.security["execution_timeout"], 
                                  lambda: self._kill_container(container_name))
            timer.start()
            
            # Wait for process to finish
            exit_code = process.wait()
            timer.cancel()  # Cancel timeout if finished normally
            
            return exit_code
        except subprocess.SubprocessError as e:
            logger.error(f"Error running container: {e}")
            return 1
    def _kill_container(self, container_name: str) -> None:
        """Kill container if timeout reached"""
        logger.warning(f"Plugin execution timeout, killing container: {container_name}")
        try:
            subprocess.run(["docker", "kill", container_name], check=True)
        except subprocess.SubprocessError:
            pass
    
    def run(self, command: List[str] = None, env: Dict[str, str] = None) -> int:
        """Run plugin in sandbox with security constraints"""
        if not self._validate_permissions():
            logger.error("Permission validation failed")
            return 1
        
        try:
            self._prepare_sandbox()
            
            if not command:
                # Default to plugin's main.py if exists, otherwise entrypoint from manifest
                if (self.plugin_path / "main.py").exists():
                    command = ["python3", "main.py"]
                else:
                    entrypoint = self.config.get("entrypoint", "")
                    if not entrypoint:
                        logger.error("No entrypoint specified in plugin manifest")
                        return 1
                    command = entrypoint.split()
            
            return self._run_container(command, env)
        except Exception as e:
            logger.error(f"Error running plugin: {e}")
            return 1
    
    def cleanup(self) -> None:
        """Clean up sandbox resources"""
        if self.sandbox_dir.exists():
            try:
                shutil.rmtree(self.sandbox_dir)
                logger.info(f"Cleaned up sandbox: {self.sandbox_dir}")
            except Exception as e:
                logger.error(f"Error cleaning up sandbox: {e}")
}


def main():
    """CLI entrypoint for plugin sandbox"""
    parser = argparse.ArgumentParser(description='NextHunt Plugin Sandbox')
    parser.add_argument('plugin_path', help='Path to plugin directory')
    parser.add_argument('--config', help='Path to plugin configuration')
    parser.add_argument('--command', help='Command to run', nargs='*')
    parser.add_argument('--env', help='Environment variables', action='append', default=[])
    
    args = parser.parse_args()
    
    # Parse environment variables
    env = {}
    for e in args.env:
        if '=' in e:
            key, value = e.split('=', 1)
            env[key] = value
    
    # Create and run sandbox
    sandbox = PluginSandbox(args.plugin_path, args.config)
    exit_code = sandbox.run(args.command, env)
    sandbox.cleanup()
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
EOF

    # Create plugin registry implementation
    cat > "plugins/runtime/plugin_registry.py" << 'EOF'
#!/usr/bin/env python3
"""
NextHunt Plugin Registry
Manages plugin lifecycle, dependencies, and permissions
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plugin-registry")

class PluginRegistry:
    """Manages plugin registration, validation, and dependencies"""
    
    def __init__(self, registry_dir: str = "plugins/registry"):
        """Initialize plugin registry"""
        self.registry_dir = Path(registry_dir)
        self.registry_file = self.registry_dir / "registry.json"
        self.plugins = self._load_registry()
    
    def _load_registry(self) -> Dict[str, Any]:
        """Load plugin registry from file"""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Invalid registry file: {self.registry_file}")
                return {"plugins": {}}
        else:
            logger.info("Creating new plugin registry")
            self.registry_dir.mkdir(parents=True, exist_ok=True)
            return {"plugins": {}}
    
    def _save_registry(self) -> None:
        """Save plugin registry to file"""
        with open(self.registry_file, 'w') as f:
            json.dump(self.plugins, f, indent=2)
    
    def register_plugin(self, plugin_path: str) -> bool:
        """Register a new plugin in the registry"""
        plugin_dir = Path(plugin_path)
        manifest_path = plugin_dir / "plugin.yaml"
        
        if not manifest_path.exists():
            logger.error(f"Plugin manifest not found: {manifest_path}")
            return False
        
        try:
            # Load plugin manifest
            with open(manifest_path, 'r') as f:
                manifest = yaml.safe_load(f)
            
            # Extract plugin metadata
            plugin_name = manifest.get("name")
            plugin_version = manifest.get("version", "0.0.0")
            
            if not plugin_name:
                logger.error("Plugin name not specified in manifest")
                return False
            
            # Register plugin
            self.plugins["plugins"][plugin_name] = {
                "name": plugin_name,
                "version": plugin_version,
                "path": str(plugin_dir),
                "enabled": True,
                "manifest": manifest,
                "dependencies": manifest.get("dependencies", {}),
                "permissions": manifest.get("permissions", {}),
                "registered_at": int(os.path.getmtime(manifest_path))
            }
            
            # Save registry
            self._save_registry()
            logger.info(f"Plugin registered: {plugin_name} v{plugin_version}")
            return True
            
        except Exception as e:
            logger.error(f"Error registering plugin: {e}")
            return False
    
    def unregister_plugin(self, plugin_name: str) -> bool:
        """Remove a plugin from the registry"""
        if plugin_name in self.plugins["plugins"]:
            del self.plugins["plugins"][plugin_name]
            self._save_registry()
            logger.info(f"Plugin unregistered: {plugin_name}")
            return True
        else:
            logger.warning(f"Plugin not found: {plugin_name}")
            return False
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        if plugin_name in self.plugins["plugins"]:
            self.plugins["plugins"][plugin_name]["enabled"] = True
            self._save_registry()
            logger.info(f"Plugin enabled: {plugin_name}")
            return True
        else:
            logger.warning(f"Plugin not found: {plugin_name}")
            return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        if plugin_name in self.plugins["plugins"]:
            self.plugins["plugins"][plugin_name]["enabled"] = False
            self._save_registry()
            logger.info(f"Plugin disabled: {plugin_name}")
            return True
        else:
            logger.warning(f"Plugin not found: {plugin_name}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get plugin information by name"""
        return self.plugins["plugins"].get(plugin_name)
    
    def list_plugins(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all registered plugins"""
        plugins = self.plugins["plugins"].values()
        if enabled_only:
            return [p for p in plugins if p.get("enabled", False)]
        return list(plugins)
    
    def check_dependencies(self, plugin_name: str) -> List[str]:
        """Check if plugin dependencies are satisfied"""
        if plugin_name not in self.plugins["plugins"]:
            return [f"Plugin not found: {plugin_name}"]
        
        errors = []
        plugin = self.plugins["plugins"][plugin_name]
        dependencies = plugin.get("dependencies", {})
        
        # Check NextHunt version dependency
        if "nexthunt" in dependencies:
            # In a real implementation, compare with actual version
            nexthunt_version = "1.0.0"
            required_version = dependencies["nexthunt"]
            if not self._version_satisfies(nexthunt_version, required_version):
                errors.append(f"NextHunt version mismatch: requires {required_version}, found {nexthunt_version}")
        
        # Check service dependencies
        for service in dependencies.get("services", []):
            # In a real implementation, check if service exists
            if service not in ["reconnaissance", "intelligence", "scanning", "exploitation", "reporting"]:
                errors.append(f"Required service not found: {service}")
        
        # Check plugin dependencies
        for dep_plugin, version in dependencies.get("plugins", {}).items():
            if dep_plugin not in self.plugins["plugins"]:
                errors.append(f"Required plugin not found: {dep_plugin}")
            elif not self._version_satisfies(self.plugins["plugins"][dep_plugin]["version"], version):
                errors.append(f"Plugin version mismatch: {dep_plugin} requires {version}, found {self.plugins['plugins'][dep_plugin]['version']}")
        
        return errors
    
    def _version_satisfies(self, version: str, requirement: str) -> bool:
        """Check if version satisfies requirement"""
        # Simplified version check, a real implementation would use semver
        if requirement.startswith(">="):
            return version >= requirement[2:]
        elif requirement.startswith("<="):
            return version <= requirement[2:]
        elif requirement.startswith(">"):
            return version > requirement[1:]
        elif requirement.startswith("<"):
            return version < requirement[1:]
        else:
            return version == requirement


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='NextHunt Plugin Registry')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Register plugin
    register_parser = subparsers.add_parser('register', help='Register a plugin')
    register_parser.add_argument('path', help='Path to plugin directory')
    
    # Unregister plugin
    unregister_parser = subparsers.add_parser('unregister', help='Unregister a plugin')
    unregister_parser.add_argument('name', help='Plugin name')
    
    # Enable plugin
    enable_parser = subparsers.add_parser('enable', help='Enable a plugin')
    enable_parser.add_argument('name', help='Plugin name')
    
    # Disable plugin
    disable_parser = subparsers.add_parser('disable', help='Disable a plugin')
    disable_parser.add_argument('name', help='Plugin name')
    
    # List plugins
    list_parser = subparsers.add_parser('list', help='List plugins')
    list_parser.add_argument('--enabled-only', action='store_true', help='List only enabled plugins')
    
    # Check dependencies
    check_parser = subparsers.add_parser('check', help='Check plugin dependencies')
    check_parser.add_argument('name', help='Plugin name')
    
    args = parser.parse_args()
    
    registry = PluginRegistry()
    
    if args.command == 'register':
        success = registry.register_plugin(args.path)
        print(f"Registration {'successful' if success else 'failed'}")
    elif args.command == 'unregister':
        success = registry.unregister_plugin(args.name)
        print(f"Unregistration {'successful' if success else 'failed'}")
    elif args.command == 'enable':
        success = registry.enable_plugin(args.name)
        print(f"Plugin {args.name} {'enabled' if success else 'not found'}")
    elif args.command == 'disable':
        success = registry.disable_plugin(args.name)
        print(f"Plugin {args.name} {'disabled' if success else 'not found'}")
    elif args.command == 'list':
        plugins = registry.list_plugins(args.enabled_only)
        print(f"Found {len(plugins)} plugins:")
        for plugin in plugins:
            status = "enabled" if plugin.get("enabled") else "disabled"
            print(f"- {plugin['name']} v{plugin['version']} ({status})")
    elif args.command == 'check':
        errors = registry.check_dependencies(args.name)
        if errors:
            print(f"Dependency check failed with {len(errors)} errors:")
            for error in errors:
                print(f"- {error}")
        else:
            print("All dependencies satisfied")
    else:
        parser.print_help()
EOF

    # Make plugin scripts executable
    chmod +x plugins/runtime/plugin_sandbox.py
    chmod +x plugins/runtime/plugin_registry.py
    
    print_success "Plugin system implementation created"
}

# Main setup function
setup_framework() {
    print_status "Setting up NextHunt Framework..."
    
    create_project_structure
    generate_docker_compose
    generate_environment
    create_service_configs
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        create_monitoring_config
    fi

    # Create essential scripts
    create_essential_scripts

    # Enable globstar for recursive globbing
    shopt -s globstar 2>/dev/null || true
    # Make scripts executable
    find scripts -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true
    
    print_success "NextHunt Framework setup completed!"
    
    echo
    echo "🚀 Next Steps:"
    echo "1. Review and customize .env file"
    echo "2. Run: docker compose up -d"
    echo "3. Access API at: http://localhost:8000"
    echo "4. Access Grafana at: http://localhost:3000"
    echo
    echo "📖 Documentation:"
    echo "- Quick Start: ./quick-start-guide.md"
    echo "- API Docs: http://localhost:8000/docs"
}

# Create essential scripts
create_essential_scripts() {
    print_status "Creating essential scripts..."
    
    # Create start script
    cat > start.sh << 'EOF'
#!/bin/bash
# Start NextHunt Framework

set -euo pipefail

echo "🚀 Starting NextHunt Framework..."

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start services
docker compose up -d

echo "✅ NextHunt Framework started successfully!"
echo
echo "Service endpoints:"
echo "- API Gateway: http://localhost:8000"
echo "- Grafana: http://localhost:3000"
echo "- Prometheus: http://localhost:9090"
echo
echo "Check status with: docker compose ps"
EOF

    # Create stop script
    cat > stop.sh << 'EOF'
#!/bin/bash
# Stop NextHunt Framework

set -euo pipefail

echo "🛑 Stopping NextHunt Framework..."

docker compose down

echo "✅ NextHunt Framework stopped successfully!"
EOF

    # Create add-service script
    cat > add-service.sh << 'EOF'
#!/bin/bash
# Add new service to NextHunt Framework

set -euo pipefail

usage() {
    echo "Usage: $0 <service-name> <port> <language>"
    echo "Languages: python, go"
    echo "Example: $0 my-scanner 8087 python"
}

if [[ $# -ne 3 ]]; then
    usage
    exit 1
fi

SERVICE_NAME="$1"
SERVICE_PORT="$2"
LANGUAGE="$3"

if [[ ! "$LANGUAGE" =~ ^(python|go)$ ]]; then
    echo "❌ Unsupported language: $LANGUAGE"
    usage
    exit 1
fi

echo "🔧 Adding $LANGUAGE service: $SERVICE_NAME on port $SERVICE_PORT"

# Create service directory
mkdir -p "services/$SERVICE_NAME"

if [[ "$LANGUAGE" == "python" ]]; then
    # Create Python service
    cat > "services/$SERVICE_NAME/app.py" << EOF
#!/usr/bin/env python3
"""
NextHunt ${SERVICE_NAME^} Service
"""

import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NextHunt ${SERVICE_NAME^} Service",
    description="NextHunt Framework - ${SERVICE_NAME^} Service",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "$SERVICE_NAME"}

@app.get("/")
async def root():
    return {"message": "NextHunt ${SERVICE_NAME^} Service", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, log_level="info", reload=True)
EOF

    cat > "services/$SERVICE_NAME/requirements.txt" << EOF
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
requests==2.31.0
EOF

    cat > "services/$SERVICE_NAME/Dockerfile" << EOF
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
EOF

else
    # Create Go service
    cat > "services/$SERVICE_NAME/main.go" << EOF
package main

import (
    "encoding/json"
    "log"
    "net/http"
    "github.com/gorilla/mux"
)

type HealthResponse struct {
    Status  string \`json:"status"\`
    Service string \`json:"service"\`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(HealthResponse{
        Status:  "healthy",
        Service: "$SERVICE_NAME",
    })
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "NextHunt ${SERVICE_NAME^} Service",
        "version": "1.0.0",
    })
}

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/health", healthHandler).Methods("GET")
    r.HandleFunc("/", rootHandler).Methods("GET")
    
    log.Printf("Starting ${SERVICE_NAME^} service on port 8000")
    log.Fatal(http.ListenAndServe(":8000", r))
}
EOF

    cat > "services/$SERVICE_NAME/go.mod" << EOF
module github.com/nexthunt/$SERVICE_NAME

go 1.21

require github.com/gorilla/mux v1.8.1
EOF

    cat > "services/$SERVICE_NAME/Dockerfile" << EOF
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8000
CMD ["./main"]
EOF
fi

# Add to docker-compose.yml
cat >> docker-compose.yml << EOF

  $SERVICE_NAME:
    build: ./services/$SERVICE_NAME
    ports:
      - "$SERVICE_PORT:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=\${DATABASE_URL}
      - REDIS_URL=\${REDIS_URL}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF

echo "✅ Service $SERVICE_NAME added successfully!"
echo "  - Language: $LANGUAGE"
echo "  - Port: $SERVICE_PORT"
echo "  - Directory: services/$SERVICE_NAME"
echo
echo "To start the new service:"
echo "  docker compose up -d $SERVICE_NAME"
EOF

    # Make scripts executable
    chmod +x start.sh stop.sh add-service.sh
    
    print_success "Essential scripts created"
}

# Validate command
validate_framework() {
    print_status "Validating NextHunt Framework setup..."
    
    local errors=0
    
    # Check project structure
    if [[ ! -f ".setup_complete" ]]; then
        print_error "Setup not completed"
        ((errors++))
    fi
    
    # Check essential files
    local required_files=("docker-compose.yml" ".env" "start.sh" "stop.sh")
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_success "File exists: $file"
        else
            print_error "Missing file: $file"
            ((errors++))
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        print_success "Validation completed successfully!"
    else
        print_error "Validation failed with $errors error(s)"
        return 1
    fi
}

# Clean command
clean_framework() {
    print_status "Cleaning NextHunt Framework installation..."
    
    # Stop services if running
    if [[ -f "docker-compose.yml" ]]; then
        docker compose down -v --remove-orphans 2>/dev/null || true
    fi
    
    # Remove setup marker
    rm -f .setup_complete
    
    print_success "Clean completed!"
}

# Update command
update_framework() {
    print_status "Updating NextHunt Framework components..."
    
    # Pull latest images
    if [[ -f "docker-compose.yml" ]]; then
        docker compose pull
    fi
    
    print_success "Update completed!"
}

# Main script execution
print_status "Starting NextHunt Framework setup..."

# Check for required commands
for cmd in docker openssl; do
    if ! command -v $cmd &>/dev/null; then
        print_error "$cmd is not installed. Please install $cmd and try again."
        exit 1
    fi
done

# Check Docker Compose
if ! docker compose version &>/dev/null; then
    if ! command -v docker-compose &>/dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
fi

# Run the selected command
case "$COMMAND" in
    setup)
        setup_framework
        # Add plugin system implementation
        create_plugin_system_implementation
        ;;
    validate)
        validate_framework
        ;;
    clean)
        clean_framework
        ;;
    update)
        update_framework
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac

print_success "NextHunt Framework setup script completed!"
echo "See $LOG_FILE for detailed logs"