#!/bin/bash
# Unified service addition script for NextHunt Framework
# Prevents port conflicts and ensures consistent service structure

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

# Global variables for rollback
ROLLBACK_ACTIONS=()
TEMP_FILES=()

# Add rollback action
add_rollback() {
    ROLLBACK_ACTIONS+=("$1")
}

# Execute rollback
execute_rollback() {
    print_warning "Executing rollback..."
    for ((i=${#ROLLBACK_ACTIONS[@]}-1; i>=0; i--)); do
        print_status "Rollback: ${ROLLBACK_ACTIONS[i]}"
        eval "${ROLLBACK_ACTIONS[i]}" || true
    done
    
    # Clean up temporary files
    for temp_file in "${TEMP_FILES[@]}"; do
        [[ -f "$temp_file" ]] && rm -f "$temp_file"
    done
    
    ROLLBACK_ACTIONS=()
    TEMP_FILES=()
}

# Trap for cleanup on exit
cleanup_on_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        execute_rollback
    fi
    exit $exit_code
}

trap cleanup_on_exit EXIT

usage() {
    cat << EOF
Usage: $0 <service-name> <port> <language> [OPTIONS]

Arguments:
    service-name    Name of the service (lowercase, alphanumeric, hyphens allowed)
    port           Port number for the service (8000-9999 recommended)
    language       Programming language (python, go, node)

Options:
    --description   Service description
    --template      Use specific template (basic, scanner, api, worker)
    --no-docker     Skip Docker Compose integration
    --force         Overwrite existing service
    --remove        Remove existing service
    --help          Show this help

Examples:
    $0 vulnerability-scanner 8087 python
    $0 osint-collector 8088 go --template scanner
    $0 web-crawler 8089 node --description "Web crawling service"
    $0 old-service 0 "" --remove

EOF
}

# Enhanced validation functions
validate_service_name() {
    local name="$1"
    
    # Check format
    if [[ ! $name =~ ^[a-z0-9-]+$ ]]; then
        print_error "Service name must contain only lowercase letters, numbers, and hyphens"
        return 1
    fi
    
    # Check length
    if [[ ${#name} -lt 3 || ${#name} -gt 63 ]]; then
        print_error "Service name must be between 3 and 63 characters"
        return 1
    fi
    
    # Check reserved words
    local reserved_names=(
        "docker" "compose" "kubernetes" "k8s" "prometheus" "grafana"
        "postgres" "postgresql" "redis" "nginx" "apache" "mysql"
        "api" "web" "app" "service" "server" "client" "admin"
        "root" "system" "daemon" "kernel" "init" "systemd"
        "nexthunt" "nexthunt-"*
    )
    
    for reserved in "${reserved_names[@]}"; do
        if [[ "$name" == "$reserved" ]] || [[ "$name" == nexthunt-* ]]; then
            print_error "Service name '$name' is reserved or conflicts with system names"
            return 1
        fi
    done
    
    return 0
}

validate_port() {
    local port="$1"
    
    # Check if port is numeric
    if [[ ! $port =~ ^[0-9]+$ ]]; then
        print_error "Port must be a number"
        return 1
    fi
    
    # Check port range
    if [[ $port -lt 1024 || $port -gt 65535 ]]; then
        print_error "Port must be between 1024 and 65535"
        return 1
    fi
    
    # Check if port is in use by system
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            print_error "Port $port is already in use by system"
            return 1
        fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            print_error "Port $port is already in use by system"
            return 1
        fi
    fi
    
    return 0
}

validate_language() {
    local language="$1"
    
    case "$language" in
        python|go|node|nodejs)
            return 0
            ;;
        *)
            print_error "Unsupported language: $language. Supported: python, go, node"
            return 1
            ;;
    esac
}

# Enhanced port conflict detection using yq if available
check_port_conflicts() {
    local port="$1"
    local service_name="$2"
    
    if [[ ! -f "docker-compose.yml" ]]; then
        return 0  # No conflicts if no compose file
    fi
    
    # Use yq if available for proper YAML parsing
    if command -v yq >/dev/null 2>&1; then
        local conflicting_services
        conflicting_services=$(yq eval '.services | to_entries | .[] | select(.value.ports[]? | test("^'$port':")) | .key' docker-compose.yml 2>/dev/null || true)
        
        if [[ -n "$conflicting_services" && "$conflicting_services" != "$service_name" ]]; then
            print_error "Port $port is already used by service: $conflicting_services"
            return 1
        fi
    else
        # Fallback to grep-based detection with improved regex
        local conflicting_line
        conflicting_line=$(grep -n "^\s*-\s*['\"]\\?$port:" docker-compose.yml 2>/dev/null || true)
        
        if [[ -n "$conflicting_line" ]]; then
            # Extract service name by looking backwards for service definition
            local line_num
            line_num=$(echo "$conflicting_line" | cut -d: -f1)
            local conflicting_service
            conflicting_service=$(awk -v line="$line_num" 'NR < line && /^[[:space:]]*[a-zA-Z0-9_-]+:/ { service = $1; gsub(/:/, "", service) } END { print service }' docker-compose.yml)
            
            if [[ -n "$conflicting_service" && "$conflicting_service" != "$service_name" ]]; then
                print_error "Port $port is already used by service: $conflicting_service"
                return 1
            fi
        fi
    fi
    
    # Check .env for port variable conflicts
    if [[ -f ".env" ]]; then
        local port_var_pattern="PORT_.*=${port}$"
        local service_var="PORT_$(echo "$service_name" | tr '[:lower:]-' '[:upper:]_')"
        
        if grep -q "$port_var_pattern" .env && ! grep -q "^${service_var}=${port}$" .env; then
            local conflicting_var
            conflicting_var=$(grep "$port_var_pattern" .env | cut -d= -f1)
            print_error "Port $port is already assigned to environment variable: $conflicting_var"
            return 1
        fi
    fi
    
    return 0
}

# Check for existing service
check_existing_service() {
    local service_name="$1"
    local force="$2"
    
    if [[ -d "services/$service_name" ]]; then
        if [[ "$force" == "true" ]]; then
            print_warning "Existing service directory will be overwritten: services/$service_name"
            return 0
        else
            print_error "Service already exists: $service_name"
            print_status "Use --force to overwrite or --remove to delete"
            return 1
        fi
    fi
    
    # Check if service exists in docker-compose.yml
    if [[ -f "docker-compose.yml" ]]; then
        if command -v yq >/dev/null 2>&1; then
            if yq eval ".services.\"$service_name\"" docker-compose.yml >/dev/null 2>&1; then
                if [[ "$force" != "true" ]]; then
                    print_error "Service definition exists in docker-compose.yml: $service_name"
                    return 1
                fi
            fi
        else
            if grep -q "^[[:space:]]*${service_name}:" docker-compose.yml; then
                if [[ "$force" != "true" ]]; then
                    print_error "Service definition exists in docker-compose.yml: $service_name"
                    return 1
                fi
            fi
        fi
    fi
    
    return 0
}

# Generate Python service with enhanced features
generate_python_service() {
    local service_name="$1"
    local service_port="$2"
    local description="$3"
    local template="$4"
    local service_dir="services/$service_name"
    
    print_status "Generating Python service: $service_name"
    
    # Create service directory
    mkdir -p "$service_dir"
    add_rollback "rm -rf '$service_dir'"
    
    # Create enhanced app.py based on template
    case "$template" in
        "scanner")
            create_python_scanner_template "$service_dir" "$service_name" "$description"
            ;;
        "api")
            create_python_api_template "$service_dir" "$service_name" "$description"
            ;;
        "worker")
            create_python_worker_template "$service_dir" "$service_name" "$description"
            ;;
        *)
            create_python_basic_template "$service_dir" "$service_name" "$description"
            ;;
    esac
    
    # Create requirements.txt
    cat > "$service_dir/requirements.txt" << 'EOF'
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
aiohttp==3.9.1
beautifulsoup4==4.12.2
lxml==4.9.3
EOF
    
    # Create Dockerfile with security best practices
    cat > "$service_dir/Dockerfile" << 'EOF'
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy service files
COPY . .

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Use non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start service
CMD ["python", "app.py"]
EOF
    
    # Create README
    cat > "$service_dir/README.md" << EOF
# $description

## Overview
This service is part of the NextHunt Framework and provides ${service_name//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

2. Run the service:
   \`\`\`bash
   python app.py
   \`\`\`

3. Access the API documentation:
   - Swagger UI: http://localhost:$service_port/docs
   - ReDoc: http://localhost:$service_port/redoc

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint
- GET /api/v1/$service_name/info - Service information

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
- HOST - Service host (default: 0.0.0.0)
- DEBUG - Enable debug mode (default: false)
- AUTHENTICATION_REQUIRED - Require authentication (default: true)

## Docker
Build and run with Docker:
\`\`\`bash
docker build -t nexthunt/$service_name .
docker run -p $service_port:8000 nexthunt/$service_name
\`\`\`
EOF
    
    print_success "Python service generated: $service_name"
}

# Generate Go service with complete implementation
generate_go_service() {
    local service_name="$1"
    local service_port="$2"
    local description="$3"
    local template="$4"
    local service_dir="services/$service_name"
    
    print_status "Generating Go service: $service_name"
    
    # Create service directory
    mkdir -p "$service_dir"
    add_rollback "rm -rf '$service_dir'"
    
    # Create main.go
    cat > "$service_dir/main.go" << EOF
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

// HealthResponse represents health check response
type HealthResponse struct {
	Status  string \`json:"status"\`
	Service string \`json:"service"\`
	Version string \`json:"version"\`
	Time    int64  \`json:"timestamp"\`
}

// ServiceInfo represents service information
type ServiceInfo struct {
	Name        string \`json:"name"\`
	Description string \`json:"description"\`
	Version     string \`json:"version"\`
	Type        string \`json:"type"\`
}

// Metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

// Middleware for logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create response recorder to capture status code
		recorder := &responseRecorder{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(recorder, r)
		
		duration := time.Since(start)
		log.Printf("[%s] %s %s %d %v", r.Method, r.RequestURI, r.RemoteAddr, recorder.statusCode, duration)
		
		// Record metrics
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, fmt.Sprintf("%d", recorder.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
	})
}

// Response recorder to capture status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

// Handlers
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{
		Status:  "healthy",
		Service: "$service_name",
		Version: "1.0.0",
		Time:    time.Now().Unix(),
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "$description",
		"service": "$service_name",
		"version": "1.0.0",
	})
}

func serviceInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ServiceInfo{
		Name:        "$service_name",
		Description: "$description",
		Version:     "1.0.0",
		Type:        "go",
	})
}

func main() {
	// Get configuration from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	
	// Setup router
	r := mux.NewRouter()
	
	// Add middleware
	r.Use(loggingMiddleware)
	
	// Routes
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/", rootHandler).Methods("GET")
	r.HandleFunc("/api/v1/$service_name/info", serviceInfoHandler).Methods("GET")
	
	// Metrics endpoint
	r.Handle("/metrics", promhttp.Handler())
	
	// Setup server with timeouts
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", host, port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Start server in goroutine
	go func() {
		log.Printf("Starting $service_name service on %s:%s", host, port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()
	
	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down server...")
	
	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	
	log.Println("Server stopped")
}
EOF

    # Create go.mod
    cat > "$service_dir/go.mod" << EOF
module github.com/nexthunt/$service_name

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
    cat > "$service_dir/Dockerfile" << 'EOF'
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git for private modules
RUN apk --no-cache add git

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags=-static' \
    -o service .

# Final stage
FROM alpine:latest

# Add security updates and CA certificates
RUN apk --no-cache add ca-certificates tzdata && \
    update-ca-certificates

# Create non-root user
RUN adduser -D -H -h /app appuser

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /app/service .

# Change ownership
RUN chown appuser:appuser service

# Use non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start service
CMD ["./service"]
EOF

    # Create README
    cat > "$service_dir/README.md" << EOF
# $description

## Overview
This service is part of the NextHunt Framework and provides ${service_name//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`bash
   go mod download
   \`\`\`

2. Run the service:
   \`\`\`bash
   go run main.go
   \`\`\`

3. Build the service:
   \`\`\`bash
   go build -o service .
   \`\`\`

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint  
- GET /api/v1/$service_name/info - Service information
- GET /metrics - Prometheus metrics

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
- HOST - Service host (default: 0.0.0.0)

## Docker
Build and run with Docker:
\`\`\`bash
docker build -t nexthunt/$service_name .
docker run -p $service_port:8000 nexthunt/$service_name
\`\`\`
EOF

    print_success "Go service generated: $service_name"
}

# Generate Node.js service with complete implementation
generate_node_service() {
    local service_name="$1"
    local service_port="$2"
    local description="$3"
    local template="$4"
    local service_dir="services/$service_name"
    
    print_status "Generating Node.js service: $service_name"
    
    # Create service directory
    mkdir -p "$service_dir"
    add_rollback "rm -rf '$service_dir'"
    
    # Create package.json
    cat > "$service_dir/package.json" << EOF
{
  "name": "$service_name",
  "version": "1.0.0",
  "description": "$description",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest",
    "lint": "eslint .",
    "format": "prettier --write ."
  },
  "keywords": [
    "nexthunt",
    "security",
    "api"
  ],
  "author": "NextHunt Framework",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "winston": "^3.11.0",
    "prom-client": "^15.0.0",
    "dotenv": "^16.3.1",
    "jsonwebtoken": "^9.0.2",
    "express-rate-limit": "^7.1.5",
    "compression": "^1.7.4",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "eslint": "^8.56.0",
    "prettier": "^3.1.1",
    "@types/node": "^20.10.5"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
EOF

    # Create main index.js
    cat > "$service_dir/index.js" << EOF
'use strict';

// Import dependencies
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const winston = require('winston');
const promClient = require('prom-client');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

// Load environment variables
require('dotenv').config();

// Create Express app
const app = express();
const port = process.env.PORT || 8000;
const host = process.env.HOST || '0.0.0.0';

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: '$service_name' },
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Configure Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register]
});

// HTTP request duration
const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route'],
  registers: [register]
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', { 
  stream: { 
    write: (message) => logger.info(message.trim()) 
  } 
}));
app.use(limiter);

// Request metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestsTotal.labels(req.method, route, res.statusCode).inc();
    httpRequestDurationMicroseconds.labels(req.method, route).observe(duration);
  });
  
  next();
});

// Authentication middleware (optional)
const authRequired = process.env.AUTHENTICATION_REQUIRED === 'true';
const authMiddleware = (req, res, next) => {
  if (!authRequired) {
    req.user = { role: 'anonymous' };
    return next();
  }
  
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'development-secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error('JWT verification failed:', error);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: '$service_name',
    version: '1.0.0',
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '$description',
    service: '$service_name',
    version: '1.0.0',
    endpoints: [
      'GET /health',
      'GET /',
      'GET /api/v1/$service_name/info',
      'GET /metrics'
    ]
  });
});

// Service info endpoint
app.get('/api/v1/$service_name/info', authMiddleware, (req, res) => {
  res.json({
    name: '$service_name',
    description: '$description',
    version: '1.0.0',
    type: 'node',
    user: req.user,
    config: {
      authentication_required: authRequired,
      rate_limiting: true,
      cors_enabled: true
    }
  });
});

// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  const metrics = await register.metrics();
  res.end(metrics);
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.originalUrl
  });
});

// Start server
const server = app.listen(port, host, () => {
  logger.info(\`$service_name service listening on \${host}:\${port}\`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(\`Received \${signal}, starting graceful shutdown\`);
  
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
  
  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Export app for testing
module.exports = app;
EOF

    # Create .env file
    cat > "$service_dir/.env" << EOF
NODE_ENV=development
PORT=8000
HOST=0.0.0.0
LOG_LEVEL=info

# Authentication
AUTHENTICATION_REQUIRED=true
JWT_SECRET=your-jwt-secret-here

# External services
API_GATEWAY_URL=http://api-gateway:8000
DATABASE_URL=postgresql://nexthunt:password@postgres:5432/nexthunt
REDIS_URL=redis://:password@redis:6379
EOF

    # Create Dockerfile
    cat > "$service_dir/Dockerfile" << 'EOF'
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install app dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Bundle app source
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -S appuser -u 1001 -G appuser

# Change ownership
RUN chown -R appuser:appuser /app

# Use non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Start service
CMD ["node", "index.js"]
EOF

    # Create README
    cat > "$service_dir/README.md" << EOF
# $description

## Overview
This service is part of the NextHunt Framework and provides ${service_name//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

2. Run the service:
   \`\`\`bash
   npm start
   \`\`\`

3. Run in development mode (with auto-reload):
   \`\`\`bash
   npm run dev
   \`\`\`

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint
- GET /api/v1/$service_name/info - Service information
- GET /metrics - Prometheus metrics

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
- HOST - Service host (default: 0.0.0.0)
- LOG_LEVEL - Logging level (default: info)
- AUTHENTICATION_REQUIRED - Require authentication (default: true)
- JWT_SECRET - Secret for JWT authentication

## Docker
Build and run with Docker:
\`\`\`bash
docker build -t nexthunt/$service_name .
docker run -p $service_port:8000 nexthunt/$service_name
\`\`\`

## Testing
Run tests:
\`\`\`bash
npm test
\`\`\`

## Linting
Check code style:
\`\`\`bash
npm run lint
npm run format
\`\`\`
EOF

    print_success "Node.js service generated: $service_name"
}

# Template creation functions for Python
create_python_basic_template() {
    local service_dir="$1"
    local service_name="$2"
    local description="$3"
    
    cat > "$service_dir/app.py" << EOF
#!/usr/bin/env python3
"""
$description
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import uvicorn
from pydantic import BaseModel

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="$description",
    description="NextHunt Framework - ${service_name^} Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Security
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')

# Models
class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: int

class ServiceInfo(BaseModel):
    name: str
    description: str
    version: str
    type: str

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """Validate authentication token"""
    auth_required = os.getenv("AUTHENTICATION_REQUIRED", "true").lower() == "true"
    
    if not auth_required:
        return {"role": "anonymous"}
    
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Authentication token required")
    
    # In production, implement proper token validation
    return {"id": "user_id", "username": "test_user", "role": "admin"}

@app.middleware("http")
async def metrics_middleware(request, call_next):
    """Middleware to collect metrics"""
    start_time = datetime.now()
    response = await call_next(request)
    duration = (datetime.now() - start_time).total_seconds()
    
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    REQUEST_DURATION.observe(duration)
    
    return response

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        service="$service_name",
        version="1.0.0",
        timestamp=int(datetime.now().timestamp())
    )

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "$description",
        "service": "$service_name",
        "version": "1.0.0",
        "endpoints": [
            "GET /health",
            "GET /",
            "GET /api/v1/$service_name/info",
            "GET /metrics"
        ]
    }

@app.get("/api/v1/$service_name/info", response_model=ServiceInfo)
async def service_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get service information"""
    return ServiceInfo(
        name="$service_name",
        description="$description",
        version="1.0.0",
        type="python"
    )

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    from fastapi import Response
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        log_level="info",
        reload=debug
    )
EOF
}

# Add service to docker-compose using yq or fallback to text manipulation
add_to_docker_compose() {
    local service_name="$1"
    local service_port="$2"
    local no_docker="$3"
    
    if [[ "$no_docker" == "true" ]]; then
        print_status "Skipping Docker Compose integration"
        return 0
    fi
    
    if [[ ! -f "docker-compose.yml" ]]; then
        print_error "docker-compose.yml not found"
        return 1
    fi
    
    # Create backup
    local backup_file="docker-compose.yml.backup.$(date +%s)"
    cp docker-compose.yml "$backup_file"
    add_rollback "mv '$backup_file' docker-compose.yml"
    TEMP_FILES+=("$backup_file")
    
    # Check if service already exists and remove it if force mode
    if command -v yq >/dev/null 2>&1; then
        # Use yq for proper YAML manipulation
        if yq eval ".services.\"$service_name\"" docker-compose.yml >/dev/null 2>&1; then
            print_status "Removing existing service definition"
            yq eval "del(.services.\"$service_name\")" -i docker-compose.yml
        fi
        
        # Add new service definition
        local service_config
        service_config=$(cat << EOF
{
  "build": "./services/$service_name",
  "ports": ["$service_port:8000"],
  "environment": [
    "API_GATEWAY_URL=http://api-gateway:8000",
    "DATABASE_URL=postgresql://nexthunt:\${POSTGRES_PASSWORD}@postgres:5432/nexthunt",
    "REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379",
    "ENVIRONMENT=\${ENVIRONMENT:-production}",
    "DEBUG=\${DEBUG:-false}",
    "AUTHENTICATION_REQUIRED=\${AUTHENTICATION_REQUIRED:-true}"
  ],
  "depends_on": ["api-gateway"],
  "networks": ["nexthunt-network"],
  "restart": "unless-stopped"
}
EOF
)
        
        yq eval ".services.\"$service_name\" = $service_config" -i docker-compose.yml
    else
        # Fallback to text manipulation
        print_warning "yq not available, using text manipulation (less reliable)"
        
        # Remove existing service if present
        if grep -q "^[[:space:]]*${service_name}:" docker-compose.yml; then
            # Find service block and remove it (simplified approach)
            print_status "Removing existing service definition (manual cleanup may be needed)"
        fi
        
        # Append new service
        cat >> docker-compose.yml << EOF

  $service_name:
    build: ./services/$service_name
    ports:
      - "$service_port:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=postgresql://nexthunt:\${POSTGRES_PASSWORD}@postgres:5432/nexthunt
      - REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379
      - ENVIRONMENT=\${ENVIRONMENT:-production}
      - DEBUG=\${DEBUG:-false}
      - AUTHENTICATION_REQUIRED=\${AUTHENTICATION_REQUIRED:-true}
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF
    fi
    
    print_success "Service added to docker-compose.yml"
}

# Add port to .env file
add_to_env() {
    local service_name="$1"
    local service_port="$2"
    
    if [[ ! -f ".env" ]]; then
        print_warning ".env file not found, creating it"
        touch .env
        add_rollback "rm -f .env"
    fi
    
    # Create backup
    local backup_file=".env.backup.$(date +%s)"
    cp .env "$backup_file"
    add_rollback "mv '$backup_file' .env"
    TEMP_FILES+=("$backup_file")
    
    # Add port variable
    local port_var="PORT_$(echo "$service_name" | tr '[:lower:]-' '[:upper:]_')"
    
    # Remove existing variable if present
    if grep -q "^${port_var}=" .env; then
        sed -i "/^${port_var}=/d" .env
    fi
    
    # Add new variable
    echo "${port_var}=${service_port}" >> .env
    
    print_success "Port variable added to .env: ${port_var}=${service_port}"
}

# Remove service function
remove_service() {
    local service_name="$1"
    
    print_status "Removing service: $service_name"
    
    # Remove from docker-compose.yml
    if [[ -f "docker-compose.yml" ]]; then
        if command -v yq >/dev/null 2>&1; then
            if yq eval ".services.\"$service_name\"" docker-compose.yml >/dev/null 2>&1; then
                yq eval "del(.services.\"$service_name\")" -i docker-compose.yml
                print_success "Removed service from docker-compose.yml"
            fi
        else
            print_warning "yq not available, manual removal from docker-compose.yml required"
        fi
    fi
    
    # Remove from .env
    if [[ -f ".env" ]]; then
        local port_var="PORT_$(echo "$service_name" | tr '[:lower:]-' '[:upper:]_')"
        sed -i "/^${port_var}=/d" .env
        print_success "Removed port variable from .env"
    fi
    
    # Remove service directory
    if [[ -d "services/$service_name" ]]; then
        rm -rf "services/$service_name"
        print_success "Removed service directory"
    fi
    
    # Stop and remove container if running
    if docker ps -a --format "table {{.Names}}" | grep -q "${PWD##*/}[_-]${service_name}[_-]"; then
        docker compose rm -f "$service_name" 2>/dev/null || true
        print_success "Removed Docker container"
    fi
    
    print_success "Service $service_name removed successfully"
}

# Unit tests for critical functions
run_unit_tests() {
    print_status "Running unit tests..."
    
    # Test service name validation
    if validate_service_name "test-service"; then
        print_success "Service name validation: PASS"
    else
        print_error "Service name validation: FAIL"
        return 1
    fi
    
    # Test invalid service name
    if ! validate_service_name "Test_Service"; then
        print_success "Invalid service name rejection: PASS"
    else
        print_error "Invalid service name rejection: FAIL"
        return 1
    fi
    
    # Test port validation
    if validate_port "8080"; then
        print_success "Port validation: PASS"
    else
        print_error "Port validation: FAIL"
        return 1
    fi
    
    # Test invalid port
    if ! validate_port "80"; then
        print_success "Invalid port rejection: PASS"
    else
        print_error "Invalid port rejection: FAIL"
        return 1
    fi
    
    # Test language validation
    if validate_language "python" && validate_language "go" && validate_language "node"; then
        print_success "Language validation: PASS"
    else
        print_error "Language validation: FAIL"
        return 1
    fi
    
    print_success "All unit tests passed"
}

# Main execution
main() {
    local service_name=""
    local service_port=""
    local language=""
    local description=""
    local template="basic"
    local no_docker=false
    local force=false
    local remove=false
    local run_tests=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --description)
                description="$2"
                shift 2
                ;;
            --template)
                template="$2"
                shift 2
                ;;
            --no-docker)
                no_docker=true
                shift
                ;;
            --force)
                force=true
                shift
                ;;
            --remove)
                remove=true
                shift
                ;;
            --test)
                run_tests=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$service_name" ]]; then
                    service_name="$1"
                elif [[ -z "$service_port" ]]; then
                    service_port="$1"
                elif [[ -z "$language" ]]; then
                    language="$1"
                else
                    print_error "Too many arguments"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Run unit tests if requested
    if [[ "$run_tests" == "true" ]]; then
        run_unit_tests
        return $?
    fi
    
    # Handle removal
    if [[ "$remove" == "true" ]]; then
        if [[ -z "$service_name" ]]; then
            print_error "Service name required for removal"
            usage
            exit 1
        fi
        remove_service "$service_name"
        return 0
    fi
    
    # Validate required arguments
    if [[ -z "$service_name" || -z "$service_port" || -z "$language" ]]; then
        print_error "Missing required arguments"
        usage
        exit 1
    fi
    
    # Set default description
    if [[ -z "$description" ]]; then
        description="NextHunt ${service_name^} Service"
    fi
    
    # Validate inputs
    validate_service_name "$service_name" || exit 1
    validate_port "$service_port" || exit 1
    validate_language "$language" || exit 1
    
    # Check for conflicts
    check_port_conflicts "$service_port" "$service_name" || exit 1
    check_existing_service "$service_name" "$force" || exit 1
    
    # Generate service based on language
    case "$language" in
        python)
            generate_python_service "$service_name" "$service_port" "$description" "$template"
            ;;
        go)
            generate_go_service "$service_name" "$service_port" "$description" "$template"
            ;;
        node|nodejs)
            generate_node_service "$service_name" "$service_port" "$description" "$template"
            ;;
        *)
            print_error "Unsupported language: $language"
            exit 1
            ;;
    esac
    
    # Add to Docker Compose and environment
    add_to_docker_compose "$service_name" "$service_port" "$no_docker"
    add_to_env "$service_name" "$service_port"
    
    # Clear rollback actions on success
    ROLLBACK_ACTIONS=()
    
    print_success "Service $service_name created successfully!"
    echo
    echo "📁 Service Location: services/$service_name"
    echo "🚀 Port: $service_port"
    echo "🔧 Language: $language"
    echo "📝 Template: $template"
    echo
    echo "To start the service:"
    echo "  docker compose up -d $service_name"
    echo
    echo "To view logs:"
    echo "  docker compose logs -f $service_name"
    echo
    echo "To test the service:"
    echo "  curl http://localhost:$service_port/health"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
