#!/bin/bash
# NextHunt Service Template Generator
# Creates service structure from templates with customization

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

# Default values
SERVICE_NAME=""
SERVICE_PORT=""
SERVICE_TYPE="python"  # python, go, node
SERVICE_DESCRIPTION=""
OUTPUT_DIR="services"
TEMPLATE_DIR="templates"

# Show usage
usage() {
    cat << EOF
NextHunt Service Template Generator

Usage: $0 [OPTIONS]

Options:
  -n, --name NAME         Service name (required)
  -p, --port PORT         Service port (required)
  -t, --type TYPE         Service type: python, go, node (default: python)
  -d, --description DESC  Service description
  -o, --output DIR        Output directory (default: services)
  -h, --help              Show this help

Examples:
  $0 --name vulnerability-scanner --port 8087 --type python
  $0 --name osint-collector --port 8088 --type go --description "OSINT Data Collection Service"
EOF
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                SERVICE_NAME="$2"
                shift 2
                ;;
            -p|--port)
                SERVICE_PORT="$2"
                shift 2
                ;;
            -t|--type)
                SERVICE_TYPE="$2"
                if [[ ! "$SERVICE_TYPE" =~ ^(python|go|node)$ ]]; then
                    print_error "Invalid service type: $SERVICE_TYPE"
                    usage
                    exit 1
                fi
                shift 2
                ;;
            -d|--description)
                SERVICE_DESCRIPTION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$SERVICE_NAME" ]]; then
        print_error "Service name is required"
        usage
        exit 1
    fi
    
    if [[ -z "$SERVICE_PORT" ]]; then
        print_error "Service port is required"
        usage
        exit 1
    fi
    
    # Default description if not provided
    if [[ -z "$SERVICE_DESCRIPTION" ]]; then
        SERVICE_DESCRIPTION="NextHunt ${SERVICE_NAME^} Service"
    fi
}

# Create service directory
create_service_directory() {
    local service_dir="$OUTPUT_DIR/$SERVICE_NAME"
    
    # Check if service directory already exists
    if [[ -d "$service_dir" ]]; then
        print_error "Service directory already exists: $service_dir"
        exit 1
    fi
    
    mkdir -p "$service_dir"
    print_status "Created service directory: $service_dir"
    
    return 0
}

# Generate Python service
generate_python_service() {
    local service_dir="$OUTPUT_DIR/$SERVICE_NAME"
    
    # Create main application file
    cat > "$service_dir/app.py" << EOF
#!/usr/bin/env python3
"""
$SERVICE_DESCRIPTION
"""

import os
import logging
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from typing import Dict, Any, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="$SERVICE_DESCRIPTION",
    description="NextHunt Framework - ${SERVICE_NAME^} Service",
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

# Dependency for authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """Validate authentication token"""
    # In production, implement proper token validation
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    # For development, just return a mock user
    return {"id": "user_id", "username": "test_user", "role": "admin"}

# Authentication can be disabled for development
auth_required = os.getenv("AUTHENTICATION_REQUIRED", "true").lower() == "true"
auth_dependency = get_current_user if auth_required else lambda: {"role": "anonymous"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "$SERVICE_NAME",
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "$SERVICE_DESCRIPTION",
        "version": "1.0.0",
        "documentation": "/docs"
    }

@app.get("/api/v1/$SERVICE_NAME/info")
async def service_info(current_user: Dict[str, Any] = Depends(auth_dependency)):
    """Get service information"""
    return {
        "name": "$SERVICE_NAME",
        "description": "$SERVICE_DESCRIPTION",
        "version": "1.0.0",
        "type": "python-fastapi",
        "user": current_user["role"]
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        log_level="debug" if debug else "info",
        reload=debug
    )
EOF

    # Create requirements file
    cat > "$service_dir/requirements.txt" << EOF
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
requests==2.31.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
prometheus-client==0.19.0
structlog==23.2.0
EOF

    # Create Dockerfile
    cat > "$service_dir/Dockerfile" << EOF
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \\
    pip install --no-cache-dir -r requirements.txt

# Copy service files
COPY . .

# Run as non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Start service
CMD ["python", "app.py"]
EOF

    # Create README
    cat > "$service_dir/README.md" << EOF
# $SERVICE_DESCRIPTION

## Overview
This service is part of the NextHunt Framework and provides ${SERVICE_NAME//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`
   pip install -r requirements.txt
   \`\`\`

2. Run the service:
   \`\`\`
   python app.py
   \`\`\`

3. Access the API documentation:
   - Swagger UI: http://localhost:$SERVICE_PORT/docs
   - ReDoc: http://localhost:$SERVICE_PORT/redoc

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint
- GET /api/v1/$SERVICE_NAME/info - Service information

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
- HOST - Service host (default: 0.0.0.0)
- DEBUG - Enable debug mode (default: false)
- AUTHENTICATION_REQUIRED - Require authentication (default: true)
EOF

    print_success "Generated Python service: $SERVICE_NAME"
}

# Generate Go service
generate_go_service() {
    local service_dir="$OUTPUT_DIR/$SERVICE_NAME"
    
    # Create main.go
    cat > "$service_dir/main.go" << EOF
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
}

// ServiceInfo represents service information
type ServiceInfo struct {
	Name        string \`json:"name"\`
	Description string \`json:"description"\`
	Version     string \`json:"version"\`
	Type        string \`json:"type"\`
	User        string \`json:"user"\`
}

// RequestMetrics holds prometheus metrics
type RequestMetrics struct {
	requestDuration *prometheus.HistogramVec
	requestCounter  *prometheus.CounterVec
}

// Initialize prometheus metrics
func initMetrics() *RequestMetrics {
	metrics := &RequestMetrics{
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Duration of HTTP requests in seconds",
				Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"path", "method", "status"},
		),
		requestCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"path", "method", "status"},
		),
	}

	prometheus.MustRegister(metrics.requestDuration, metrics.requestCounter)
	return metrics
}

// Middleware to log HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s %s", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// Middleware to track metrics
func metricsMiddleware(metrics *RequestMetrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Create response wrapper to capture status code
			wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
			
			// Call next handler
			next.ServeHTTP(wrapper, r)
			
			// Record metrics
			duration := time.Since(start).Seconds()
			path := getPathTemplate(r.URL.Path)
			statusCode := strconv.Itoa(wrapper.statusCode)
			
			metrics.requestDuration.WithLabelValues(path, r.Method, statusCode).Observe(duration)
			metrics.requestCounter.WithLabelValues(path, r.Method, statusCode).Inc()
		})
	}
}

// Response wrapper to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

// Capture status code when WriteHeader is called
func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Get path template for metrics to avoid cardinality explosion
func getPathTemplate(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func main() {
	// Get environment variables
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// Initialize router and metrics
	router := mux.NewRouter()
	metrics := initMetrics()
	
	// Add middleware
	router.Use(loggingMiddleware)
	router.Use(metricsMiddleware(metrics))
	
	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{
			Status:  "healthy",
			Service: "$SERVICE_NAME",
			Version: "1.0.0",
		})
	}).Methods("GET")
	
	// Root endpoint
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":       "$SERVICE_DESCRIPTION",
			"version":       "1.0.0",
			"documentation": "/docs",
		})
	}).Methods("GET")
	
	// Service info endpoint
	router.HandleFunc("/api/v1/$SERVICE_NAME/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ServiceInfo{
			Name:        "$SERVICE_NAME",
			Description: "$SERVICE_DESCRIPTION",
			Version:     "1.0.0",
			Type:        "go-service",
			User:        "anonymous", // In production, get from auth token
		})
	}).Methods("GET")
	
	// Prometheus metrics endpoint
	router.Handle("/metrics", promhttp.Handler())
	
	// Start server
	log.Printf("Starting $SERVICE_NAME service on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
EOF

    # Create go.mod file
    cat > "$service_dir/go.mod" << EOF
module github.com/nexthunt/$SERVICE_NAME

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

    # Create Dockerfile
    cat > "$service_dir/Dockerfile" << EOF
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
    -o service .

# Final stage
FROM alpine:latest

# Add security patches and CA certificates
RUN apk --no-cache add ca-certificates tzdata && \
    update-ca-certificates

# Create non-root user
RUN adduser -D -H -h /app appuser
WORKDIR /app

# Copy binary from build stage
COPY --from=builder /app/service .

# Use non-root user
USER appuser

# Set execute permissions
RUN chmod +x /app/service

# Configure health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run with explicit port binding
CMD ["./service"]
EOF

    # Create README
    cat > "$service_dir/README.md" << EOF
# $SERVICE_DESCRIPTION

## Overview
This service is part of the NextHunt Framework and provides ${SERVICE_NAME//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`
   go mod download
   \`\`\`

2. Run the service:
   \`\`\`
   go run main.go
   \`\`\`

3. Build the service:
   \`\`\`
   go build -o service .
   \`\`\`

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint
- GET /api/v1/$SERVICE_NAME/info - Service information
- GET /metrics - Prometheus metrics

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
EOF

    print_success "Generated Go service: $SERVICE_NAME"
}

# Generate Node.js service
generate_node_service() {
    local service_dir="$OUTPUT_DIR/$SERVICE_NAME"
    
    # Create package.json
    cat > "$service_dir/package.json" << EOF
{
  "name": "$SERVICE_NAME",
  "version": "1.0.0",
  "description": "$SERVICE_DESCRIPTION",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest"
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
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "prom-client": "^15.0.0",
    "winston": "^3.11.0",
    "jsonwebtoken": "^9.0.2"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "nodemon": "^3.0.1",
    "supertest": "^6.3.3"
  }
}
EOF

    # Create main application file
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

// Load environment variables
require('dotenv').config();

// Create Express app
const app = express();
const port = process.env.PORT || 8000;

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Configure Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'path', 'status'],
  registers: [register]
});

// HTTP request duration
const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'path', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10],
  registers: [register]
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

// Request metrics middleware
app.use((req, res, next) => {
  const end = httpRequestDurationMicroseconds.startTimer();
  res.on('finish', () => {
    const path = req.route ? req.route.path : req.path;
    httpRequestsTotal.inc({ method: req.method, path, status: res.statusCode });
    end({ method: req.method, path, status: res.statusCode });
  });
  next();
});

// Auth middleware
const authRequired = process.env.AUTHENTICATION_REQUIRED === 'true';
const authMiddleware = (req, res, next) => {
  if (!authRequired) {
    req.user = { role: 'anonymous' };
    return next();
  }
  
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // In production, verify with proper secret
    // const user = jwt.verify(token, process.env.JWT_SECRET);
    
    // For development, just decode without verification
    const user = jwt.decode(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    logger.error('Auth error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: '$SERVICE_NAME',
    version: '1.0.0'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '$SERVICE_DESCRIPTION',
    version: '1.0.0',
    documentation: '/docs'
  });
});

// Service info endpoint
app.get('/api/v1/$SERVICE_NAME/info', authMiddleware, (req, res) => {
  res.json({
    name: '$SERVICE_NAME',
    description: '$SERVICE_DESCRIPTION',
    version: '1.0.0',
    type: 'nodejs-express',
    user: req.user.role
  });
});

// Prometheus metrics endpoint
app.get('/metrics', (req, res) => {
  res.set('Content-Type', register.contentType);
  register.metrics().then(metrics => res.end(metrics));
});

// Start server
app.listen(port, () => {
  logger.info(\`$SERVICE_NAME service listening on port \${port}\`);
});

// Handle process termination
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down...');
  process.exit(0);
});

// Export app for testing
module.exports = app;
EOF

    # Create Dockerfile
    cat > "$service_dir/Dockerfile" << EOF
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy app source
COPY . .

# Create non-root user
RUN addgroup -g 1001 appuser && \\
    adduser -D -u 1001 -G appuser appuser

# Set ownership and permissions
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Start service
CMD ["node", "index.js"]
EOF

    # Create README
    cat > "$service_dir/README.md" << EOF
# $SERVICE_DESCRIPTION

## Overview
This service is part of the NextHunt Framework and provides ${SERVICE_NAME//-/ } functionality.

## Development
1. Install dependencies:
   \`\`\`
   npm install
   \`\`\`

2. Run the service:
   \`\`\`
   npm start
   \`\`\`

3. Run in development mode (with auto-reload):
   \`\`\`
   npm run dev
   \`\`\`

## API Endpoints
- GET /health - Health check endpoint
- GET / - Root endpoint
- GET /api/v1/$SERVICE_NAME/info - Service information
- GET /metrics - Prometheus metrics

## Configuration
Environment variables:
- PORT - Service port (default: 8000)
- LOG_LEVEL - Logging level (default: info)
- AUTHENTICATION_REQUIRED - Require authentication (default: true)
- JWT_SECRET - Secret for JWT authentication
EOF

    print_success "Generated Node.js service: $SERVICE_NAME"
}

# Add service to docker-compose.yml
add_to_docker_compose() {
    if [[ ! -f "docker-compose.yml" ]]; then
        print_warning "docker-compose.yml not found, skipping service registration"
        return 0
    fi
    
    print_status "Adding service to docker-compose.yml..."
    
    cat >> docker-compose.yml << EOF

  $SERVICE_NAME:
    build: ./services/$SERVICE_NAME
    ports:
      - "$SERVICE_PORT:8000"
    environment:
      - PORT=8000
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=\${DATABASE_URL}
      - REDIS_URL=\${REDIS_URL}
      - AUTHENTICATION_REQUIRED=\${AUTHENTICATION_REQUIRED:-true}
      - LOG_LEVEL=\${LOG_LEVEL:-info}
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF

    print_success "Added service to docker-compose.yml"
}

# Add service to configuration
add_to_service_config() {
    if [[ ! -f "service-config.json" ]]; then
        print_warning "service-config.json not found, creating basic configuration..."
        
        # Create basic service config if it doesn't exist
        cat > "service-config.json" << EOF
{
  "services": {}
}
EOF
    fi
    
    print_status "Adding service to service-config.json..."
    
    # Check if jq is available
    if command -v jq >/dev/null 2>&1; then
        # Use jq to modify JSON
        jq ".services[\"$SERVICE_NAME\"] = {
            \"name\": \"$SERVICE_NAME\",
            \"description\": \"$SERVICE_DESCRIPTION\",
            \"port\": $SERVICE_PORT,
            \"type\": \"$SERVICE_TYPE\",
            \"enabled\": true,
            \"resources\": {
                \"memory\": \"256Mi\",
                \"cpu\": \"0.2\"
            },
            \"healthcheck\": {
                \"endpoint\": \"/health\",
                \"interval\": \"30s\",
                \"timeout\": \"10s\",
                \"retries\": 3
            }
        }" "service-config.json" > "service-config.json.tmp"
        
        mv "service-config.json.tmp" "service-config.json"
    else
        # Fallback to basic JSON insertion
        local service_json="{
            \"name\": \"$SERVICE_NAME\",
            \"description\": \"$SERVICE_DESCRIPTION\",
            \"port\": $SERVICE_PORT,
            \"type\": \"$SERVICE_TYPE\",
            \"enabled\": true,
            \"resources\": {
                \"memory\": \"256Mi\",
                \"cpu\": \"0.2\"
            },
            \"healthcheck\": {
                \"endpoint\": \"/health\",
                \"interval\": \"30s\",
                \"timeout\": \"10s\",
                \"retries\": 3
            }
        }"
        
        # Replace the closing brace of services object with the new service and closing brace
        sed -i.bak "s/\"services\": {/\"services\": {\n    \"$SERVICE_NAME\": $service_json,/g" "service-config.json"
        # Remove the trailing comma if it's the only service
        sed -i.bak "s/,\n  }/\n  }/g" "service-config.json"
        
        # Remove backup file
        rm -f "service-config.json.bak"
    fi
    
    print_success "Added service to service-config.json"
}

# Create convenient script to test the service
create_test_script() {
    local service_dir="$OUTPUT_DIR/$SERVICE_NAME"
    local test_script="$service_dir/test.sh"
    
    cat > "$test_script" << EOF
#!/bin/bash
# Test script for $SERVICE_NAME service

echo "Testing $SERVICE_NAME Service..."

# Wait for service to be ready
echo "Waiting for service to start..."
sleep 5

# Test health endpoint
echo "1. Testing health endpoint..."
curl -s http://localhost:$SERVICE_PORT/health | jq .

# Test service info endpoint
echo -e "\n2. Testing service info endpoint..."
curl -s http://localhost:$SERVICE_PORT/api/v1/$SERVICE_NAME/info | jq .

# Test metrics endpoint
echo -e "\n3. Testing metrics endpoint..."
curl -s http://localhost:$SERVICE_PORT/metrics | head -10

echo -e "\n✅ $SERVICE_NAME Service tests completed!"
EOF

    chmod +x "$test_script"
    print_success "Created test script: $test_script"
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Create service directory
    create_service_directory
    
    # Generate service based on type
    case "$SERVICE_TYPE" in
        python)
            generate_python_service
            ;;
        go)
            generate_go_service
            ;;
        node)
            generate_node_service
            ;;
    esac
    
    # Add service to docker-compose
    add_to_docker_compose
    
    # Add service to configuration
    add_to_service_config
    
    # Create test script
    create_test_script
    
    # Print final instructions
    echo
    echo "🚀 Service '$SERVICE_NAME' created successfully!"
    echo "  - Type: $SERVICE_TYPE"
    echo "  - Port: $SERVICE_PORT"
    echo "  - Location: $OUTPUT_DIR/$SERVICE_NAME"
    echo
    echo "To start the service:"
    echo "  docker compose up -d $SERVICE_NAME"
    echo
    echo "To test the service:"
    echo "  $OUTPUT_DIR/$SERVICE_NAME/test.sh"
    echo
    echo "To access the service:"
    echo "  http://localhost:$SERVICE_PORT"
}

# Execute main function if script is not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi