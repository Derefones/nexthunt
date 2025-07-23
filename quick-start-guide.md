# NextHunt Framework - Quick Start Guide

## Prerequisites
- Docker (20.10+) and Docker Compose (v2)
- 8GB+ RAM recommended
- 20GB+ disk space
- Linux/macOS/Windows with WSL2

## Quick Setup (5 minutes)

### 1. Initialize Framework
```bash
# Clone or download the NextHunt setup files
# Make setup script executable
chmod +x nexthunt-setup.sh

# Run setup
./nexthunt-setup.sh setup
```

### 2. Start Services
```bash
# Enter project directory
cd nexthunt

# Start all services
./start.sh

# Wait for services to be ready (about 2-3 minutes)
```

### 3. Verify Installation
```bash
# Check service status
docker compose ps

# Test API Gateway
curl http://localhost:8000/health
```

## Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| API Gateway | http://localhost:8000 | Main entry point |
| Reconnaissance | http://localhost:8080 | Target discovery |
| Intelligence | http://localhost:8081 | Threat analysis |
| Scanning | http://localhost:8084 | Vulnerability scanning |
| Exploitation | http://localhost:8083 | Controlled exploitation |
| Reporting | http://localhost:8085 | Report generation |
| Grafana | http://localhost:3000 | Monitoring dashboard |
| Prometheus | http://localhost:9090 | Metrics collection |

## Basic Usage Examples

### Health Check All Services
```bash
# API Gateway
curl http://localhost:8000/health

# Individual services
curl http://localhost:8080/health  # Reconnaissance
curl http://localhost:8081/health  # Intelligence
curl http://localhost:8084/health  # Scanning
```

### Start a Basic Scan
```bash
# Reconnaissance scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "type": "subdomain"}'

# Vulnerability scan
curl -X POST http://localhost:8084/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "basic"}'
```

### Check Scan Status
```bash
# Get scan status (replace SCAN_ID with actual ID)
curl http://localhost:8080/api/v1/scan/SCAN_ID
```

### Generate Report
```bash
# Generate PDF report
curl -X POST http://localhost:8085/api/v1/report \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "SCAN_ID", "format": "pdf"}'
```

## Management Commands

### Service Control
```bash
# Start all services
./start.sh

# Stop all services
./stop.sh

# Restart specific service
docker compose restart reconnaissance

# View logs
docker compose logs -f api-gateway
```

### Add New Service
```bash
# Add Python service
./add-service.sh my-scanner 8087 python

# Add Go service
./add-service.sh my-tool 8088 go

# Start new service
docker compose up -d my-scanner
```

### Update Configuration
```bash
# Edit environment variables
vi .env

# Restart services to apply changes
docker compose restart
```

## Monitoring and Troubleshooting

### Check System Status
```bash
# Service status
docker compose ps

# Resource usage
docker stats

# Service logs
docker compose logs --tail=100 [service-name]
```

### Access Monitoring
1. **Grafana Dashboard**: http://localhost:3000
   - Username: admin
   - Password: Check `.env` file for `GRAFANA_PASSWORD`

2. **Prometheus Metrics**: http://localhost:9090

### Common Issues

#### Services won't start
```bash
# Check Docker daemon
docker info

# Check port conflicts
netstat -tlnp | grep :8000

# Clean restart
docker compose down -v
docker compose up -d
```

#### Out of memory errors
```bash
# Check available memory
free -h

# Reduce service replicas
# Edit docker-compose.yml and remove some services temporarily
```

#### Permission errors
```bash
# Fix script permissions
chmod +x *.sh

# Fix directory permissions
sudo chown -R $USER:$USER nexthunt/
```

#### Database connection issues
```bash
# Check PostgreSQL status
docker compose exec postgres pg_isready -U nexthunt

# Reset database
docker compose down -v postgres
docker compose up -d postgres
```

## Configuration Guide

### Environment Variables
Key settings in `.env` file:

```bash
# Basic settings
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=info

# Database
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_password

# Security
JWT_SECRET=your_jwt_secret
AUTHENTICATION_REQUIRED=true

# Scanning limits
MAX_CONCURRENT_SCANS=10
SCAN_TIMEOUT=3600
```

### Service Configuration
Each service can be configured via environment variables:

```yaml
# In docker-compose.yml
environment:
  - CUSTOM_SETTING=value
  - API_KEY=${EXTERNAL_API_KEY}
```

## Security Considerations

### Production Deployment
Before production use:

1. **Change default passwords**:
   ```bash
   # Generate new passwords
   openssl rand -base64 32
   ```

2. **Enable HTTPS**:
   ```bash
   # Use production deployment script
   ./production-deployment.sh deploy --ssl \
     -d your-domain.com -e admin@your-domain.com
   ```

3. **Configure authentication**:
   ```bash
   # Set in .env
   AUTHENTICATION_REQUIRED=true
   JWT_SECRET=your_very_secure_secret
   ```

### Network Security
- Services communicate on internal Docker network
- Only necessary ports exposed to host
- API authentication required for sensitive operations

## Advanced Usage

### Plugin Development

NextHunt uses a secure plugin system for extending functionality. Here's how to develop your own plugins:

#### 1. Plugin Structure

Every plugin needs the following structure:
```
my-plugin/
├── plugin.yaml       # Plugin manifest
├── __init__.py       # Plugin initialization
├── main.py          # Plugin main logic
├── requirements.txt # Dependencies
└── README.md        # Documentation
```

#### 2. Plugin Manifest

Create a `plugin.yaml` file:
```yaml
name: "my-vulnerability-scanner"
version: "1.0.0"
description: "Custom vulnerability scanner plugin"
author: "Your Name"
license: "MIT"
  
# Plugin dependencies
dependencies:
  nexthunt: ">=1.0.0"
  services:
    - reconnaissance
    - reporting

# Security permissions required
permissions:
  required:
    - "scan:create"
    - "scan:read"
    - "report:write"
  optional:
    - "file:read:/tmp"
    - "exec:nmap"
```

#### 3. Plugin Implementation

Create `main.py`:
```python
from nexthunt import Plugin, ScanResult, Vulnerability

class CustomScanner(Plugin):
    def __init__(self):
        super().__init__(
            name="my-vulnerability-scanner",
            version="1.0.0",
            description="Custom vulnerability scanner"
        )
    
    async def scan(self, target, options):
        # Your scanning logic here
        vulnerabilities = []
        
        # Example vulnerability
        vulnerabilities.append(Vulnerability(
            title="Example Finding",
            description="This is an example finding",
            severity="medium",
            evidence="Test evidence",
            remediation="Test remediation"
        ))
        
        return ScanResult(
            target=target,
            vulnerabilities=vulnerabilities,
            metadata={"scanner": "custom-scanner"}
        )
```

#### 4. Register Plugin

```bash
# Register your plugin
./plugins/runtime/plugin_registry.py register path/to/my-plugin

# Enable your plugin
./plugins/runtime/plugin_registry.py enable my-vulnerability-scanner
```

### API Reference

NextHunt provides comprehensive REST APIs for all services. Here are the core endpoints:

#### Authentication API

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|--------------|
| `/auth/login` | POST | Get authentication token | No |
| `/auth/logout` | POST | Invalidate token | Yes |
| `/auth/refresh` | POST | Refresh token | Yes |

**Example Login:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'
```

#### Scan API

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|--------------|
| `/api/v1/scans` | GET | List all scans | Yes |
| `/api/v1/scans` | POST | Start new scan | Yes |
| `/api/v1/scans/{id}` | GET | Get scan details | Yes |
| `/api/v1/scans/{id}/status` | GET | Get scan status | Yes |
| `/api/v1/scans/{id}/results` | GET | Get scan results | Yes |

**Example Scan Request:**
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "comprehensive",
    "options": {
      "ports": "1-1000",
      "intensity": "medium"
    }
  }'
```

#### Report API

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|--------------|
| `/api/v1/reports` | GET | List all reports | Yes |
| `/api/v1/reports` | POST | Generate report | Yes |
| `/api/v1/reports/{id}` | GET | Get report | Yes |
| `/api/v1/reports/{id}/download` | GET | Download report | Yes |

**Example Report Generation:**
```bash
curl -X POST http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "SCAN_ID",
    "format": "pdf",
    "template": "executive",
    "include_details": true
  }'
```

### Advanced Configuration

#### Environment Variables

See the full list of available environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `production` | Environment (development, production) |
| `DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `API_PORT` | `8000` | API gateway port |
| `AUTHENTICATION_REQUIRED` | `true` | Require authentication for all endpoints |
| `JWT_SECRET` | | JWT signing secret |
| `JWT_EXPIRATION` | `3600` | JWT token expiration in seconds |
| `CORS_ENABLED` | `false` | Enable CORS for all origins |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics |
| `POSTGRES_PASSWORD` | | PostgreSQL password |
| `REDIS_PASSWORD` | | Redis password |

#### Production Security Checklist

Before deploying to production:

- [ ] Change all default passwords in `.env`
- [ ] Enable TLS with `TLS_ENABLED=true`
- [ ] Set `CORS_ENABLED=false` or configure specific origins
- [ ] Set `DEBUG=false`
- [ ] Configure proper rate limiting
- [ ] Set up backup schedule
- [ ] Configure alerting in Prometheus
- [ ] Set up log forwarding to a central system
- [ ] Perform security scan on all custom code
- [ ] Validate plugin permissions
