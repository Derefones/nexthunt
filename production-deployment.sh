#!/bin/bash
# Production Deployment Script for NextHunt Framework
# Handles SSL, security hardening, monitoring, and production optimizations

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

# Configuration
DOMAIN=""
EMAIL=""
ENVIRONMENT="production"
ENABLE_SSL=false
ENABLE_MONITORING=true
ENABLE_BACKUP=true

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

Commands:
    deploy      Deploy NextHunt to production
    update      Update existing production deployment
    rollback    Rollback to previous version
    backup      Create production backup
    status      Check deployment status

Options:
    -d, --domain DOMAIN     Production domain name
    -e, --email EMAIL       Email for SSL certificate
    --ssl                   Enable SSL/TLS with Let's Encrypt
    --no-monitoring        Disable monitoring stack
    --no-backup           Disable automated backups
    -h, --help            Show this help message

Examples:
    $0 deploy -d nexthunt.company.com -e admin@company.com --ssl
    $0 update
    $0 backup
    $0 status
EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            deploy|update|rollback|backup|status)
                COMMAND="$1"
                shift
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -e|--email)
                EMAIL="$2"
                shift 2
                ;;
            --ssl)
                ENABLE_SSL=true
                shift
                ;;
            --no-monitoring)
                ENABLE_MONITORING=false
                shift
                ;;
            --no-backup)
                ENABLE_BACKUP=false
                shift
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
    
    if [[ -z "${COMMAND:-}" ]]; then
        print_error "Command is required"
        usage
        exit 1
    fi
}

# Production environment setup
setup_production_environment() {
    print_status "Setting up production environment..."
    
    # Create necessary directories
    mkdir -p {config/alertmanager,scripts/backup}
    
    # Update environment configuration
    cat >> .env << EOF

# Production Environment Overrides
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=warn
TLS_ENABLED=$ENABLE_SSL
DOMAIN=$DOMAIN

# Production Security
CORS_ENABLED=false
AUTHENTICATION_REQUIRED=true
RATE_LIMITING_ENABLED=true
API_KEY_VALIDATION=true

# Production Performance
WORKER_COUNT=10
MAX_CONCURRENT_SCANS=50
CACHE_ENABLED=true
COMPRESSION_ENABLED=true

# Production Monitoring
METRICS_ENABLED=$ENABLE_MONITORING
TRACING_ENABLED=true
AUDIT_ENABLED=true
EOF

    print_success "Production environment configured"
}

# SSL/TLS setup with Let's Encrypt
setup_ssl() {
    if [[ "$ENABLE_SSL" != "true" ]]; then
        return 0
    fi
    
    print_status "Setting up SSL/TLS certificates..."
    
    if [[ -z "$DOMAIN" ]] || [[ -z "$EMAIL" ]]; then
        print_error "Domain and email are required for SSL setup"
        exit 1
    fi
    
    # Install certbot if not present
    if ! command -v certbot &>/dev/null; then
        print_status "Installing certbot..."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y certbot
        elif command -v yum &>/dev/null; then
            yum install -y certbot
        elif command -v apk &>/dev/null; then
            apk add --no-cache certbot
        else
            print_error "Could not install certbot. Please install manually."
            exit 1
        fi
    fi
    
    # Generate SSL certificates
    mkdir -p certs
    
    if [[ ! -f "certs/$DOMAIN.crt" ]]; then
        print_status "Generating SSL certificates for $DOMAIN..."
        certbot certonly --standalone -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive
        
        # Copy certificates to the certs directory
        cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem certs/$DOMAIN.crt
        cp /etc/letsencrypt/live/$DOMAIN/privkey.pem certs/$DOMAIN.key
        
        chmod 644 certs/*.crt
    fi
    
    # Update nginx configuration for SSL
    create_nginx_ssl_config
    
    print_success "SSL certificates configured"
}

# Create nginx SSL configuration
create_nginx_ssl_config() {
    cat > nginx.conf << EOF
events {
    worker_connections 1024;
}

http {
    upstream nexthunt_api {
        server api-gateway:8000;
    }
    
    upstream nexthunt_grafana {
        server grafana:3000;
    }
    
    # HTTP redirect to HTTPS
    server {
        listen 80;
        server_name $DOMAIN;
        
        location / {
            return 301 https://\$host\$request_uri;
        }
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
    }
    
    # HTTPS configuration
    server {
        listen 443 ssl;
        server_name $DOMAIN;
        
        ssl_certificate /etc/nginx/certs/$DOMAIN.crt;
        ssl_certificate_key /etc/nginx/certs/$DOMAIN.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Content-Security-Policy "default-src 'self';" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        
        # API Gateway proxy
        location /api/ {
            proxy_pass http://nexthunt_api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Grafana proxy
        location /grafana/ {
            proxy_pass http://nexthunt_grafana/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Root redirect to API docs
        location / {
            proxy_pass http://nexthunt_api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF

    # Add nginx to docker-compose
    cat >> docker-compose.yml << EOF

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./data/certbot/www:/var/www/certbot:ro
    depends_on:
      - api-gateway
      - grafana
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF
}

# Production monitoring setup
setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != "true" ]]; then
        return 0
    fi
    
    print_status "Setting up production monitoring..."
    
    # Create alertmanager configuration
    mkdir -p config/alertmanager
    cat > config/alertmanager/alertmanager.yml << EOF
global:
  smtp_smarthost: '${SMTP_SERVER:-localhost:587}'
  smtp_from: '${ALERT_EMAIL_FROM:-alerts@$DOMAIN}'
  smtp_auth_username: '${SMTP_USERNAME:-}'
  smtp_auth_password: '${SMTP_PASSWORD:-}'
  smtp_require_tls: true

route:
  group_by: ['alertname', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h
  receiver: 'email-notifications'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
    continue: true

receivers:
- name: 'email-notifications'
  email_configs:
  - to: '${ALERT_EMAIL_TO:-admin@$DOMAIN}'
    send_resolved: true
    html: '{{ template "email.default.html" . }}'
- name: 'critical-alerts'
  email_configs:
  - to: '${CRITICAL_EMAIL_TO:-admin@$DOMAIN}'
    send_resolved: true
  slack_configs:
  - api_url: '${SLACK_WEBHOOK_URL:-https://hooks.slack.com/services/REPLACE/THIS/VALUE}'
    channel: '#alerts'
    send_resolved: true
    icon_url: 'https://avatars3.githubusercontent.com/u/3380462'
    title: '{{ template "slack.default.title" . }}'
    text: '{{ template "slack.default.text" . }}'

templates:
- '/etc/alertmanager/template/*.tmpl'
EOF

    # Add alertmanager to docker-compose
    cat >> docker-compose.yml << EOF

  alertmanager:
    image: prom/alertmanager:latest
    volumes:
      - ./config/alertmanager:/etc/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://${DOMAIN}/alertmanager/'
    ports:
      - "9093:9093"
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF

    # Create Prometheus rules for alerts
    mkdir -p config/prometheus/rules
    cat > config/prometheus/rules/nexthunt_alerts.yml << EOF
groups:
- name: nexthunt_alerts
  rules:
  - alert: ServiceDown
    expr: up == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Service {{ \$labels.job }} down"
      description: "{{ \$labels.job }} has been down for more than 2 minutes."
      
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate for {{ \$labels.job }}"
      description: "{{ \$labels.job }} has a high HTTP error rate (> 10%)."
      
  - alert: SlowResponseTime
    expr: http_request_duration_seconds{quantile="0.9"} > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Slow response time for {{ \$labels.job }}"
      description: "{{ \$labels.job }} has a 90th percentile response time > 2s."
      
  - alert: HighCPUUsage
    expr: (1 - avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on {{ \$labels.instance }}"
      description: "{{ \$labels.instance }} has CPU usage above 90% for 5 minutes."
      
  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage on {{ \$labels.instance }}"
      description: "{{ \$labels.instance }} has memory usage above 90% for 5 minutes."
      
  - alert: HighDiskUsage
    expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100 < 10
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High disk usage on {{ \$labels.instance }}"
      description: "{{ \$labels.instance }} has less than 10% disk space available."
EOF

    # Update Prometheus config to include alerts
    sed -i 's|rule_files:|rule_files:\n  - "rules/nexthunt_alerts.yml"|' config/prometheus/prometheus.yml

    print_success "Production monitoring configured"
}

# Production backup setup
setup_backup() {
    if [[ "$ENABLE_BACKUP" != "true" ]]; then
        return 0
    fi
    
    print_status "Setting up automated backups..."
    
    # Create backup directories
    mkdir -p scripts/backup backups
    
    # Create backup service
    cat >> docker-compose.yml << EOF

  backup:
    image: postgres:15-alpine
    volumes:
      - ./scripts/backup:/backup-scripts:ro
      - ./backups:/backups
      - postgres_data:/var/lib/postgresql/data:ro
    environment:
      - PGPASSWORD=\${POSTGRES_PASSWORD}
      - PGUSER=nexthunt
      - PGHOST=postgres
      - PGDATABASE=nexthunt
      - BACKUP_SCHEDULE=\${BACKUP_SCHEDULE:-0 2 * * *}
    entrypoint: []
    command: sh -c 'crond -f -d 8 & echo "\${BACKUP_SCHEDULE} /backup-scripts/production-backup.sh" > /etc/crontabs/root && tail -f /dev/null'
    networks:
      - nexthunt-network
    depends_on:
      - postgres
EOF

    # Create production backup script
    cat > scripts/backup/production-backup.sh << 'EOF'
#!/bin/sh
# Production backup script

BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="nexthunt_prod_$TIMESTAMP"

echo "Starting production backup: $BACKUP_NAME"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
pg_dump -h postgres -U nexthunt nexthunt | gzip > "$BACKUP_DIR/${BACKUP_NAME}_database.sql.gz"

# Data backups
tar czf "$BACKUP_DIR/${BACKUP_NAME}_scans.tar.gz" -C /data scans/ 2>/dev/null || echo "No scan data to backup"
tar czf "$BACKUP_DIR/${BACKUP_NAME}_reports.tar.gz" -C /data reports/ 2>/dev/null || echo "No report data to backup"

# Cleanup old backups (keep last 30 days)
find "$BACKUP_DIR" -name "nexthunt_prod_*" -mtime +30 -delete 2>/dev/null || true

echo "Backup completed: $BACKUP_NAME"
EOF

    # Create restore script
    cat > scripts/backup/restore.sh << 'EOF'
#!/bin/bash
# Restore from backup

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <backup-name>"
  echo "Example: $0 nexthunt_prod_20231231_235959"
  exit 1
fi

BACKUP_NAME="$1"
BACKUP_DIR="./backups"

echo "Restoring from backup: $BACKUP_NAME"

if [ ! -f "$BACKUP_DIR/${BACKUP_NAME}_database.sql.gz" ]; then
  echo "Error: Backup file not found: $BACKUP_DIR/${BACKUP_NAME}_database.sql.gz"
  exit 1
fi

echo "Stopping services..."
docker compose down

echo "Restoring database..."
gunzip -c "$BACKUP_DIR/${BACKUP_NAME}_database.sql.gz" | docker compose run --rm postgres psql -h postgres -U nexthunt -d nexthunt

if [ -f "$BACKUP_DIR/${BACKUP_NAME}_scans.tar.gz" ]; then
  echo "Restoring scan data..."
  docker run --rm -v nexthunt_scan_results:/data -v "$PWD/backups:/backups" alpine sh -c "tar xzf /backups/${BACKUP_NAME}_scans.tar.gz -C /data"
fi

if [ -f "$BACKUP_DIR/${BACKUP_NAME}_reports.tar.gz" ]; then
  echo "Restoring reports..."
  docker run --rm -v nexthunt_reports:/data -v "$PWD/backups:/backups" alpine sh -c "tar xzf /backups/${BACKUP_NAME}_reports.tar.gz -C /data"
fi

echo "Restore completed!"
echo "Start services with: docker compose up -d"
EOF

    # Create backup utilities
    cat > scripts/backup/full-backup.sh << 'EOF'
#!/bin/bash
# Full production backup script

set -euo pipefail

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="nexthunt_full_$TIMESTAMP"

echo "Starting full backup: $BACKUP_NAME"

mkdir -p "$BACKUP_DIR"

# Database backup
docker compose exec -T postgres pg_dump -U nexthunt nexthunt | gzip > "$BACKUP_DIR/${BACKUP_NAME}_database.sql.gz"

# Volume backups
docker run --rm -v nexthunt_scan_results:/data/scans -v "$PWD/backups:/backups" alpine tar czf "/backups/${BACKUP_NAME}_scans.tar.gz" -C /data scans/ 2>/dev/null || echo "No scan data"
docker run --rm -v nexthunt_reports:/data/reports -v "$PWD/backups:/backups" alpine tar czf "/backups/${BACKUP_NAME}_reports.tar.gz" -C /data reports/ 2>/dev/null || echo "No report data"

echo "Full backup completed: $BACKUP_NAME"
EOF

    chmod +x scripts/backup/*.sh
    
    print_success "Automated backups configured"
}

# Deploy to production
deploy_production() {
    print_status "Deploying NextHunt to production..."
    
    # Validate prerequisites
    if [[ ! -f "docker-compose.yml" ]] || [[ ! -f ".env" ]]; then
        print_error "Missing required files. Ensure you're in the NextHunt project directory."
        exit 1
    fi
    
    # Setup production configurations
    setup_production_environment
    setup_ssl
    setup_monitoring
    setup_backup
    
    # Security hardening
    if [[ -x "scripts/security-hardening.sh" ]]; then
        ./scripts/security-hardening.sh
    fi
    
    # Start services
    print_status "Starting production services..."
    docker compose down --remove-orphans
    docker compose up -d --build
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Validate deployment
    validate_deployment
    
    print_success "Production deployment completed!"
    
    # Display access information
    echo
    echo "🌐 Production Access:"
    if [[ "$ENABLE_SSL" == "true" ]]; then
        echo "- API: https://$DOMAIN/api"
        echo "- UI: https://$DOMAIN/"
        echo "- Monitoring: https://$DOMAIN/grafana"
    else
        echo "- API: http://$DOMAIN:8000/api"
        echo "- UI: http://$DOMAIN:8000/"
        echo "- Monitoring: http://$DOMAIN:3000"
    fi
    echo
    echo "🔧 Management:"
    echo "- Update: $0 update"
    echo "- Backup: $0 backup"
    echo "- Status: $0 status"
}

# Validate deployment
validate_deployment() {
    print_status "Validating deployment..."
    
    local failed=0
    
    # Check service health
    local services=("api-gateway" "postgres" "redis")
    for service in "${services[@]}"; do
        if ! docker compose ps "$service" | grep -q "Up"; then
            print_error "Service $service is not running"
            ((failed++))
        else
            print_success "Service $service is running"
        fi
    done
    
    # Check API endpoint
    local api_url="http://localhost:8000"
    if [[ "$ENABLE_SSL" == "true" ]]; then
        api_url="https://$DOMAIN"
    fi
    
    if curl -f -s "$api_url/health" &>/dev/null; then
        print_success "API endpoint is accessible"
    else
        print_error "API endpoint is not accessible"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        print_error "Deployment validation failed with $failed errors"
        return 1
    fi
    
    print_success "Deployment validation passed"
}

# Update production deployment
update_production() {
    print_status "Updating production deployment..."
    
    # Create backup before update
    backup_production
    
    # Pull latest images
    docker compose pull
    
    # Rolling update
    docker compose up -d --no-deps api-gateway
    sleep 10
    docker compose up -d --no-deps reconnaissance intelligence scanning exploitation reporting
    
    # Validate update
    validate_deployment
    
    print_success "Production update completed!"
}

# Rollback production deployment
rollback_production() {
    print_status "Rolling back production deployment..."
    
    # Find latest backup
    local latest_backup
    latest_backup=$(ls -t backups/nexthunt_prod_* 2>/dev/null | head -n1 | sed 's/.*nexthunt_prod_\([0-9_]*\).*/\1/')
    
    if [[ -z "$latest_backup" ]]; then
        print_error "No backups found for rollback"
        exit 1
    fi
    
    print_status "Rolling back to backup: $latest_backup"
    
    # Stop services
    docker compose down
    
    # Restore from backup
    ./scripts/backup/restore.sh "nexthunt_prod_$latest_backup"
    
    # Start services
    docker compose up -d
    
    # Validate rollback
    validate_deployment
    
    print_success "Rollback completed successfully!"
}

# Create production backup
backup_production() {
    print_status "Creating production backup..."
    
    # Ensure backup directory exists
    mkdir -p backups
    
    # Run backup script
    if [[ -f "scripts/backup/full-backup.sh" ]]; then
        ./scripts/backup/full-backup.sh
        print_success "Backup completed successfully"
    else
        print_error "Backup script not found"
        exit 1
    fi
}

# Check deployment status
check_status() {
    print_status "Checking deployment status..."
    
    # Check Docker Compose services
    docker compose ps
    
    # Check service health
    local services=("api-gateway" "reconnaissance" "intelligence" "scanning" "exploitation" "reporting")
    echo
    echo "Service Health:"
    for service in "${services[@]}"; do
        if docker compose ps "$service" | grep -q "Up"; then
            local health_url="http://localhost:8000/health"
            if [[ "$service" != "api-gateway" ]]; then
                port=$(docker compose port "$service" 8000 | cut -d':' -f2)
                health_url="http://localhost:${port}/health"
            fi
            
            if curl -s "$health_url" | grep -q "healthy"; then
                print_success "$service: Healthy"
            else
                print_warning "$service: Running but health check failed"
            fi
        else
            print_error "$service: Not running"
        fi
    done
    
    # Check resource usage
    echo
    echo "Resource Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
}

# Main execution
main() {
    # Parse arguments
    parse_args "$@"
    
    # Execute command
    case "$COMMAND" in
        deploy)
            deploy_production
            ;;
        update)
            update_production
            ;;
        rollback)
            rollback_production
            ;;
        backup)
            backup_production
            ;;
        status)
            check_status
            ;;
        *)
            print_error "Unknown command: $COMMAND"
            usage
            exit 1
            ;;
    esac
}

main "$@"
