#!/bin/bash
# Fix port conflicts in docker-compose.yml

print_status() { echo -e "\033[0;34m[*]\033[0m $1"; }

print_status "Fixing service port conflicts..."

# Update docker-compose.yml to use unique ports for each service
cat >> docker-compose.yml << 'EOF'

  reconnaissance:
    build: ./services/reconnaissance
    ports:
      - "8080:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped

  intelligence:
    build: ./services/intelligence
    ports:
      - "8081:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=postgresql://nexthunt:${POSTGRES_PASSWORD}@postgres:5432/nexthunt
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped

  scanning:
    build: ./services/scanning
    ports:
      - "8084:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped

  exploitation:
    build: ./services/exploitation
    ports:
      - "8083:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped

  reporting:
    build: ./services/reporting
    ports:
      - "8085:8000"
    environment:
      - API_GATEWAY_URL=http://api-gateway:8000
      - DATABASE_URL=postgresql://nexthunt:${POSTGRES_PASSWORD}@postgres:5432/nexthunt
    depends_on:
      - api-gateway
    networks:
      - nexthunt-network
    restart: unless-stopped
EOF

print_status "Port conflicts fixed"
