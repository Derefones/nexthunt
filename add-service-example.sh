#!/bin/bash
# Example: Adding a custom web crawler service to NextHunt

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

# Add web crawler service using the built-in add-service script
add_web_crawler_service() {
    local SERVICE_NAME="web-crawler"
    local SERVICE_PORT="8086"
    
    print_status "Adding Web Crawler Service using template system..."
    
    # Check if we're in a NextHunt project directory
    if [[ ! -f "docker-compose.yml" ]] || [[ ! -f "add-service.sh" ]]; then
        print_error "Must be run from NextHunt project directory"
        print_error "Please run 'cd nexthunt' first"
        exit 1
    fi
    
    # Use the built-in add-service script
    if ./add-service.sh "$SERVICE_NAME" "$SERVICE_PORT" "python"; then
        print_success "Web Crawler Service base created successfully!"
    else
        print_error "Failed to create base service"
        exit 1
    fi
    
    # Enhance the service with crawler-specific functionality
    print_status "Enhancing service with crawler functionality..."
    
    # Add crawler-specific requirements
    cat >> "services/$SERVICE_NAME/requirements.txt" << 'EOF'
beautifulsoup4==4.12.2
aiohttp==3.9.1
selenium==4.15.2
scrapy==2.11.0
lxml==4.9.3
EOF

    # Replace the basic app.py with crawler functionality
    cat > "services/$SERVICE_NAME/app.py" << 'EOF'
#!/usr/bin/env python3
"""
NextHunt Web Crawler Service
Enhanced web crawling and content analysis
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import aiohttp
import uvicorn
from bs4 import BeautifulSoup

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NextHunt Web Crawler Service",
    description="Advanced web crawling and content analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state for crawl jobs
crawl_jobs = {}

class CrawlRequest(BaseModel):
    url: HttpUrl
    max_depth: int = 2
    max_pages: int = 100
    follow_external: bool = False
    extract_forms: bool = True
    extract_links: bool = True

class CrawlResult(BaseModel):
    job_id: str
    url: str
    status: str
    pages_crawled: int = 0
    links_found: List[str] = []
    forms_found: List[Dict] = []
    errors: List[str] = []
    started_at: datetime
    completed_at: Optional[datetime] = None

async def crawl_page(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    """Crawl a single page and extract information"""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status != 200:
                return {"error": f"HTTP {response.status}"}
            
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                links.append(absolute_url)
            
            # Extract forms
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_field in form.find_all('input'):
                    form_data['inputs'].append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    })
                
                forms.append(form_data)
            
            return {
                'url': url,
                'title': soup.title.string if soup.title else '',
                'links': links,
                'forms': forms,
                'status_code': response.status,
                'content_length': len(content)
            }
            
    except Exception as e:
        logger.error(f"Error crawling {url}: {e}")
        return {"error": str(e)}

async def perform_crawl(job_id: str, start_url: str, max_depth: int, max_pages: int):
    """Perform the actual crawling operation"""
    result = crawl_jobs[job_id]
    visited_urls = set()
    urls_to_visit = [(start_url, 0)]  # (url, depth)
    
    async with aiohttp.ClientSession() as session:
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url, depth = urls_to_visit.pop(0)
            
            if current_url in visited_urls or depth > max_depth:
                continue
                
            visited_urls.add(current_url)
            logger.info(f"Crawling: {current_url} (depth: {depth})")
            
            page_result = await crawl_page(session, current_url)
            
            if 'error' in page_result:
                result.errors.append(f"{current_url}: {page_result['error']}")
                continue
            
            # Add links to crawl queue
            if depth < max_depth:
                for link in page_result.get('links', []):
                    if link not in visited_urls:
                        urls_to_visit.append((link, depth + 1))
            
            # Update results
            result.pages_crawled += 1
            result.links_found.extend(page_result.get('links', []))
            result.forms_found.extend(page_result.get('forms', []))
            
            # Small delay to be respectful
            await asyncio.sleep(0.5)
    
    result.status = "completed"
    result.completed_at = datetime.now()
    logger.info(f"Crawl {job_id} completed. Pages: {result.pages_crawled}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "web-crawler",
        "active_jobs": len([j for j in crawl_jobs.values() if j.status == "running"])
    }

@app.post("/api/v1/crawl")
async def start_crawl(request: CrawlRequest, background_tasks: BackgroundTasks):
    """Start a new web crawling job"""
    job_id = f"crawl_{int(time.time())}"
    
    # Create result object
    result = CrawlResult(
        job_id=job_id,
        url=str(request.url),
        status="running",
        started_at=datetime.now()
    )
    
    crawl_jobs[job_id] = result
    
    # Start crawling in background
    background_tasks.add_task(
        perform_crawl,
        job_id,
        str(request.url),
        request.max_depth,
        request.max_pages
    )
    
    return {"job_id": job_id, "status": "started"}

@app.get("/api/v1/crawl/{job_id}")
async def get_crawl_status(job_id: str):
    """Get the status of a crawling job"""
    if job_id not in crawl_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return crawl_jobs[job_id]

@app.get("/api/v1/crawls")
async def list_crawls():
    """List all crawling jobs"""
    return {
        "jobs": list(crawl_jobs.values()),
        "total": len(crawl_jobs)
    }

@app.delete("/api/v1/crawl/{job_id}")
async def delete_crawl(job_id: str):
    """Delete a crawling job"""
    if job_id not in crawl_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    del crawl_jobs[job_id]
    return {"message": "Job deleted successfully"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "NextHunt Web Crawler Service",
        "version": "1.0.0",
        "status": "running",
        "active_jobs": len([j for j in crawl_jobs.values() if j.status == "running"])
    }

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True
    )
EOF

    # Create a simple test script
    cat > "test-web-crawler.sh" << 'EOF'
#!/bin/bash
# Test script for web crawler service

echo "Testing Web Crawler Service..."

# Wait for service to be ready
echo "Waiting for service to start..."
sleep 10

# Test health endpoint
echo "1. Testing health endpoint..."
curl -s http://localhost:8086/health | jq .

# Start a crawl job
echo -e "\n2. Starting crawl job..."
RESPONSE=$(curl -s -X POST http://localhost:8086/api/v1/crawl \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org",
    "max_depth": 1,
    "max_pages": 5
  }')

JOB_ID=$(echo $RESPONSE | jq -r .job_id)
echo "Job ID: $JOB_ID"

# Check job status
echo -e "\n3. Checking job status..."
sleep 5
curl -s http://localhost:8086/api/v1/crawl/$JOB_ID | jq .

# List all crawls
echo -e "\n4. Listing all crawls..."
curl -s http://localhost:8086/api/v1/crawls | jq .

echo -e "\n✅ Web Crawler Service tests completed!"
EOF

    chmod +x test-web-crawler.sh
    
    print_success "Web Crawler Service enhanced successfully!"
    echo
    echo "📁 Service Location: services/$SERVICE_NAME"
    echo "🚀 Port: $SERVICE_PORT"
    echo "🔧 Type: Enhanced Python Web Crawler"
    echo
    echo "Features:"
    echo "  ✓ Asynchronous web crawling"
    echo "  ✓ Form extraction"
    echo "  ✓ Link discovery"
    echo "  ✓ Background job processing"
    echo "  ✓ RESTful API interface"
    echo
    echo "To start using it:"
    echo "1. docker compose up -d $SERVICE_NAME"
    echo "2. ./test-web-crawler.sh"
    echo "3. View logs: docker compose logs -f $SERVICE_NAME"
    echo
    echo "API Endpoints:"
    echo "  POST /api/v1/crawl - Start new crawl"
    echo "  GET  /api/v1/crawl/{id} - Get crawl status" 
    echo "  GET  /api/v1/crawls - List all crawls"
    echo "  GET  /health - Health check"
}

# Execute the function
add_web_crawler_service

print_success "Web Crawler Service addition completed!"