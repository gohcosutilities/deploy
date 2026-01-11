#!/bin/bash

# ==========================================
# HCOS Deployment Script - Fixed Port Conflicts
# ==========================================

# Exit immediately if a command exits with a non-zero status
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
BASE_DIR="/opt/hcos_stack"
DOMAINS=("hcos.io" "key.hcos.io" "onedash.hcos.io" "request.hcos.io" "gohcos.com")
CERT_EMAIL="admin@hcos.io"
HOST_NGINX_CONF="/etc/nginx/sites-available/hcos_proxy"
HOST_APACHE_CONF="/etc/apache2/sites-available/hcos_proxy.conf"

# Function to check if port is in use
check_port() {
    local port=$1
    if netstat -tuln | grep ":$port " > /dev/null; then
        echo "Port $port is in use"
        return 0
    else
        echo "Port $port is available"
        return 1
    fi
}

# Function to kill process using port
kill_port() {
    local port=$1
    local service=$2
    echo -e "${YELLOW}Stopping $service to free port $port...${NC}"
    
    # Try systemctl first
    if systemctl is-active --quiet $service 2>/dev/null; then
        systemctl stop $service
        sleep 2
    fi
    
    # If port still in use, find and kill the process
    if check_port $port; then
        echo -e "${YELLOW}Port $port still in use, finding and killing process...${NC}"
        local pid=$(lsof -ti:$port 2>/dev/null | head -1)
        if [ ! -z "$pid" ]; then
            echo -e "${YELLOW}Killing process $pid using port $port...${NC}"
            kill -9 $pid 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Double check
    if check_port $port; then
        echo -e "${RED}Failed to free port $port. Please check manually.${NC}"
        return 1
    else
        echo -e "${GREEN}Port $port is now free.${NC}"
        return 0
    fi
}

echo -e "${GREEN}Starting HCOS Deployment Setup...${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Initial cleanup
echo -e "${YELLOW}Initial cleanup...${NC}"
mkdir -p $BASE_DIR
cd $BASE_DIR

# Stop any existing Docker containers
echo -e "${YELLOW}Stopping any existing Docker containers...${NC}"
docker compose -f docker-compose.yml down 2>/dev/null || true
docker compose -f docker-compose-ssl.yml down 2>/dev/null || true

# 1. Ask for GitHub Credentials
echo -e "${YELLOW}Please enter your GitHub credentials to clone private repositories.${NC}"
read -p "GitHub Username: " GITHUB_USER
read -s -p "GitHub Password/Token: " GITHUB_TOKEN
echo ""

# 2. DETECT AND STOP WEB SERVERS (IMPROVED - BEFORE INSTALLATION)
echo -e "${YELLOW}Checking for existing web servers...${NC}"

# First, check what's using port 80
echo -e "${YELLOW}Checking what's using port 80...${NC}"
if check_port 80; then
    echo -e "${YELLOW}Port 80 is in use. Identifying service...${NC}"
    
    # Try to identify the service
    if systemctl is-active --quiet nginx 2>/dev/null; then
        kill_port 80 "nginx"
    elif systemctl is-active --quiet apache2 2>/dev/null; then
        kill_port 80 "apache2"
    elif systemctl is-active --quiet httpd 2>/dev/null; then
        kill_port 80 "httpd"
    else
        # Unknown service, just kill whatever is on port 80
        kill_port 80 ""
    fi
fi

# Also check and free port 443 if needed
if check_port 443; then
    kill_port 443 ""
fi

# 3. Install packages WITHOUT starting services
echo -e "${YELLOW}Installing packages (services will NOT auto-start)...${NC}"
apt-get update -qq

# Install nginx without starting it
echo -e "${YELLOW}Installing nginx (will not auto-start)...${NC}"
apt-get install -y -qq --no-install-recommends nginx
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

# Install other packages
apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release git net-tools lsof

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}Installing Docker Compose...${NC}"
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# 4. Clone Repositories
echo -e "${YELLOW}Cloning repositories...${NC}"

clone_repo() {
    local URL=$1
    local FOLDER=$2
    local FULL_PATH="$BASE_DIR/$FOLDER"
    
    echo -e "${YELLOW}Processing $FOLDER...${NC}"
    
    if [ -d "$FOLDER" ]; then
        echo -e "Directory $FULL_PATH already exists. Removing to ensure clean state..."
        rm -rf "$FOLDER"
    fi

    # Inject credentials
    CLEAN_URL="${URL/https:\/\//https:\/\/$GITHUB_USER:$GITHUB_TOKEN@}"
    
    echo -e "Cloning into: ${GREEN}$FULL_PATH${NC}"
    if git clone "$CLEAN_URL" "$FOLDER"; then
        echo -e "${GREEN}Successfully cloned $FOLDER${NC}"
    else
        echo -e "${RED}FAILED to clone $FOLDER. Check username/token permissions.${NC}"
        exit 1
    fi
}

clone_repo "https://github.com/gohcosutilities/BACKEND-API" "BACKEND-API"
clone_repo "https://github.com/gohcosutilities/ONEDASH.HCOS.IO-BUILD" "ONEDASH.HCOS.IO-BUILD"
clone_repo "https://github.com/gohcosutilities/HOMEPAGE-BUILD" "HOMEPAGE-BUILD"
clone_repo "https://github.com/gohcosutilities/DEMONSTRATION-HOMEPAGE-BUILD" "DEMONSTRATION-HOMEPAGE-BUILD"

# Verify folders exist
if [ ! -d "$BASE_DIR/BACKEND-API" ]; then
    echo -e "${RED}CRITICAL: BACKEND-API folder missing. Script stopping.${NC}"
    exit 1
fi

# 5. CRITICAL: ENSURE PORT 80 IS FREE BEFORE SSL GENERATION
echo -e "${YELLOW}Preparing for SSL certificate generation...${NC}"
echo -e "${YELLOW}Ensuring port 80 is free for SSL container...${NC}"

# Double-check port 80
if check_port 80; then
    echo -e "${RED}Port 80 is still in use! Force killing...${NC}"
    kill_port 80 ""
fi

# Also ensure no nginx/apache is running
systemctl stop nginx 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true
systemctl stop httpd 2>/dev/null || true

# Setup SSL directories
echo -e "${YELLOW}Setting up SSL directories...${NC}"
mkdir -p nginx-ssl/templates
mkdir -p certbot/conf
mkdir -p certbot/www

# Create docker-compose-ssl.yml
cat > docker-compose-ssl.yml <<EOF
version: '3'
services:
  nginx:
    image: nginx:latest
    container_name: nginx-ssl-temp
    volumes:
      - ./nginx-ssl/templates:/etc/nginx/templates
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    ports:
      - "80:80"
    networks:
      - local

  certbot:
    image: certbot/certbot:latest
    container_name: certbot-ssl-temp
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    command: certonly --non-interactive --webroot -w /var/www/certbot --email ${CERT_EMAIL} -d request.hcos.io -d onedash.hcos.io -d hcos.io -d key.hcos.io -d gohcos.com --agree-tos --expand
    depends_on:
      - nginx
    networks:
      - local

networks:
  local:
    driver: bridge
EOF

# Create Nginx SSL Template
cat > nginx-ssl/templates/default.conf.template <<EOF
server {
    listen 80;
    server_name request.hcos.io onedash.hcos.io hcos.io key.hcos.io gohcos.com;
    location ~ /.well-known/acme-challenge {
        allow all;
        root /var/www/certbot;
    }
    location / {
        return 200 'SSL Setup - HCOS';
        add_header Content-Type text/plain;
    }
}
EOF

# Run SSL generation with PORT CHECK
echo -e "${YELLOW}Starting SSL certificate generation...${NC}"

# Final port 80 check
if check_port 80; then
    echo -e "${RED}Cannot proceed: Port 80 is still in use!${NC}"
    echo -e "${YELLOW}Checking what's using port 80:${NC}"
    lsof -i :80 || netstat -tulpn | grep :80 || ss -tulpn | grep :80
    exit 1
fi

echo -e "${GREEN}Port 80 is free. Starting temporary Nginx for SSL...${NC}"
docker compose -f docker-compose-ssl.yml up -d nginx

# Verify nginx container started
sleep 3
if ! docker ps | grep nginx-ssl-temp > /dev/null; then
    echo -e "${RED}Failed to start nginx-ssl-temp container${NC}"
    docker logs nginx-ssl-temp 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}Temporary Nginx container started successfully.${NC}"
echo -e "${YELLOW}Requesting certificates from Let's Encrypt...${NC}"

# Run certbot
docker compose -f docker-compose-ssl.yml up certbot

# Check if certs were generated
if [ ! -f "./certbot/conf/live/request.hcos.io/fullchain.pem" ]; then
    echo -e "${RED}Certificate generation failed. Please check:${NC}"
    echo -e "1. DNS records point to this server's IP"
    echo -e "2. Port 80 is accessible from internet"
    echo -e "3. Check logs above for specific errors"
    
    # Clean up temp containers
    docker compose -f docker-compose-ssl.yml down
    exit 1
fi

echo -e "${GREEN}Certificates generated successfully!${NC}"

# Stop SSL containers
echo -e "${YELLOW}Stopping temporary SSL containers...${NC}"
docker compose -f docker-compose-ssl.yml down

# Store cert path variables
CERT_PATH="$BASE_DIR/certbot/conf/live/request.hcos.io/fullchain.pem"
KEY_PATH="$BASE_DIR/certbot/conf/live/request.hcos.io/privkey.pem"

# Create symlinks for compatibility
echo -e "${YELLOW}Creating compatibility symlinks...${NC}"
mkdir -p /etc/letsencrypt/live/request.hcos.io
ln -sf "$CERT_PATH" /etc/letsencrypt/live/request.hcos.io/fullchain.pem
ln -sf "$KEY_PATH" /etc/letsencrypt/live/request.hcos.io/privkey.pem

# Save SSL paths for later use
cat > "$BASE_DIR/ssl_paths.env" <<EOF
# SSL Certificate Paths - HCOS Deployment
# Generated on $(date)
SSL_CERT_PATH="$CERT_PATH"
SSL_KEY_PATH="$KEY_PATH"
BASE_DIR="$BASE_DIR"
DOMAINS="${DOMAINS[*]}"
EOF

echo -e "${GREEN}SSL paths saved to $BASE_DIR/ssl_paths.env${NC}"

# 6. Create Main Production Stack
echo -e "${YELLOW}Creating main production stack...${NC}"
mkdir -p nginx-prod

# Create Main Nginx Config for Docker
cat > nginx-prod/default.conf <<EOF
upstream keycloak_upstream { server keycloak:8080; }
upstream django_upstream { server backend:5000; }

server {
    listen 3443 ssl;
    server_name onedash.hcos.io;
    ssl_certificate /etc/letsencrypt/live/request.hcos.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/request.hcos.io/privkey.pem;
    root /var/www/onedash;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
}

server {
    listen 3443 ssl;
    server_name hcos.io;
    ssl_certificate /etc/letsencrypt/live/request.hcos.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/request.hcos.io/privkey.pem;
    root /var/www/homepage;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
}

server {
    listen 3443 ssl;
    server_name gohcos.com;
    ssl_certificate /etc/letsencrypt/live/request.hcos.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/request.hcos.io/privkey.pem;
    root /var/www/demo;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
}

server {
    listen 3443 ssl;
    server_name request.hcos.io;
    ssl_certificate /etc/letsencrypt/live/request.hcos.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/request.hcos.io/privkey.pem;
    location / {
        proxy_pass https://django_upstream;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 3443 ssl;
    server_name key.hcos.io;
    ssl_certificate /etc/letsencrypt/live/request.hcos.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/request.hcos.io/privkey.pem;
    location / {
        proxy_pass http://keycloak_upstream;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# HTTP to HTTPS redirect
server {
    listen 81;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF

# Create main docker-compose.yml
cat > docker-compose.yml <<'EOF'
version: '3.8'

services:
  mariadb:
    image: mariadb:10.6
    environment:
      MYSQL_ROOT_PASSWORD: securerootpassword
      MYSQL_DATABASE: keycloak
      MYSQL_USER: keycloak
      MYSQL_PASSWORD: keycloakpassword
    volumes:
      - mariadb_data:/var/lib/mysql
    networks:
      - local

  postgres:
    image: postgres:18
    environment:
      POSTGRES_DB: hcos_db
      POSTGRES_USER: hcos_user
      POSTGRES_PASSWORD: hcos_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - local

  redis:
    image: redis:alpine
    networks:
      - local

  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    command: start-dev --import-realm
    environment:
      KC_DB: mariadb
      KC_DB_URL: jdbc:mariadb://mariadb/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloakpassword
      KC_HOSTNAME: key.hcos.io
      KC_PROXY: edge
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "4000:8080"
    depends_on:
      - mariadb
    networks:
      - local

  backend:
    build: 
      context: ./BACKEND-API
    command: sh -c "daphne -e ssl:port=5000:privateKey=/etc/letsencrypt/live/request.hcos.io/privkey.pem:certKey=/etc/letsencrypt/live/request.hcos.io/fullchain.pem hcos.asgi:application"
    volumes:
      - ./BACKEND-API:/app
      - ./certbot/conf:/etc/letsencrypt:ro
    environment:
      - DATABASE_URL=postgres://hcos_user:hcos_password@postgres:5432/hcos_db
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    extra_hosts:
      - "host.docker.internal:host-gateway"      
    networks:
      - local
    ports:
      - "5000:5000"      

  celery:
    build: 
      context: ./BACKEND-API
    command: celery -A hcos worker -l info
    volumes:
      - ./BACKEND-API:/app
    environment:
      - DATABASE_URL=postgres://hcos_user:hcos_password@postgres:5432/hcos_db
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - backend
      - redis
    networks:
      - local

  nginx_main:
    image: nginx:latest
    ports:
      - "81:81"
      - "3443:3443"
    volumes:
      - ./nginx-prod/default.conf:/etc/nginx/conf.d/default.conf
      - ./certbot/conf:/etc/letsencrypt:ro
      - ./ONEDASH.HCOS.IO-BUILD:/var/www/onedash
      - ./HOMEPAGE-BUILD:/var/www/homepage
      - ./DEMONSTRATION-HOMEPAGE-BUILD:/var/www/demo
    depends_on:
      - backend
      - keycloak
    networks:
      - local

networks:
  local:
    driver: bridge

volumes:
  mariadb_data:
  postgres_data:
EOF

echo -e "${YELLOW}Starting main Docker stack...${NC}"
docker compose up -d --build

# Wait for services to start
echo -e "${YELLOW}Waiting for services to initialize (30 seconds)...${NC}"
sleep 30

# 7. Configure Host Nginx (Now it's safe to start it)
echo -e "${YELLOW}Configuring host Nginx...${NC}"

# Create host Nginx config
cat > $HOST_NGINX_CONF <<EOF
# HCOS Proxy Configuration
# Generated on $(date)

server {
    listen 80;
    server_name hcos.io key.hcos.io onedash.hcos.io request.hcos.io gohcos.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name hcos.io key.hcos.io onedash.hcos.io request.hcos.io gohcos.com;

    # SSL certificates from Let's Encrypt
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    
    # SSL optimizations
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Proxy to Docker nginx_main container
    location / {
        proxy_pass https://127.0.0.1:3443;
        proxy_ssl_verify off;
        
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        # Timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF

# Enable the site
ln -sf $HOST_NGINX_CONF /etc/nginx/sites-enabled/

# Remove default nginx site if exists
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Test configuration
echo -e "${YELLOW}Testing Nginx configuration...${NC}"
if nginx -t; then
    echo -e "${GREEN}Nginx configuration test passed.${NC}"
    
    # Start and enable nginx
    systemctl start nginx
    systemctl enable nginx
    
    echo -e "${GREEN}Host Nginx started successfully.${NC}"
else
    echo -e "${RED}Nginx configuration test failed.${NC}"
    echo -e "${YELLOW}Manual intervention required.${NC}"
    exit 1
fi

# 8. Final Verification
echo -e "${YELLOW}Performing final verification...${NC}"

# Check Docker containers
echo -e "${GREEN}Checking Docker containers...${NC}"
docker ps

# Check Nginx status
echo -e "${GREEN}Checking Nginx status...${NC}"
systemctl status nginx --no-pager

# Check ports
echo -e "${GREEN}Checking listening ports...${NC}"
echo "Port 80 (Host Nginx):"
ss -tulpn | grep :80 || true
echo ""
echo "Port 443 (Host Nginx SSL):"
ss -tulpn | grep :443 || true
echo ""
echo "Port 81 (Docker Nginx HTTP):"
ss -tulpn | grep :81 || true
echo ""
echo "Port 3443 (Docker Nginx SSL):"
ss -tulpn | grep :3443 || true

# Test certificate access
echo -e "${GREEN}Verifying certificate access...${NC}"
if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo -e "${GREEN}✓ SSL certificates are accessible${NC}"
else
    echo -e "${RED}✗ SSL certificates are missing${NC}"
fi

# Create a verification script for later use
cat > "$BASE_DIR/verify_deployment.sh" <<'EOF'
#!/bin/bash
echo "=== HCOS Deployment Verification ==="
echo "Checking services at $(date)"
echo ""
echo "1. Docker containers:"
docker ps
echo ""
echo "2. Nginx status:"
systemctl status nginx --no-pager | grep -A 3 "Active:"
echo ""
echo "3. SSL certificates:"
ls -la /opt/hcos_stack/certbot/conf/live/request.hcos.io/
echo ""
echo "4. Listening ports:"
echo "Port 80:  $(ss -tulpn | grep :80 | wc -l) listeners"
echo "Port 443: $(ss -tulpn | grep :443 | wc -l) listeners"
echo "Port 81:  $(ss -tulpn | grep :81 | wc -l) listeners"
echo "Port 3443: $(ss -tulpn | grep :3443 | wc -l) listeners"
EOF

chmod +x "$BASE_DIR/verify_deployment.sh"

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}DEPLOYMENT COMPLETE!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "${YELLOW}Services are now running at:${NC}"
echo -e "  • https://hcos.io (Homepage)"
echo -e "  • https://onedash.hcos.io (OneDash)"
echo -e "  • https://request.hcos.io (Backend API)"
echo -e "  • https://key.hcos.io (Keycloak)"
echo -e "  • https://gohcos.com (Demo)"
echo ""
echo -e "${YELLOW}Important files:${NC}"
echo -e "  • SSL Certificates: $CERT_PATH"
echo -e "  • SSL Keys: $KEY_PATH"
echo -e "  • Configuration: $BASE_DIR/ssl_paths.env"
echo -e "  • Verification: $BASE_DIR/verify_deployment.sh"
echo ""
echo -e "${YELLOW}Management commands:${NC}"
echo -e "  • View logs: cd $BASE_DIR && docker compose logs -f"
echo -e "  • Restart: cd $BASE_DIR && docker compose restart"
echo -e "  • Stop: cd $BASE_DIR && docker compose down"
echo -e "  • Start: cd $BASE_DIR && docker compose up -d"
echo ""
echo -e "${YELLOW}Host Nginx management:${NC}"
echo -e "  • Restart: systemctl restart nginx"
echo -e "  • Status: systemctl status nginx"
echo -e "  • Logs: journalctl -u nginx -f"
echo ""
echo -e "${GREEN}Deployment completed successfully!${NC}"
