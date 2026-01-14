#!/bin/bash

# ==========================================
# HCOS Deployment Script - Final Version
# ==========================================

# Exit immediately if a command exits with a non-zero status
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to get user input for frontend domains
get_frontend_domains() {
    local -n frontend_domains_ref=$1
    local -n container_map_ref=$2
    
    echo -e "${YELLOW}=== Frontend Domains Setup ===${NC}"
    echo -e "${YELLOW}Enter frontend domains one at a time.${NC}"
    echo -e "${YELLOW}For each domain, specify which Vue3 container will serve it.${NC}"
    echo -e "${YELLOW}Available Vue3 containers: onedash, homepage, demo${NC}"
    echo -e "${YELLOW}Type 'done' when all frontend domains are entered.${NC}"
    echo ""
    
    while true; do
        read -p "Enter domain (or 'done' to finish): " domain
        if [[ "$domain" == "done" ]]; then
            break
        fi
        
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        echo -e "${YELLOW}Which Vue3 container should serve $domain?${NC}"
        echo "Options: onedash, homepage, demo"
        read -p "Container name: " container
        
        # Validate container choice
        if [[ "$container" != "onedash" && "$container" != "homepage" && "$container" != "demo" ]]; then
            echo -e "${RED}Invalid container. Please choose: onedash, homepage, or demo${NC}"
            continue
        fi
        
        frontend_domains_ref+=("$domain")
        container_map_ref["$domain"]="$container"
        echo -e "${GREEN}Added: $domain -> $container${NC}"
        echo ""
    done
}

# Function to get user input for backend domains and subdomains
get_backend_domains_and_subdomains() {
    local -n backend_domains_ref=$1
    local -n backend_subdomains_map_ref=$2
    
    echo -e "${YELLOW}=== Backend Domains Setup ===${NC}"
    echo -e "${YELLOW}Step 1: Enter backend ROOT domains only (no subdomains).${NC}"
    echo -e "${YELLOW}Wildcard SSL will be issued for each root domain (*.example.com).${NC}"
    echo -e "${YELLOW}Enter all backend domains separated by spaces.${NC}"
    echo -e "${YELLOW}Example: backend1.com backend2.org${NC}"
    echo ""
    
    read -p "Enter backend root domains (space-separated): " backend_input
    
    # Split by spaces into array
    IFS=' ' read -ra backend_domains_ref <<< "$backend_input"
    
    echo -e "${GREEN}Backend root domains to process:${NC}"
    for domain in "${backend_domains_ref[@]}"; do
        echo "  - $domain (will get *.${domain} wildcard)"
    done
    echo ""
    
    # Now get subdomains for each root domain
    echo -e "${YELLOW}=== Backend Subdomains Setup ===${NC}"
    echo -e "${YELLOW}Step 2: Enter subdomains for each root domain.${NC}"
    echo -e "${YELLOW}These subdomains will proxy to the backend container.${NC}"
    echo -e "${YELLOW}Type 'done' when finished with a domain, or 'skip' to skip.${NC}"
    echo -e "${YELLOW}Note: Wildcard SSL (*.domain.com) already covers all subdomains.${NC}"
    echo ""
    
    for root_domain in "${backend_domains_ref[@]}"; do
        echo -e "${YELLOW}Entering subdomains for: $root_domain${NC}"
        echo -e "${YELLOW}Enter one subdomain per line (without the root domain).${NC}"
        echo -e "${YELLOW}Example: For 'api.example.com', just enter 'api'${NC}"
        echo ""
        
        local subdomains=()
        while true; do
            read -p "Subdomain (or 'done' to finish, 'skip' to skip): " subdomain
            
            if [[ "$subdomain" == "done" ]]; then
                break
            fi
            
            if [[ "$subdomain" == "skip" ]]; then
                echo -e "${YELLOW}Skipping subdomains for $root_domain${NC}"
                subdomains=()
                break
            fi
            
            if [[ -z "$subdomain" ]]; then
                continue
            fi
            
            # Validate subdomain format
            if [[ "$subdomain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$ ]]; then
                subdomains+=("$subdomain")
                echo -e "${GREEN}Added: $subdomain.$root_domain${NC}"
            else
                echo -e "${RED}Invalid subdomain format. Use letters, numbers, and hyphens only.${NC}"
            fi
        done
        
        if [ ${#subdomains[@]} -gt 0 ]; then
            backend_subdomains_map_ref["$root_domain"]="${subdomains[*]}"
            echo -e "${GREEN}Subdomains for $root_domain: ${subdomains[*]}${NC}"
        fi
        echo ""
    done
}

# Function to get Let's Encrypt email
get_letsencrypt_email() {
    echo -e "${YELLOW}=== Let's Encrypt Email ===${NC}"
    echo -e "${YELLOW}This email will be used for SSL certificate notifications and recovery.${NC}"
    echo ""
    
    while true; do
        read -p "Let's Encrypt email address: " CERT_EMAIL
        
        if [[ -z "$CERT_EMAIL" ]]; then
            echo -e "${RED}Email cannot be empty.${NC}"
            continue
        fi
        
        # Basic email validation
        if [[ "$CERT_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo -e "${RED}Please enter a valid email address.${NC}"
        fi
    done
    echo ""
}

# Function to get GitHub credentials
get_github_credentials() {
    echo -e "${YELLOW}=== GitHub Credentials ===${NC}"
    echo -e "${YELLOW}GitHub expects a Token as password when cloning repositories.${NC}"
    echo -e "${YELLOW}You can use an email address as username (e.g., user@example.com).${NC}"
    echo ""
    
    read -p "GitHub Username/Email: " GITHUB_USER
    read -sp "GitHub Token: " GITHUB_TOKEN
    echo ""
    echo ""
}

# Function to get Cloudflare token
get_cloudflare_token() {
    echo -e "${YELLOW}=== Cloudflare Credentials ===${NC}"
    echo -e "${YELLOW}This will be used to create A records and SSL certificates.${NC}"
    echo ""
    
    while true; do
        read -sp "Cloudflare API Token: " CLOUDFLARE_API_TOKEN
        echo ""
        
        if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
            echo -e "${RED}Cloudflare API Token cannot be empty.${NC}"
        else
            break
        fi
    done
    echo ""
}

# Function to get server public IP
get_public_ip() {
    echo -e "${YELLOW}=== Server Public IP ===${NC}"
    
    # Try to get public IP automatically
    local auto_ip=""
    if command -v curl &> /dev/null; then
        auto_ip=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || curl -s -4 ipinfo.io/ip || echo "")
    fi
    
    if [[ -n "$auto_ip" && "$auto_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${GREEN}Detected public IP: $auto_ip${NC}"
        read -p "Use this IP? (y/n): " use_auto
        if [[ "$use_auto" == "y" || "$use_auto" == "Y" ]]; then
            PUBLIC_IP="$auto_ip"
            return
        fi
    fi
    
    # Manual input
    while true; do
        read -p "Enter server public IP: " PUBLIC_IP
        
        # Validate IP format
        if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            echo -e "${RED}Invalid IP format. Please enter a valid IPv4 address.${NC}"
        fi
    done
}

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

# Function to get Cloudflare zone ID
get_cloudflare_zone_id() {
    local domain=$1
    
    echo -e "${YELLOW}Getting Cloudflare zone ID for $domain...${NC}"
    
    # Extract root domain (remove subdomains)
    local root_domain="$domain"
    if [[ "$domain" == *"."*"."* ]]; then
        root_domain=$(echo "$domain" | rev | cut -d. -f1,2 | rev)
    fi
    
    local zone_info=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    local zone_id=$(echo "$zone_info" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [[ -n "$zone_id" ]]; then
        echo -e "${GREEN}Zone ID for $root_domain: $zone_id${NC}"
        CLOUDFLARE_ZONE_ID="$zone_id"
        return 0
    else
        echo -e "${RED}Failed to get zone ID for $root_domain${NC}"
        echo -e "${YELLOW}Please ensure the domain is added to your Cloudflare account.${NC}"
        return 1
    fi
}

# Function to create Cloudflare DNS records for root domains and subdomains
create_cloudflare_dns_records() {
    local domain=$1
    
    echo -e "${YELLOW}Creating DNS records for $domain...${NC}"
    
    # Create A record for root domain
    if curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":true}" > /dev/null; then
        echo -e "${GREEN}✓ A record created for $domain${NC}"
    else
        echo -e "${RED}✗ Failed to create A record for $domain${NC}"
    fi
    
    # Create CNAME record for www subdomain
    if curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"CNAME\",\"name\":\"www.$domain\",\"content\":\"$domain\",\"ttl\":120,\"proxied\":true}" > /dev/null; then
        echo -e "${GREEN}✓ CNAME record created for www.$domain${NC}"
    else
        echo -e "${RED}✗ Failed to create CNAME record for www.$domain${NC}"
    fi
    
    # Create records for specific subdomains if any
    if [[ -v BACKEND_SUBDOMAINS_MAP["$domain"] ]]; then
        IFS=' ' read -ra subdomains <<< "${BACKEND_SUBDOMAINS_MAP[$domain]}"
        for subdomain in "${subdomains[@]}"; do
            if curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
                -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"$subdomain.$domain\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":true}" > /dev/null; then
                echo -e "${GREEN}✓ A record created for $subdomain.$domain${NC}"
            else
                echo -e "${RED}✗ Failed to create A record for $subdomain.$domain${NC}"
            fi
        done
    fi
}

# Function to generate SSL certificates - ONLY root domains with wildcards
generate_ssl_certificates() {
    echo -e "${YELLOW}=== Generating SSL Certificates ===${NC}"
    
    # Create Cloudflare credentials file
    echo -e "${YELLOW}Creating Cloudflare credentials file...${NC}"
    mkdir -p /opt
    cat > /opt/cf_creds.ini <<EOF
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN
EOF
    chmod 400 /opt/cf_creds.ini
    echo -e "${GREEN}✓ Cloudflare credentials file created${NC}"
    
    # Initialize certificate path arrays
    declare -gA BACKEND_CERT_PATHS=()
    declare -gA BACKEND_KEY_PATHS=()
    declare -gA FRONTEND_CERT_PATHS=()
    declare -gA FRONTEND_KEY_PATHS=()
    
    # Process backend domains for SSL - ONLY root domains with wildcards
    echo -e "${YELLOW}Generating SSL certificates for backend domains...${NC}"
    echo -e "${YELLOW}Note: Only requesting wildcard certificates for root domains (*.domain.com)${NC}"
    echo -e "${YELLOW}Specific subdomains will be covered by the wildcard certificate.${NC}"
    
    # Generate certificates for each backend root domain
    for root_domain in "${BACKEND_DOMAINS[@]}"; do
        echo -e "${GREEN}Processing SSL for: $root_domain${NC}"
        echo -e "${YELLOW}Requesting wildcard certificate for: $root_domain and *.$root_domain${NC}"
        
        echo -e "${YELLOW}Running certbot for $root_domain...${NC}"
        
        # ONLY request root domain and wildcard - NO specific subdomains
        if certbot certonly \
            --non-interactive \
            --agree-tos \
            --email "${CERT_EMAIL}" \
            --dns-cloudflare \
            --dns-cloudflare-credentials /opt/cf_creds.ini \
            --dns-cloudflare-propagation-seconds 60 \
            -d "$root_domain" \
            -d "*.$root_domain"; then
            
            echo -e "${GREEN}✅ SSL certificate generated for $root_domain and *.$root_domain${NC}"
            
            # Store certificate path for this domain
            BACKEND_CERT_PATHS["$root_domain"]="/etc/letsencrypt/live/$root_domain/fullchain.pem"
            BACKEND_KEY_PATHS["$root_domain"]="/etc/letsencrypt/live/$root_domain/privkey.pem"
            
            # Verify the paths exist
            if [[ -f "${BACKEND_CERT_PATHS[$root_domain]}" && -f "${BACKEND_KEY_PATHS[$root_domain]}" ]]; then
                echo -e "${GREEN}✓ Certificate files verified:${NC}"
                echo -e "  Cert: ${BACKEND_CERT_PATHS[$root_domain]}"
                echo -e "  Key:  ${BACKEND_KEY_PATHS[$root_domain]}"
            else
                echo -e "${YELLOW}⚠️  Warning: Certificate files not found at expected location${NC}"
                
                # Try to find the actual certificate location
                local cert_base="/etc/letsencrypt/live"
                local found_cert=$(find "$cert_base" -name "fullchain.pem" -type f 2>/dev/null | grep -i "$root_domain" | head -1)
                local found_key=$(find "$cert_base" -name "privkey.pem" -type f 2>/dev/null | grep -i "$root_domain" | head -1)
                
                if [[ -n "$found_cert" && -n "$found_key" ]]; then
                    BACKEND_CERT_PATHS["$root_domain"]="$found_cert"
                    BACKEND_KEY_PATHS["$root_domain"]="$found_key"
                    echo -e "${GREEN}✓ Found certificate files at:${NC}"
                    echo -e "  Cert: $found_cert"
                    echo -e "  Key:  $found_key"
                else
                    echo -e "${RED}✗ Could not find certificate files for $root_domain${NC}"
                fi
            fi
            
        else
            echo -e "${RED}⚠️ SSL certificate generation failed for $root_domain${NC}"
            echo -e "${YELLOW}Will try to continue with other domains...${NC}"
            
            # Check if certificate already exists from previous run
            local existing_cert="/etc/letsencrypt/live/$root_domain/fullchain.pem"
            local existing_key="/etc/letsencrypt/live/$root_domain/privkey.pem"
            
            if [[ -f "$existing_cert" && -f "$existing_key" ]]; then
                echo -e "${YELLOW}Using existing certificate for $root_domain${NC}"
                BACKEND_CERT_PATHS["$root_domain"]="$existing_cert"
                BACKEND_KEY_PATHS["$root_domain"]="$existing_key"
            else
                echo -e "${RED}No certificate available for $root_domain${NC}"
            fi
        fi
        
        echo ""
    done
    
    # Process frontend domains for SSL
    echo -e "${YELLOW}Processing frontend domains for SSL...${NC}"
    for domain in "${FRONTEND_DOMAINS[@]}"; do
        echo -e "${GREEN}Processing frontend domain: $domain${NC}"
        
        # Check if this frontend domain matches any backend domain
        local found_backend_domain=""
        for root_domain in "${BACKEND_DOMAINS[@]}"; do
            if [[ "$domain" == *"$root_domain" ]]; then
                found_backend_domain="$root_domain"
                break
            fi
        done
        
        if [[ -n "$found_backend_domain" ]]; then
            # Frontend domain is a subdomain of a backend domain
            echo -e "${GREEN}✓ $domain is a subdomain of $found_backend_domain${NC}"
            
            if [[ -v BACKEND_CERT_PATHS["$found_backend_domain"] ]]; then
                FRONTEND_CERT_PATHS["$domain"]="${BACKEND_CERT_PATHS[$found_backend_domain]}"
                FRONTEND_KEY_PATHS["$domain"]="${BACKEND_KEY_PATHS[$found_backend_domain]}"
                echo -e "${GREEN}✓ Will use wildcard certificate from $found_backend_domain${NC}"
                echo -e "  Cert: ${BACKEND_CERT_PATHS[$found_backend_domain]}"
                echo -e "  Key:  ${BACKEND_KEY_PATHS[$found_backend_domain]}"
            else
                echo -e "${RED}✗ No certificate found for backend domain $found_backend_domain${NC}"
            fi
        else
            # Frontend domain is completely separate (not a subdomain of any backend domain)
            echo -e "${YELLOW}⚠️  $domain is not a subdomain of any backend domain${NC}"
            echo -e "${YELLOW}Generating separate certificate for $domain${NC}"
            
            if certbot certonly \
                --non-interactive \
                --agree-tos \
                --email "${CERT_EMAIL}" \
                --dns-cloudflare \
                --dns-cloudflare-credentials /opt/cf_creds.ini \
                --dns-cloudflare-propagation-seconds 60 \
                -d "$domain"; then
                
                echo -e "${GREEN}✅ SSL certificate generated for $domain${NC}"
                FRONTEND_CERT_PATHS["$domain"]="/etc/letsencrypt/live/$domain/fullchain.pem"
                FRONTEND_KEY_PATHS["$domain"]="/etc/letsencrypt/live/$domain/privkey.pem"
                
                # Verify the paths exist
                if [[ -f "${FRONTEND_CERT_PATHS[$domain]}" && -f "${FRONTEND_KEY_PATHS[$domain]}" ]]; then
                    echo -e "${GREEN}✓ Certificate files verified:${NC}"
                    echo -e "  Cert: ${FRONTEND_CERT_PATHS[$domain]}"
                    echo -e "  Key:  ${FRONTEND_KEY_PATHS[$domain]}"
                fi
            else
                echo -e "${RED}⚠️ SSL certificate generation failed for $domain${NC}"
                
                # Check if certificate already exists
                local existing_cert="/etc/letsencrypt/live/$domain/fullchain.pem"
                local existing_key="/etc/letsencrypt/live/$domain/privkey.pem"
                
                if [[ -f "$existing_cert" && -f "$existing_key" ]]; then
                    echo -e "${YELLOW}Using existing certificate for $domain${NC}"
                    FRONTEND_CERT_PATHS["$domain"]="$existing_cert"
                    FRONTEND_KEY_PATHS["$domain"]="$existing_key"
                fi
            fi
        fi
        
        echo ""
    done
    
    # Set primary certificate path (use first backend domain)
    if [ ${#BACKEND_DOMAINS[@]} -gt 0 ]; then
        PRIMARY_DOMAIN="${BACKEND_DOMAINS[0]}"
        if [[ -v BACKEND_CERT_PATHS["$PRIMARY_DOMAIN"] ]]; then
            CERT_PATH="${BACKEND_CERT_PATHS[$PRIMARY_DOMAIN]}"
            KEY_PATH="${BACKEND_KEY_PATHS[$PRIMARY_DOMAIN]}"
            
            echo -e "${GREEN}Primary certificate (for Docker containers):${NC}"
            echo -e "  Cert: $CERT_PATH"
            echo -e "  Key:  $KEY_PATH"
            
            # Save certificate paths to a file for reference
            save_certificate_paths
            
            return 0
        else
            echo -e "${RED}No certificate found for primary domain $PRIMARY_DOMAIN${NC}"
            return 1
        fi
    else
        echo -e "${RED}No backend domains configured for SSL${NC}"
        return 1
    fi
}

# Function to save certificate paths to a file
save_certificate_paths() {
    local certs_file="$BASE_DIR/certificate_paths.env"
    
    echo -e "${YELLOW}Saving certificate paths to $certs_file...${NC}"
    
    cat > "$certs_file" <<EOF
# Certificate Paths - Generated on $(date)
# Let's Encrypt Email: $CERT_EMAIL

# Backend Domains Certificates (Wildcard: *.domain.com)
EOF
    
    for domain in "${!BACKEND_CERT_PATHS[@]}"; do
        cat >> "$certs_file" <<EOF
BACKEND_CERT_${domain//./_}=${BACKEND_CERT_PATHS[$domain]}
BACKEND_KEY_${domain//./_}=${BACKEND_KEY_PATHS[$domain]}
EOF
    done
    
    cat >> "$certs_file" <<EOF

# Frontend Domains Certificates
EOF
    
    for domain in "${!FRONTEND_CERT_PATHS[@]}"; do
        cat >> "$certs_file" <<EOF
FRONTEND_CERT_${domain//./_}=${FRONTEND_CERT_PATHS[$domain]}
FRONTEND_KEY_${domain//./_}=${FRONTEND_KEY_PATHS[$domain]}
EOF
    done
    
    cat >> "$certs_file" <<EOF

# Primary Certificate (for Docker containers)
PRIMARY_CERT=$CERT_PATH
PRIMARY_KEY=$KEY_PATH
EOF
    
    chmod 600 "$certs_file"
    echo -e "${GREEN}✓ Certificate paths saved to $certs_file${NC}"
}

# Function to display certificate summary
display_certificate_summary() {
    echo -e "${GREEN}=== Certificate Summary ===${NC}"
    echo -e "${YELLOW}Let's Encrypt Email: $CERT_EMAIL${NC}"
    echo ""
    
    echo -e "${YELLOW}Backend Domains (Wildcard Certificates):${NC}"
    for domain in "${BACKEND_DOMAINS[@]}"; do
        if [[ -v BACKEND_CERT_PATHS["$domain"] ]]; then
            echo -e "  ✓ $domain (covers *.${domain})"
            echo -e "    Cert: ${BACKEND_CERT_PATHS[$domain]}"
            echo -e "    Key:  ${BACKEND_KEY_PATHS[$domain]}"
            # Show subdomains covered by this wildcard
            if [[ -v BACKEND_SUBDOMAINS_MAP["$domain"] ]]; then
                IFS=' ' read -ra subdomains <<< "${BACKEND_SUBDOMAINS_MAP[$domain]}"
                echo -e "    Covers subdomains: ${subdomains[*]}"
            fi
        else
            echo -e "  ✗ $domain - NO CERTIFICATE"
        fi
        echo ""
    done
    
    echo -e "${YELLOW}Frontend Domains:${NC}"
    for domain in "${FRONTEND_DOMAINS[@]}"; do
        if [[ -v FRONTEND_CERT_PATHS["$domain"] ]]; then
            echo -e "  ✓ $domain"
            echo -e "    Cert: ${FRONTEND_CERT_PATHS[$domain]}"
            echo -e "    Key:  ${FRONTEND_KEY_PATHS[$domain]}"
            
            # Check if using backend wildcard certificate
            for root_domain in "${BACKEND_DOMAINS[@]}"; do
                if [[ "$domain" == *"$root_domain" && -v BACKEND_CERT_PATHS["$root_domain"] ]]; then
                    if [[ "${FRONTEND_CERT_PATHS[$domain]}" == "${BACKEND_CERT_PATHS[$root_domain]}" ]]; then
                        echo -e "    (Uses wildcard certificate from $root_domain)"
                    fi
                fi
            done
        else
            echo -e "  ✗ $domain - NO CERTIFICATE"
        fi
        echo ""
    done
    
    echo -e "${YELLOW}Primary Certificate (for Docker):${NC}"
    echo -e "  Cert: $CERT_PATH"
    echo -e "  Key:  $KEY_PATH"
    echo ""
}

# Function to generate Nginx configuration with certificate paths
generate_nginx_config() {
    echo -e "${YELLOW}Creating Nginx configuration...${NC}"
    mkdir -p nginx-prod

    # Generate Nginx upstream blocks for backend domains
    UPSTREAM_BLOCKS=""

    for domain in "${BACKEND_DOMAINS[@]}"; do
    UPSTREAM_NAME=$(echo "$domain" | tr '.-' '_' )_backend
    UPSTREAM_BLOCKS+=$(printf "upstream %s { server backend:5000; }\n\n" "$UPSTREAM_NAME")
    done

    # Generate Nginx server blocks
    SERVER_BLOCKS=""
    
    # First, create explicit server blocks for specific backend subdomains
    for root_domain in "${BACKEND_DOMAINS[@]}"; do
        UPSTREAM_NAME=$(echo "$root_domain" | tr '.' '_' | tr '-' '_')_backend
        
        # Get certificate paths for this domain
        if [[ -v BACKEND_CERT_PATHS["$root_domain"] ]]; then
            local cert_path="${BACKEND_CERT_PATHS[$root_domain]}"
            local key_path="${BACKEND_KEY_PATHS[$root_domain]}"
            
            echo -e "${GREEN}Configuring Nginx for $root_domain${NC}"
            
            # Check if there are specific subdomains for this root domain
            if [[ -v BACKEND_SUBDOMAINS_MAP["$root_domain"] ]]; then
                IFS=' ' read -ra subdomains <<< "${BACKEND_SUBDOMAINS_MAP[$root_domain]}"
                for subdomain in "${subdomains[@]}"; do
                    SERVER_BLOCKS+="
# === Backend subdomain: ${subdomain}.${root_domain} ===
server {
    listen 3443 ssl;
    server_name ${subdomain}.${root_domain};
    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    
    location / {
        proxy_pass https://${UPSTREAM_NAME};
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
    
    location /ws/ {
        proxy_pass https://${UPSTREAM_NAME};
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
    }
}
"
                done
            fi
            
            # Remove root domain server block for backend domains
            # Backend domains should only be accessed via subdomains
            # Don't create server blocks for root domains as backend endpoints
            
        else
            echo -e "${RED}Warning: No certificate found for $root_domain${NC}"
            echo -e "${YELLOW}Skipping Nginx configuration for $root_domain${NC}"
        fi
    done

    # Frontend domains
    for domain in "${FRONTEND_DOMAINS[@]}"; do
        CONTAINER="${CONTAINER_MAP[$domain]}"
        case $CONTAINER in
            "onedash")
                ROOT="/var/www/onedash"
                ;;
            "homepage")
                ROOT="/var/www/homepage"
                ;;
            "demo")
                ROOT="/var/www/demo"
                ;;
            *)
                ROOT="/var/www/default"
                ;;
        esac
        
        # Get certificate for this domain
        if [[ -v FRONTEND_CERT_PATHS["$domain"] ]]; then
            local cert_path="${FRONTEND_CERT_PATHS[$domain]}"
            local key_path="${FRONTEND_KEY_PATHS[$domain]}"
            
            echo -e "${GREEN}Configuring Nginx for frontend $domain${NC}"
            
            # Find which backend upstream to use for this domain
            local backend_upstream=""
            local matched_backend_domain=""
            
            # Check if this frontend domain is a subdomain of any backend domain
            for root_domain in "${BACKEND_DOMAINS[@]}"; do
                # Check if domain ends with .root_domain or equals root_domain
                if [[ "$domain" == *".$root_domain" || "$domain" == "$root_domain" ]]; then
                    matched_backend_domain="$root_domain"
                    backend_upstream=$(echo "$root_domain" | tr '.' '_' | tr '-' '_')_backend
                    break
                fi
            done
            
            # If no match found, use first backend domain
            if [[ -z "$backend_upstream" && ${#BACKEND_DOMAINS[@]} -gt 0 ]]; then
                local first_domain="${BACKEND_DOMAINS[0]}"
                backend_upstream=$(echo "$first_domain" | tr '.' '_' | tr '-' '_')_backend
            fi
            
            SERVER_BLOCKS+="
# === Frontend: $domain ===
server {
    listen 3443 ssl;
    server_name $domain;
    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    root $ROOT;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
"
            
            # Add API proxy if backend upstream exists
            if [[ -n "$backend_upstream" ]]; then
                SERVER_BLOCKS+="
    # API proxy to backend
    location /api/ {
        proxy_pass https://${backend_upstream};
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
"
            fi
            
            SERVER_BLOCKS+="}
"
        else
            echo -e "${RED}Warning: No certificate found for frontend $domain${NC}"
            echo -e "${YELLOW}Skipping Nginx configuration for $domain${NC}"
        fi
    done

    # Create Nginx config file
    cat > nginx-prod/default.conf <<EOF
$UPSTREAM_BLOCKS

$SERVER_BLOCKS

# HTTP to HTTPS redirect
server {
    listen 81;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF
    
    echo -e "${GREEN}✓ Nginx configuration created${NC}"
}

# Function to generate host Nginx configuration
generate_host_nginx_config() {
    echo -e "${YELLOW}Configuring host Nginx...${NC}"

    # Generate host Nginx server blocks
    HOST_SERVER_BLOCKS=""
    
    # Build server names list
    SERVER_NAMES=""
    
    # Backend subdomains
    for root_domain in "${BACKEND_DOMAINS[@]}"; do
        if [[ -v BACKEND_CERT_PATHS["$root_domain"] ]]; then
            local cert_path="${BACKEND_CERT_PATHS[$root_domain]}"
            local key_path="${BACKEND_KEY_PATHS[$root_domain]}"
            
            # Add specific subdomains to server names
            if [[ -v BACKEND_SUBDOMAINS_MAP["$root_domain"] ]]; then
                IFS=' ' read -ra subdomains <<< "${BACKEND_SUBDOMAINS_MAP[$root_domain]}"
                for subdomain in "${subdomains[@]}"; do
                    SERVER_NAMES+="${subdomain}.${root_domain} "
                    
                    HOST_SERVER_BLOCKS+="
# === Backend subdomain: ${subdomain}.${root_domain} ===
server {
    listen 443 ssl http2;
    server_name ${subdomain}.${root_domain};

    # SSL certificates from Let's Encrypt
    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    
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
        proxy_set_header Connection \"upgrade\";
    }
    
    # Security headers
    add_header X-Frame-Options \"SAMEORIGIN\" always;
    add_header X-Content-Type-Options \"nosniff\" always;
    add_header X-XSS-Protection \"1; mode=block\" always;
}
"
                done
            fi
        fi
    done
    
    # Frontend domains
    for domain in "${FRONTEND_DOMAINS[@]}"; do
        SERVER_NAMES+="$domain "
        
        if [[ -v FRONTEND_CERT_PATHS["$domain"] ]]; then
            local cert_path="${FRONTEND_CERT_PATHS[$domain]}"
            local key_path="${FRONTEND_KEY_PATHS[$domain]}"
            
            HOST_SERVER_BLOCKS+="
# === Frontend: $domain ===
server {
    listen 443 ssl http2;
    server_name $domain;

    # SSL certificates from Let's Encrypt
    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    
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
    }
    
    # Security headers
    add_header X-Frame-Options \"SAMEORIGIN\" always;
    add_header X-Content-Type-Options \"nosniff\" always;
    add_header X-XSS-Protection \"1; mode=block\" always;
}
"
        fi
    done

    cat > $HOST_NGINX_CONF <<EOF
# HCOS Proxy Configuration
# Generated on $(date)

# HTTP to HTTPS redirect for all domains
server {
    listen 80;
    server_name $SERVER_NAMES;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

$HOST_SERVER_BLOCKS
EOF
    
    echo -e "${GREEN}✓ Host Nginx configuration created${NC}"
}

# Function to clone repositories
clone_repositories() {
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

    # Clone repositories (adjust these URLs as needed)
    clone_repo "https://github.com/gohcosutilities/BACKEND-API" "BACKEND-API"
    clone_repo "https://github.com/gohcosutilities/ONEDASH.HCOS.IO-BUILD" "ONEDASH.HCOS.IO-BUILD"
    clone_repo "https://github.com/gohcosutilities/HOMEPAGE-BUILD" "HOMEPAGE-BUILD"
    clone_repo "https://github.com/gohcosutilities/DEMONSTRATION-HOMEPAGE-BUILD" "DEMONSTRATION-HOMEPAGE-BUILD"
}

# Function to create docker-compose.yml
create_docker_compose() {
    echo -e "${YELLOW}Creating docker-compose.yml...${NC}"
    
    cat > docker-compose.yml <<EOF
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
    image: postgres:14-alpine
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
      KC_HOSTNAME: key.${BACKEND_DOMAINS[0]:-example.com}
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
    command: sh -c "daphne -e ssl:port=5000:privateKey=$KEY_PATH:certKey=$CERT_PATH hcos.asgi:application"
    volumes:
      - ./BACKEND-API:/app
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ./nginx-prod:/etc/nginx-prod
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DATABASE_URL=postgres://hcos_user:hcos_password@postgres:5432/hcos_db
      - CELERY_BROKER_URL=redis://redis:6379/0
      - NGINX_CONFIG_PATH=/etc/nginx-prod/default.conf
      - NGINX_CONTAINER_NAME=nginx_main
    depends_on:
      - postgres
      - redis
    networks:
      - local
    extra_hosts:
      - "host.docker.internal:host-gateway"      
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
    container_name: nginx_main
    ports:
      - "81:81"
      - "3443:3443"
    volumes:
      - ./nginx-prod:/etc/nginx/conf.d
      - /etc/letsencrypt:/etc/letsencrypt:ro
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
    
    echo -e "${GREEN}✓ docker-compose.yml created${NC}"
}

# Function to run Django management commands
run_django_commands() {
    echo -e "${YELLOW}Running Django management commands...${NC}"
    sleep 30  # Wait for services to start

    docker compose exec -T backend python manage.py migrate --noinput || echo -e "${RED}Migration failed${NC}"
    docker compose exec -T backend python manage.py create_base_products || echo -e "${RED}Failed to create base products${NC}"
    docker compose exec -T backend python manage.py add_default_canada_tax || echo -e "${RED}Failed to add Canada tax data${NC}"
    docker compose exec -T backend python manage.py populate_us_tax_data || echo -e "${RED}Failed to populate US tax data${NC}"
    docker compose exec -T backend python manage.py populate_comprehensive_tax_data || echo -e "${RED}Failed to populate comprehensive tax data${NC}"
    
    echo -e "${GREEN}✓ Django management commands completed${NC}"
}

# Main execution
echo -e "${GREEN}Starting HCOS Deployment Setup...${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Global variables
BASE_DIR="/opt/hcos_stack"
declare -a FRONTEND_DOMAINS=()
declare -A CONTAINER_MAP=()
declare -a BACKEND_DOMAINS=()
declare -A BACKEND_SUBDOMAINS_MAP=()
declare -gA BACKEND_CERT_PATHS=()
declare -gA BACKEND_KEY_PATHS=()
declare -gA FRONTEND_CERT_PATHS=()
declare -gA FRONTEND_KEY_PATHS=()
HOST_NGINX_CONF="/etc/nginx/sites-available/hcos_proxy"

# Get user inputs
get_frontend_domains FRONTEND_DOMAINS CONTAINER_MAP
get_backend_domains_and_subdomains BACKEND_DOMAINS BACKEND_SUBDOMAINS_MAP
get_letsencrypt_email
get_github_credentials
get_cloudflare_token
get_public_ip

# Display summary
echo -e "${GREEN}=== Deployment Summary ===${NC}"
echo -e "Frontend domains: ${FRONTEND_DOMAINS[*]}"
echo -e "Container mapping:"
for domain in "${!CONTAINER_MAP[@]}"; do
    echo "  $domain -> ${CONTAINER_MAP[$domain]}"
done
echo -e "Backend root domains: ${BACKEND_DOMAINS[*]}"
echo -e "Backend subdomains:"
for root_domain in "${!BACKEND_SUBDOMAINS_MAP[@]}"; do
    echo "  $root_domain: ${BACKEND_SUBDOMAINS_MAP[$root_domain]}"
done
echo -e "Let's Encrypt Email: $CERT_EMAIL"
echo -e "Public IP: $PUBLIC_IP"
echo ""

read -p "Proceed with deployment? (y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi

# Initial setup
echo -e "${YELLOW}Initial setup...${NC}"
mkdir -p $BASE_DIR
cd $BASE_DIR

# Free ports 80 and 443
echo -e "${YELLOW}Checking and freeing ports 80 and 443...${NC}"
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
kill_port 80 "" || true
kill_port 443 "" || true

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt-get update -qq
apt-get install -y -qq certbot python3-certbot-dns-cloudflare
apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release git net-tools lsof nginx

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}Installing Docker Compose...${NC}"
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Get Cloudflare zone ID (using first backend domain)
if [ ${#BACKEND_DOMAINS[@]} -gt 0 ]; then
    get_cloudflare_zone_id "${BACKEND_DOMAINS[0]}"
else
    echo -e "${YELLOW}No backend domains, skipping Cloudflare zone ID check${NC}"
fi

# Generate SSL certificates
if generate_ssl_certificates; then
    display_certificate_summary
    
    # Ask user to confirm before proceeding
    echo -e "${YELLOW}Please verify the certificate paths above.${NC}"
    read -p "Proceed with DNS and Nginx configuration? (y/n): " confirm_ssl
    if [[ "$confirm_ssl" != "y" && "$confirm_ssl" != "Y" ]]; then
        echo -e "${YELLOW}SSL generation complete. Exiting for manual verification.${NC}"
        echo -e "${YELLOW}Certificate paths saved to: $BASE_DIR/certificate_paths.env${NC}"
        exit 0
    fi
else
    echo -e "${RED}SSL certificate generation failed.${NC}"
    echo -e "${YELLOW}Please check the errors above and try again.${NC}"
    exit 1
fi

# Create Cloudflare DNS records
echo -e "${YELLOW}=== Creating Cloudflare DNS Records ===${NC}"
for domain in "${BACKEND_DOMAINS[@]}"; do
    create_cloudflare_dns_records "$domain"
done

for domain in "${FRONTEND_DOMAINS[@]}"; do
    create_cloudflare_dns_records "$domain"
done

# Clone repositories
clone_repositories

# Stop any existing Docker containers
echo -e "${YELLOW}Stopping any existing Docker containers...${NC}"
docker compose -f docker-compose.yml down 2>/dev/null || true

# Generate Nginx configurations
generate_nginx_config
generate_host_nginx_config

# Create docker-compose.yml
create_docker_compose

# Start Docker stack
echo -e "${YELLOW}Starting Docker stack...${NC}"
docker compose up -d --build

# Configure host Nginx
echo -e "${YELLOW}Configuring host Nginx...${NC}"
ln -sf $HOST_NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Test and start host Nginx
if nginx -t; then
    echo -e "${GREEN}Nginx configuration test passed.${NC}"
    systemctl start nginx
    systemctl enable nginx
    echo -e "${GREEN}Host Nginx started successfully.${NC}"
else
    echo -e "${RED}Nginx configuration test failed.${NC}"
    exit 1
fi

# Run Django commands
run_django_commands

# Final output
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}DEPLOYMENT COMPLETE!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "${YELLOW}Services deployed:${NC}"
for domain in "${FRONTEND_DOMAINS[@]}"; do
    echo -e "  • https://$domain (Frontend - ${CONTAINER_MAP[$domain]})"
done
for domain in "${BACKEND_DOMAINS[@]}"; do
    if [[ -v BACKEND_SUBDOMAINS_MAP["$domain"] ]]; then
        IFS=' ' read -ra subdomains <<< "${BACKEND_SUBDOMAINS_MAP[$domain]}"
        for subdomain in "${subdomains[@]}"; do
            echo -e "  • https://$subdomain.$domain (Backend API)"
        done
    fi
done
echo ""
echo -e "${YELLOW}SSL Information:${NC}"
echo -e "  • Let's Encrypt Email: $CERT_EMAIL"
echo -e "  • Wildcard certificates issued for: ${BACKEND_DOMAINS[*]}"
echo -e "  • Certificate paths: $BASE_DIR/certificate_paths.env"
echo ""
echo -e "${YELLOW}Server Information:${NC}"
echo -e "  • Server IP: $PUBLIC_IP"
echo -e "  • Base directory: $BASE_DIR"
echo ""
echo -e "${YELLOW}Management commands:${NC}"
echo -e "  • View logs: cd $BASE_DIR && docker compose logs -f"
echo -e "  • Restart: cd $BASE_DIR && docker compose restart"
echo -e "  • Stop: cd $BASE_DIR && docker compose down"
echo -e "  • Start: cd $BASE_DIR && docker compose up -d"
echo ""
echo -e "${GREEN}Deployment completed successfully!${NC}"
