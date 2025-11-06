#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script constants
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REQUIRED_SERVICES=("oscmcpservice" "oscgoose" "oscgooseservice" "oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
REQUIRED_SERVICES=("oscmcpservice" "oscgoose" "oscgooseservice" "oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
CERT_PATHS=("src/oscreverseproxy/certs" "${HOME}/continube/certs")
GOOSE_SESSION_DIR="${SCRIPT_DIR}/goose-sessions/sessions"

# Docker command with sudo
DOCKER_CMD="sudo docker"
USE_SUDO=true


# Source environment variables
if [ -f "${SCRIPT_DIR}/etc/userconfig.env" ]; then
    set -a  # automatically export all variables
    source "${SCRIPT_DIR}/etc/userconfig.env"
    set +a  # disable auto-export
    echo -e "${GREEN}[INFO]${NC} Environment variables loaded from etc/userconfig.env"
else
    echo -e "${YELLOW}[WARNING]${NC} etc/userconfig.env not found, continuing without it"
fi

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║         PolicyCow MCP + No-Code UI Setup Script           ║"
    echo "║                   (WITH SUDO SUPPORT)                     ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running with sufficient privileges
check_privileges() {
    log_info "Checking Docker access..."
    
    # First try without sudo
    if docker ps &> /dev/null; then
        log_success "Docker accessible without sudo"
        DOCKER_CMD="docker"
        USE_SUDO=false
    elif sudo docker ps &> /dev/null; then
        log_success "Docker accessible with sudo"
        DOCKER_CMD="sudo docker"
        USE_SUDO=true
        log_info "Running Docker commands with sudo"
    else
        log_error "Cannot access Docker even with sudo"
        exit 1
    fi
}

# Validate Docker installation
check_docker() {
    log_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed!"
        echo ""
        echo "Please install Docker first:"
        echo "  - Linux: https://docs.docker.com/engine/install/"
        echo "  - Mac: https://docs.docker.com/desktop/install/mac-install/"
        echo "  - Windows: https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    fi
    
    if ! $DOCKER_CMD ps &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permission to access it."
        echo ""
        echo "Please ensure:"
        echo "  1. Docker daemon is running: sudo systemctl start docker"
        echo "  2. Or add your user to docker group: sudo usermod -aG docker \$USER"
        echo "  3. Log out and back in for group changes to take effect"
        exit 1
    fi
    
    log_success "Docker is installed and running"
    $DOCKER_CMD --version
}

# Validate Docker Compose
check_docker_compose() {
    log_info "Checking Docker Compose installation..."
    
    if $DOCKER_CMD compose version &> /dev/null; then
        log_success "Docker Compose (plugin) is available"
        $DOCKER_CMD compose version
        if [ "$USE_SUDO" = true ]; then
            COMPOSE_CMD="sudo docker compose"
        else
            COMPOSE_CMD="docker compose"
        fi
    elif command -v docker-compose &> /dev/null; then
        log_success "Docker Compose (standalone) is available"
        docker-compose --version
        COMPOSE_CMD="docker-compose"
    else
        log_error "Docker Compose is not installed!"
        echo ""
        echo "Please install Docker Compose:"
        echo "  https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check available memory
    if command -v free &> /dev/null; then
        TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
        if [ "$TOTAL_MEM" -lt 8 ]; then
            log_warning "System has less than 8GB RAM. MCP setup requires 8GB+ for optimal performance"
            echo ""
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_error "Setup cancelled. Please upgrade system resources."
                exit 1
            fi
        else
            log_success "System has ${TOTAL_MEM}GB RAM"
        fi
    fi
    
    # Check available disk space
    AVAILABLE_SPACE=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE_SPACE" -lt 30 ]; then
        log_warning "Less than 30GB free disk space available. Recommended: 30GB+ for MCP setup"
    else
        log_success "Sufficient disk space available (${AVAILABLE_SPACE}GB)"
    fi
    
    log_warning "MCP setup requires a beefy machine or remote hosting:"
    echo "  - Recommended: 8GB+ RAM, 4+ CPU cores, 30GB+ disk"
    echo "  - 6+ services will be running simultaneously"
}

# Validate Anthropic API key
check_anthropic_key() {
    log_info "Checking Anthropic API key..."
    
    # Check if key is already in environment
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        # Check in userconfig.env
        if [ -f "etc/userconfig.env" ] && grep -q "ANTHROPIC_API_KEY" etc/userconfig.env; then
            source etc/userconfig.env
        fi
    fi
    
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        log_warning "Anthropic API key not found in environment"
        echo ""
        echo "MCP setup requires an Anthropic API key for Goose integration."
        echo "Get your API key from: https://console.anthropic.com/"
        echo ""
        read -p "Enter your Anthropic API key: " -r ANTHROPIC_API_KEY
        echo ""
        
        if [ -z "$ANTHROPIC_API_KEY" ]; then
            log_error "Anthropic API key is required for MCP setup"
            exit 1
        fi
    fi
    
    # Validate the API key format
    if [[ ! "$ANTHROPIC_API_KEY" =~ ^sk-ant-[a-zA-Z0-9_-]+$ ]]; then
        log_warning "API key format looks unusual. Expected format: sk-ant-..."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please verify your API key."
            exit 1
        fi
    fi
    
    # Test the API key by making a simple request
    log_info "Validating Anthropic API key..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "x-api-key: $ANTHROPIC_API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        https://api.anthropic.com/v1/models)
    
    if [ "$HTTP_CODE" == "400" ] || [ "$HTTP_CODE" == "200" ]; then
        log_success "Anthropic API key is valid"
    else
        log_error "Anthropic API key validation failed (HTTP $HTTP_CODE)"
        echo ""
        echo "Common issues:"
        echo "  - Invalid or expired API key"
        echo "  - Network connectivity issues"
        echo "  - API rate limits"
        echo ""
        read -p "Continue with setup anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please verify your API key and network connection."
            exit 1
        fi
    fi
    
    # Save to environment file if not already there
    if [ -f "etc/userconfig.env" ] && ! grep -q "ANTHROPIC_API_KEY" etc/userconfig.env; then
        echo "" >> etc/userconfig.env
        echo "# Anthropic API Key for MCP/Goose integration" >> etc/userconfig.env
        echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" >> etc/userconfig.env
        log_success "API key saved to etc/userconfig.env"
    fi
    
    export ANTHROPIC_API_KEY
}

# Validate SSL certificates
check_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    CERT_FOUND=false
    CERT_LOCATION=""
    
    for cert_path in "${CERT_PATHS[@]}"; do
        if [ -f "$cert_path/fullchain.pem" ] && [ -f "$cert_path/privkey.pem" ]; then
            CERT_FOUND=true
            CERT_LOCATION="$cert_path"
            break
        fi
    done
    
    if [ "$CERT_FOUND" = true ]; then
        log_success "SSL certificates found at: $CERT_LOCATION"
        
        # Validate certificate expiration
        if command -v openssl &> /dev/null; then
            EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_LOCATION/fullchain.pem" | cut -d= -f2)
            log_info "Certificate expires on: $EXPIRY_DATE"
        fi
    else
        log_warning "SSL certificates not found!"
        echo ""
        echo "Please place your SSL certificates in one of these locations:"
        echo "  1. ${SCRIPT_DIR}/src/oscreverseproxy/certs/"
        echo "  2. ${HOME}/continube/certs/"
        echo ""
        echo "Required files:"
        echo "  - fullchain.pem"
        echo "  - privkey.pem"
        echo ""
        read -p "Do you want to continue without SSL certificates? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please add SSL certificates and try again."
            exit 1
        fi
    fi
}

# Validate environment files
check_env_files() {
    log_info "Checking environment configuration files..."
    
    REQUIRED_ENV_FILES=("etc/userconfig.env" "etc/policycow.env")
    MISSING_FILES=()
    
    for env_file in "${REQUIRED_ENV_FILES[@]}"; do
        if [ ! -f "$env_file" ]; then
            MISSING_FILES+=("$env_file")
        fi
    done
    
    if [ ${#MISSING_FILES[@]} -gt 0 ]; then
        log_error "Missing environment files:"
        for file in "${MISSING_FILES[@]}"; do
            echo "  - $file"
        done
        exit 1
    fi
    
    log_success "All required environment files found"
    
    # Run export_env.sh if it exists
    if [ -f "export_env.sh" ]; then
        log_info "Running export_env.sh..."
        if bash export_env.sh; then
            log_success "Environment variables exported successfully"
        else
            log_warning "export_env.sh execution had warnings, continuing..."
        fi
    else
        log_warning "export_env.sh not found, skipping environment export"
    fi
}

# Clean up dangling containers and images
cleanup_docker() {
    log_info "Cleaning up dangling Docker resources..."
    
    # Stop existing containers for these services
    for service in "${REQUIRED_SERVICES[@]}"; do
        if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -q "^${service}$"; then
            log_info "Stopping existing container: $service"
            $DOCKER_CMD stop "$service" 2>/dev/null || true
            $DOCKER_CMD rm "$service" 2>/dev/null || true
        fi
    done
    
    # Remove dangling images
    DANGLING_IMAGES=$($DOCKER_CMD images -f "dangling=true" -q)
    if [ -n "$DANGLING_IMAGES" ]; then
        log_info "Removing dangling images..."
        $DOCKER_CMD rmi $DANGLING_IMAGES 2>/dev/null || true
    fi
    
    # Clean up unused networks (except policycow networks)
    log_info "Pruning unused networks..."
    $DOCKER_CMD network prune -f 2>/dev/null || true
    
    log_success "Docker cleanup completed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "${HOME}/tmp/cowctl/minio"
    mkdir -p exported-data
    mkdir -p catalog/localcatalog
    mkdir -p goose-config
    mkdir -p "$GOOSE_SESSION_DIR"
    
    log_success "Directories created"
    log_info "Goose sessions will persist in: $GOOSE_SESSION_DIR"
}

# Build and start services
build_services() {
    log_info "Building Docker images (this may take several minutes)..."
    
    if $COMPOSE_CMD -f docker-compose.yaml build oscwebserver oscreverseproxy oscapiservice cowstorage oscgoose oscgooseservice oscmcpservice; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
}

start_services() {
    log_info "Starting all MCP services..."
    
    # Start storage first
    if $COMPOSE_CMD -f docker-compose.yaml up -d cowstorage; then
        log_success "Storage service started"
        sleep 5
    else
        log_error "Failed to start storage service"
        exit 1
    fi
    
    # Start MCP service first (before oscgoose)
    log_info "Starting MCP service..."
    if $COMPOSE_CMD -f docker-compose.yaml up -d oscmcpservice; then
        log_success "MCP service started"
    else
        log_error "Failed to start MCP service"
        exit 1
    fi
    
    # Wait for MCP service to settle
    log_info "Waiting 20 seconds for MCP service to settle..."
    for i in {20..1}; do
        echo -ne "\rTime remaining: ${i} seconds "
        sleep 1
    done
    echo -e "\r${GREEN}✓${NC} MCP service settled"
    
    # Now start remaining services including oscgoose
    log_info "Starting remaining services..."
    if $COMPOSE_CMD -f docker-compose.yaml up -d oscapiservice oscwebserver oscreverseproxy oscgoose oscgooseservice; then
        log_success "All services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Wait for services to be healthy
wait_for_services() {
    log_info "Waiting for services to be ready (this may take a minute)..."
    
    local max_attempts=60
    local attempt=0
    local services_ready=0
    
    while [ $attempt -lt $max_attempts ] && [ $services_ready -lt 3 ]; do
        services_ready=0
        
        if $DOCKER_CMD ps --filter "name=oscapiservice" --filter "status=running" | grep -q oscapiservice; then
            ((services_ready++))
        fi
        
        if $DOCKER_CMD ps --filter "name=oscgoose" --filter "status=running" | grep -q oscgoose; then
            ((services_ready++))
        fi

        if $DOCKER_CMD ps --filter "name=oscgooseservice" --filter "status=running" | grep -q oscgooseservice; then
            ((services_ready++))
        fi
        
        if $DOCKER_CMD ps --filter "name=oscmcpservice" --filter "status=running" | grep -q oscmcpservice; then
            ((services_ready++))
        fi
        
        if [ $services_ready -ge 3 ]; then
            log_success "Core services are running"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    log_warning "Some services may still be starting up. Check status with: $DOCKER_CMD ps"
}

# Display service status
show_service_status() {
    echo ""
    log_info "Service Status:"
    echo ""
    $DOCKER_CMD ps --filter "name=cow" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
}

# Display MCP-specific information
show_mcp_info() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║            MCP Setup Completed Successfully!              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Access URLs:"
    echo "  - Web UI: https://localhost:443"
    echo "  - Web UI (HTTP): http://localhost:8080"
    echo "  - API Service: http://localhost:9080"
    echo "  - MinIO Console: http://localhost:9001"
    echo "  - Goose Web: http://localhost:8976"
    echo "  - MCP Service: http://localhost:45678"
    echo ""
    log_info "MCP Configuration:"
    echo "  - Provider: Anthropic only"
    echo "  - Goose Sessions: $GOOSE_SESSION_DIR"
    echo "  - API Key: Configured (from environment)"
    echo ""
    log_info "Useful Commands:"
    echo "  - View all logs: $COMPOSE_CMD logs -f"
    echo "  - View Goose logs: $COMPOSE_CMD logs -f oscgoose"
    echo "  - View Goose Service logs: $COMPOSE_CMD logs -f oscgooseservice"
    echo "  - View MCP logs: $COMPOSE_CMD logs -f oscmcpservice"
    echo "  - Stop services: $COMPOSE_CMD down"
    echo "  - Restart services: $COMPOSE_CMD restart"
    echo "  - Check status: $DOCKER_CMD ps"
    echo ""
    log_warning "Important Notes:"
    echo "  ⚠️  Only Anthropic provider is supported"
    echo "  ⚠️  Requires ANTHROPIC_API_KEY environment variable"
    echo "  ⚠️  Goose sessions persist across restarts"
    echo "  ⚠️  This setup does NOT support multi-tenancy"
    echo "  ⚠️  Not tested at scale - for development/testing only"
    echo "  ⚠️  Ensure you have a beefy machine (8GB+ RAM, 4+ cores)"
    echo ""
}

# Main execution
main() {
    print_banner
    
    log_info "Starting PolicyCow MCP + No-Code UI Setup..."
    echo ""
    
    # Pre-flight checks
    check_docker
    check_privileges
    check_docker_compose
    check_system_requirements
    check_anthropic_key
    check_ssl_certificates
    check_env_files
    
    echo ""
    log_info "All pre-flight checks passed!"
    echo ""
    
    # Display summary
    echo -e "${CYAN}Setup Summary:${NC}"
    echo "  Services to be deployed: 6"
    echo "    1. Web UI (oscwebserver)"
    echo "    2. Reverse Proxy (oscreverseproxy)"
    echo "    3. API Service (oscapiservice)"
    echo "    4. Storage Service (cowstorage/MinIO)"
    echo "    5. Goose Integration (oscgoose)"
    echo "    6. Goose Service (oscgooseservice)"
    echo "    7. MCP Service (oscmcpservice)"
    echo ""
    
    # Confirm before proceeding
    read -p "Proceed with MCP setup? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Setup cancelled by user"
        exit 0
    fi
    
    # Setup process
    cleanup_docker
    create_directories
    build_services
    start_services
    wait_for_services
    
    # Show results
    show_service_status
    show_mcp_info
    
    log_success "MCP setup completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "  1. Access the Web UI at https://localhost:443"
    echo "  2. Configure your Goose integration at http://localhost:8976"
    echo "  3. Test MCP service at http://localhost:45678"
}

# Trap errors
trap 'log_error "Setup failed at line $LINENO. Check the error messages above."' ERR

# Run main function
main "$@"