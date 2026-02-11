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
REQUIRED_SERVICES=("oscmcpservice" "ccowmcpclient" "ccowmcpbridge" "oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
NO_CODE_UI_SERVICES=("oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
CERT_PATHS=("src/oscreverseproxy/certs" "${HOME}/continube/certs")
MCP_SESSION_DIR="${SCRIPT_DIR}/mcp-sessions/sessions"

# Setup mode: "full" (MCP + No-Code UI) or "nocode" (No-Code UI only)
SETUP_MODE="full"

# Docker command with sudo
DOCKER_CMD="sudo docker"
USE_SUDO=true

# Global variables for detected model
DETECTED_MODEL=""
DETECTED_MODEL_NAME=""


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
    echo "║   Open Security Compliance MCP + No-Code UI Setup         ║"
    echo "║                   (WITH SUDO SUPPORT)                     ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Prompt user to select setup mode
select_setup_mode() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Choose your setup mode${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} MCP + No-Code UI  ${YELLOW}(Requires a valid Anthropic API key)${NC}"
    echo "     Enables AI-powered rule creation via MCP along with the"
    echo "     No-Code web interface."
    echo "     Services: oscmcpservice, ccowmcpclient, ccowmcpbridge,"
    echo "               oscwebserver, oscreverseproxy, oscapiservice, cowstorage"
    echo ""
    echo -e "  ${GREEN}2)${NC} No-Code UI Only   ${YELLOW}(No Anthropic API key needed)${NC}"
    echo "     Enables only the No-Code web interface for manual rule"
    echo "     creation and management. No AI/MCP features."
    echo "     Services: oscapiservice, oscreverseproxy, oscwebserver, cowstorage"
    echo ""

    while true; do
        read -p "Select setup mode [1/2]: " -r mode_choice
        case "$mode_choice" in
            1)
                SETUP_MODE="full"
                log_info "Selected: MCP + No-Code UI (full setup)"
                echo ""
                log_warning "You will need a valid Anthropic API key to proceed."
                echo "  Get your API key from: https://console.anthropic.com/"
                echo ""
                break
                ;;
            2)
                SETUP_MODE="nocode"
                log_info "Selected: No-Code UI Only"
                echo ""
                break
                ;;
            *)
                log_error "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Helper function to update env variable in-place
update_env_variable() {
    local env_file=$1
    local var_name=$2
    local var_value=$3
    local comment=$4
    
    if [ ! -f "$env_file" ]; then
        mkdir -p "$(dirname "$env_file")"
        touch "$env_file"
    fi
    
    # Check if variable exists
    if grep -q "^${var_name}=" "$env_file"; then
        # Update existing variable in-place
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
        else
            # Linux
            sed -i "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
        fi
    else
        # Add new variable with comment if it doesn't exist
        if [ -n "$comment" ]; then
            # Check if comment already exists
            if ! grep -q "^${comment}" "$env_file"; then
                echo "" >> "$env_file"
                echo "$comment" >> "$env_file"
            fi
        fi
        echo "${var_name}=${var_value}" >> "$env_file"
    fi
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
        if [ "$TOTAL_MEM" -lt 16 ]; then
            log_warning "System has less than 16GB RAM. Open Security Compliance setup requires 16GB+ for optimal performance"
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
    
    # Check available disk space (cross-platform)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        AVAILABLE_SPACE=$(df -g "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    else
        # Linux
        AVAILABLE_SPACE=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    fi
    
    if [ -n "$AVAILABLE_SPACE" ] && [ "$AVAILABLE_SPACE" -lt 30 ]; then
        log_warning "Less than 30GB free disk space available. Recommended: 30GB+ for Open Security Compliance setup"
    elif [ -n "$AVAILABLE_SPACE" ]; then
        log_success "Sufficient disk space available (${AVAILABLE_SPACE}GB)"
    else
        log_warning "Could not determine available disk space"
    fi
    
    log_warning "Open Security Compliance setup requires a beefy machine or remote hosting:"
    echo "  - Recommended: 16GB+ RAM, 8+ CPU cores, 30GB+ disk"
    echo "  - 7 services will be running simultaneously"
}

# Validate Anthropic API key
check_anthropic_key() {
    log_info "Checking Anthropic API key..."
    
    ENV_FILE="${SCRIPT_DIR}/etc/userconfig.env"
    
    # Check if key is already in environment
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        # Check in userconfig.env
        if [ -f "$ENV_FILE" ] && grep -q "^ANTHROPIC_API_KEY=" "$ENV_FILE"; then
            source "$ENV_FILE"
        fi
    fi
    
    # Function to remove invalid key from env file
    remove_api_key_from_env() {
        if [ -f "$ENV_FILE" ]; then
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS
                sed -i '' '/# Anthropic API Key for MCP integration/d' "$ENV_FILE"
                sed -i '' '/^ANTHROPIC_API_KEY=/d' "$ENV_FILE"
                sed -i '' '/# Detected Claude Model/d' "$ENV_FILE"
                sed -i '' '/^MCP_MODEL=/d' "$ENV_FILE"
            else
                # Linux
                sed -i '/# Anthropic API Key for MCP integration/d' "$ENV_FILE"
                sed -i '/^ANTHROPIC_API_KEY=/d' "$ENV_FILE"
                sed -i '/# Detected Claude Model/d' "$ENV_FILE"
                sed -i '/^MCP_MODEL=/d' "$ENV_FILE"
            fi
            log_info "Removed invalid API key from etc/userconfig.env"
        fi
        unset ANTHROPIC_API_KEY
        unset MCP_MODEL
    }
    
    # Function to validate API key and detect best available Claude model
    validate_api_key() {
        local api_key=$1
        
        # Validate the API key format
        if [[ ! "$api_key" =~ ^sk-ant-[a-zA-Z0-9_-]+$ ]]; then
            log_error "Invalid API key format. Expected format: sk-ant-..."
            return 1
        fi
        
        # Test the API key by making a simple request
        log_info "Validating Anthropic API key..."
        local temp_file=$(mktemp)
        local http_code=$(curl -s -w "%{http_code}" -o "$temp_file" \
            -H "x-api-key: $api_key" \
            -H "anthropic-version: 2023-06-01" \
            -H "content-type: application/json" \
            https://api.anthropic.com/v1/models)
        
        local http_body=$(cat "$temp_file")
        rm -f "$temp_file"
        
        if [ "$http_code" != "200" ]; then
            log_error "Anthropic API key validation failed (HTTP $http_code)"
            if [ "$http_code" == "401" ]; then
                echo "  - API key is invalid or expired"
            elif [ "$http_code" == "403" ]; then
                echo "  - API key does not have required permissions"
            elif [ "$http_code" == "429" ]; then
                echo "  - API rate limit exceeded, please try again later"
            else
                echo "  - Network connectivity issues or API error"
            fi
            return 1
        fi
        
        log_success "Anthropic API key is valid"
        
        # Array of models to check in order of preference (best to minimum required)
        local models=(
            "claude-sonnet-4-5-20250929:Claude Sonnet 4.5"
            "claude-sonnet-4-20250514:Claude Sonnet 4"
        )
        
        DETECTED_MODEL=""
        DETECTED_MODEL_NAME=""
        
        log_info "Detecting best available Claude model..."
        
        for model_entry in "${models[@]}"; do
            local model_id="${model_entry%%:*}"
            local model_name="${model_entry##*:}"
            
            log_info "Testing access to $model_name ($model_id)..."
            local test_temp_file=$(mktemp)
            local test_code=$(curl -s -w "%{http_code}" -o "$test_temp_file" \
                -X POST \
                -H "x-api-key: $api_key" \
                -H "anthropic-version: 2023-06-01" \
                -H "content-type: application/json" \
                -d "{
                    \"model\": \"$model_id\",
                    \"max_tokens\": 10,
                    \"messages\": [{\"role\": \"user\", \"content\": \"Hi\"}]
                }" \
                https://api.anthropic.com/v1/messages)
            
            rm -f "$test_temp_file"
            
            if [ "$test_code" == "200" ]; then
                log_success "$model_name access confirmed"
                DETECTED_MODEL="$model_id"
                DETECTED_MODEL_NAME="$model_name"
                break
            elif [ "$test_code" == "404" ] || [ "$test_code" == "403" ]; then
                log_warning "$model_name not accessible with this API key"
            else
                log_warning "Could not verify $model_name access (HTTP $test_code)"
            fi
        done
        
        # Check if we found at least the minimum required model
        if [ -z "$DETECTED_MODEL" ]; then
            log_error "No compatible Claude model found"
            echo "  - This platform requires at least Claude Sonnet 4 (claude-sonnet-4-20250514)"
            echo "  - Your API key does not have access to any supported models"
            return 1
        fi
        
        log_success "Best available model: $DETECTED_MODEL_NAME ($DETECTED_MODEL)"
        return 0
    }
    
    # Main validation loop
    while true; do
        if [ -z "$ANTHROPIC_API_KEY" ]; then
            log_warning "Anthropic API key not found in environment"
            echo ""
            echo "Open Security Compliance MCP integration requires an Anthropic API key."
            echo "Get your API key from: https://console.anthropic.com/"
            echo ""
            read -p "Enter your Anthropic API key: " -r ANTHROPIC_API_KEY
            echo ""
            
            if [ -z "$ANTHROPIC_API_KEY" ]; then
                log_error "Anthropic API key is required for MCP setup"
                exit 1
            fi
        fi
        
        # Validate the key
        if validate_api_key "$ANTHROPIC_API_KEY"; then
            # Valid key - save it
            if [ ! -f "$ENV_FILE" ]; then
                log_info "Creating etc/userconfig.env file..."
                mkdir -p "$(dirname "$ENV_FILE")"
                touch "$ENV_FILE"
            fi

            # Update API key in-place
            update_env_variable "$ENV_FILE" "ANTHROPIC_API_KEY" "$ANTHROPIC_API_KEY" "# Anthropic API Key for MCP integration"
            
            # Update MCP_MODEL in-place with detected model
            update_env_variable "$ENV_FILE" "MCP_MODEL" "$DETECTED_MODEL" "# Detected Claude Model"
            
            log_success "API key saved to etc/userconfig.env"
            log_success "MCP_MODEL set to: $DETECTED_MODEL_NAME"
            
            export ANTHROPIC_API_KEY
            export MCP_MODEL="$DETECTED_MODEL"
            break
        else
            # Invalid key - remove from env and ask again
            remove_api_key_from_env
            log_error "API key validation failed"
            echo ""
            read -p "Would you like to try another API key? (Y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                log_error "Setup cancelled. Valid Anthropic API key with Claude Sonnet 4+ access is required."
                exit 1
            fi
            # Clear the key to prompt for a new one
            ANTHROPIC_API_KEY=""
        fi
    done
}

# Validate MinIO credentials
check_minio_credentials() {
    log_info "Checking MinIO credentials..."
    
    ENV_FILE="${SCRIPT_DIR}/etc/policycow.env"
    
    # Load environment variables if file exists
    if [ -f "$ENV_FILE" ]; then
        set -a
        source "$ENV_FILE"
        set +a
    fi
    
    # Check if credentials are set
    MINIO_USER_MISSING=false
    MINIO_PASS_MISSING=false
    
    if [ -z "$MINIO_ROOT_USER" ]; then
        MINIO_USER_MISSING=true
    fi
    
    if [ -z "$MINIO_ROOT_PASSWORD" ]; then
        MINIO_PASS_MISSING=true
    fi
    
    # Validation loop
    while true; do
        # Prompt for username if missing
        if [ "$MINIO_USER_MISSING" = true ] || [ -z "$MINIO_ROOT_USER" ]; then
            log_warning "MinIO root username not found in environment"
            echo ""
            echo "MinIO requires a root username for authentication."
            echo "Requirements: Minimum 3 characters"
            echo ""
            read -p "Enter MinIO root username: " -r MINIO_ROOT_USER
            echo ""
        fi
        
        # Validate username
        if [ ${#MINIO_ROOT_USER} -lt 3 ]; then
            log_error "MinIO username must be at least 3 characters long"
            MINIO_ROOT_USER=""
            continue
        fi
        
        # Check for invalid characters in username (spaces, special chars that could cause issues)
        if [[ "$MINIO_ROOT_USER" =~ [[:space:]] ]]; then
            log_error "MinIO username cannot contain spaces"
            MINIO_ROOT_USER=""
            continue
        fi
        
        # Prompt for password if missing
        if [ "$MINIO_PASS_MISSING" = true ] || [ -z "$MINIO_ROOT_PASSWORD" ]; then
            log_warning "MinIO root password not found in environment"
            echo ""
            echo "MinIO requires a root password for authentication."
            echo "Requirements: Minimum 8 characters"
            echo ""
            read -s -p "Enter MinIO root password: " MINIO_ROOT_PASSWORD
            echo ""
            read -s -p "Confirm MinIO root password: " MINIO_ROOT_PASSWORD_CONFIRM
            echo ""
            echo ""
            
            if [ "$MINIO_ROOT_PASSWORD" != "$MINIO_ROOT_PASSWORD_CONFIRM" ]; then
                log_error "Passwords do not match"
                MINIO_ROOT_PASSWORD=""
                MINIO_ROOT_PASSWORD_CONFIRM=""
                continue
            fi
        fi
        
        # Validate password length
        if [ ${#MINIO_ROOT_PASSWORD} -lt 8 ]; then
            log_error "MinIO password must be at least 8 characters long"
            MINIO_ROOT_PASSWORD=""
            MINIO_ROOT_PASSWORD_CONFIRM=""
            MINIO_PASS_MISSING=true
            continue
        fi
        
        # Check for spaces in password
        if [[ "$MINIO_ROOT_PASSWORD" =~ [[:space:]] ]]; then
            log_error "MinIO password cannot contain spaces"
            MINIO_ROOT_PASSWORD=""
            MINIO_ROOT_PASSWORD_CONFIRM=""
            MINIO_PASS_MISSING=true
            continue
        fi
        
        # All validations passed
        log_success "MinIO credentials validated successfully"
        log_info "Username: $MINIO_ROOT_USER (${#MINIO_ROOT_USER} characters)"
        log_info "Password: ******** (${#MINIO_ROOT_PASSWORD} characters)"
        
        # Save credentials to env file
        if [ ! -f "$ENV_FILE" ]; then
            log_info "Creating etc/policycow.env file..."
            mkdir -p "$(dirname "$ENV_FILE")"
            touch "$ENV_FILE"
        fi
        
        # Update credentials in-place
        update_env_variable "$ENV_FILE" "MINIO_ROOT_USER" "$MINIO_ROOT_USER" "# MinIO Root Credentials"
        update_env_variable "$ENV_FILE" "MINIO_ROOT_PASSWORD" "$MINIO_ROOT_PASSWORD" ""
        
        log_success "MinIO credentials saved to etc/policycow.env"
        
        # Export for current session
        export MINIO_ROOT_USER
        export MINIO_ROOT_PASSWORD
        
        break
    done
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
    
    # Clean up unused networks (except Open Security Compliance networks)
    log_info "Pruning unused networks..."
    $DOCKER_CMD network prune -f 2>/dev/null || true
    
    log_success "Docker cleanup completed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "${HOME}/tmp/cowctl/minio" && chown -R "$(id -un)":"$(id -gn)" "${HOME}/tmp/cowctl/minio"
    mkdir -p exported-data && chown -R "$(id -un)":"$(id -gn)" exported-data
    mkdir -p catalog/localcatalog && chown -R "$(id -un)":"$(id -gn)" catalog/localcatalog
    mkdir -p mcp-config && chown -R "$(id -un)":"$(id -gn)" mcp-config
    mkdir -p "$MCP_SESSION_DIR" && chown -R "$(id -un)":"$(id -gn)" "$MCP_SESSION_DIR"
    
    log_success "Directories created"
    log_info "MCP sessions will persist in: $MCP_SESSION_DIR"
}

# Build and start services
build_services() {
    log_info "Building Docker images (this may take several minutes)..."
    
    if $COMPOSE_CMD -f docker-compose-osc.yaml build oscwebserver oscreverseproxy oscapiservice cowstorage ccowmcpclient ccowmcpbridge oscmcpservice; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
}

# Health check function for MCP service
wait_for_mcp_health() {
    local max_attempts=60
    local attempt=0
    local mcp_port=45678
    local mcp_health_endpoint="http://localhost:${mcp_port}/health"
    
    log_info "Waiting for MCP service to be ready..."
    log_info "Health check endpoint: ${mcp_health_endpoint}"
    
    while [ $attempt -lt $max_attempts ]; do
        # Check if container is running first
        if ! $DOCKER_CMD ps --filter "name=oscmcpservice" --filter "status=running" | grep -q oscmcpservice; then
            log_warning "MCP service container not running yet (attempt $((attempt + 1))/$max_attempts)"
            attempt=$((attempt + 1))
            sleep 2
            continue
        fi
        
        # Try to hit the health endpoint
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "${mcp_health_endpoint}" 2>/dev/null || echo "000")
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
            if [ "$http_code" = "200" ]; then
                log_success "MCP service is healthy and responding (HTTP 200)"
            else
                log_success "MCP service is up and responding (HTTP 404 - server is running)"
            fi
            return 0
        elif [ "$http_code" = "000" ]; then
            echo -ne "\r${BLUE}[INFO]${NC} Waiting for MCP service... (attempt $((attempt + 1))/$max_attempts) - Connection refused"
        else
            echo -ne "\r${BLUE}[INFO]${NC} Waiting for MCP service... (attempt $((attempt + 1))/$max_attempts) - HTTP $http_code"
        fi
        
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo ""
    log_error "MCP service health check timed out after $((max_attempts * 2)) seconds"
    log_info "Checking MCP service logs..."
    $COMPOSE_CMD -f docker-compose-osc.yaml logs --tail=20 oscmcpservice
    return 1
}

start_services() {
    log_info "Starting all services..."
    
    # Start storage first
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d cowstorage; then
        log_success "Storage service started"
        sleep 5
    else
        log_error "Failed to start storage service"
        exit 1
    fi
    
    # Start MCP service first (before ccowmcpclient)
    log_info "Starting MCP service..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscmcpservice; then
        log_success "MCP service container started"
    else
        log_error "Failed to start MCP service"
        exit 1
    fi
    
    # Wait for MCP service to be healthy
    if ! wait_for_mcp_health; then
        log_error "MCP service failed to become healthy"
        echo ""
        read -p "Continue with remaining services anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please check MCP service configuration."
            exit 1
        fi
        log_warning "Continuing despite MCP service issues..."
    fi
    
    # Now start remaining services including ccowmcpclient
    log_info "Starting remaining services..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscapiservice oscwebserver oscreverseproxy ccowmcpclient ccowmcpbridge; then
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
        
        if $DOCKER_CMD ps --filter "name=ccowmcpclient" --filter "status=running" | grep -q ccowmcpclient; then
            ((services_ready++))
        fi

        if $DOCKER_CMD ps --filter "name=ccowmcpbridge" --filter "status=running" | grep -q ccowmcpbridge; then
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
    echo -e "${CYAN}║      Open Security Compliance Setup Completed!            ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Access URLs:"
    echo "  - Web UI (HTTPS): https://localhost:443"
    echo "  - Web UI (HTTP): http://localhost:3001"
    echo "  - API Service: http://localhost:9080"
    echo "  - MinIO Console: http://localhost:9001"
    echo "  - MCP Bridge: http://localhost:8095"
    echo "  - MCP Client Web: http://localhost:8976"
    echo "  - MCP Service: http://localhost:45678"
    echo "  - MCP Health Check: http://localhost:45678/health"
    echo ""
    log_info "AI Model Configuration:"
    echo "  - Provider: Anthropic only"
    echo "  - Detected Model: ${DETECTED_MODEL_NAME:-Claude Sonnet 4}"
    echo "  - Model ID: ${DETECTED_MODEL:-claude-sonnet-4-20250514}"
    echo "  - MCP Sessions: $MCP_SESSION_DIR"
    echo "  - API Key: Configured (from environment)"
    echo ""
    log_info "Rule Creation Methods:"
    echo "  1. Manual UI: Web UI → Reverse Proxy → API Service"
    echo "  2. MCP UI Mode: Web UI → Reverse Proxy → MCP Bridge → MCP Client → MCP Service"
    echo "  3. External MCP: Goose/Claude → MCP (port 45678)"
    echo ""
    log_info "Useful Commands:"
    echo "  - View all logs: $COMPOSE_CMD logs -f"
    echo "  - View MCP Client logs: $COMPOSE_CMD logs -f ccowmcpclient"
    echo "  - View MCP Bridge logs: $COMPOSE_CMD logs -f ccowmcpbridge"
    echo "  - View MCP logs: $COMPOSE_CMD logs -f oscmcpservice"
    echo "  - Check MCP health: curl http://localhost:45678/health"
    echo "  - Stop services: $COMPOSE_CMD down"
    echo "  - Restart services: $COMPOSE_CMD restart"
    echo "  - Check status: $DOCKER_CMD ps"
    echo ""
    log_warning "Important Notes:"
    echo "  ⚠️  Only Anthropic Claude is supported (detected: ${DETECTED_MODEL_NAME:-Claude Sonnet 4})"
    echo "  ⚠️  Requires ANTHROPIC_API_KEY environment variable"
    echo "  ⚠️  MCP sessions persist across restarts"
    echo "  ⚠️  This setup does NOT support multi-tenancy"
    echo "  ⚠️  Not tested at scale - for development/testing only"
    echo "  ⚠️  Ensure you have a beefy machine (16GB+ RAM, 8+ cores)"
    echo ""
}

# Build services for No-Code UI only mode
build_services_nocode() {
    log_info "Building Docker images for No-Code UI services (this may take several minutes)..."

    if $COMPOSE_CMD -f docker-compose-osc.yaml build oscwebserver oscreverseproxy oscapiservice cowstorage; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
}

# Start services for No-Code UI only mode
start_services_nocode() {
    log_info "Starting No-Code UI services..."

    # Start storage first
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d cowstorage; then
        log_success "Storage service started"
        sleep 5
    else
        log_error "Failed to start storage service"
        exit 1
    fi

    # Start remaining No-Code UI services
    log_info "Starting remaining services..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscapiservice oscwebserver oscreverseproxy; then
        log_success "All No-Code UI services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Wait for No-Code UI services to be healthy
wait_for_services_nocode() {
    log_info "Waiting for services to be ready (this may take a minute)..."

    local max_attempts=60
    local attempt=0
    local services_ready=0

    while [ $attempt -lt $max_attempts ] && [ $services_ready -lt 3 ]; do
        services_ready=0

        if $DOCKER_CMD ps --filter "name=oscapiservice" --filter "status=running" | grep -q oscapiservice; then
            ((services_ready++))
        fi

        if $DOCKER_CMD ps --filter "name=oscwebserver" --filter "status=running" | grep -q oscwebserver; then
            ((services_ready++))
        fi

        if $DOCKER_CMD ps --filter "name=oscreverseproxy" --filter "status=running" | grep -q oscreverseproxy; then
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

# Clean up dangling containers for No-Code UI only mode
cleanup_docker_nocode() {
    log_info "Cleaning up dangling Docker resources..."

    for service in "${NO_CODE_UI_SERVICES[@]}"; do
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

    log_info "Pruning unused networks..."
    $DOCKER_CMD network prune -f 2>/dev/null || true

    log_success "Docker cleanup completed"
}

# Display completion info for No-Code UI only mode
show_nocode_info() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Open Security Compliance No-Code UI Setup Completed!  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Access URLs:"
    echo "  - Web UI (HTTPS): https://localhost:443"
    echo "  - Web UI (HTTP): http://localhost:3001"
    echo "  - API Service: http://localhost:9080"
    echo "  - MinIO Console: http://localhost:9001"
    echo ""
    log_info "Useful Commands:"
    echo "  - View all logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f"
    echo "  - Stop services: $COMPOSE_CMD -f docker-compose-osc.yaml down"
    echo "  - Restart services: $COMPOSE_CMD -f docker-compose-osc.yaml restart"
    echo "  - Check status: $DOCKER_CMD ps"
    echo ""
    log_warning "Important Notes:"
    echo "  - MCP/AI features are not enabled in this mode"
    echo "  - To enable MCP features, re-run setup and select option 1 with a valid Anthropic API key"
    echo "  - This setup does NOT support multi-tenancy"
    echo "  - Not tested at scale - for development/testing only"
    echo ""
}

# Main execution
main() {
    print_banner

    # Ask user to select setup mode first
    select_setup_mode

    if [ "$SETUP_MODE" = "full" ]; then
        log_info "Starting Open Security Compliance MCP + No-Code UI Setup..."
    else
        log_info "Starting Open Security Compliance No-Code UI Setup..."
    fi
    echo ""

    # Pre-flight checks (common)
    check_docker
    check_privileges
    check_docker_compose
    check_system_requirements

    # Anthropic key check only for full mode
    if [ "$SETUP_MODE" = "full" ]; then
        check_anthropic_key
    fi

    check_minio_credentials
    check_ssl_certificates
    check_env_files

    # Persist setup mode to env file so the webserver can toggle MCP UI
    ENV_FILE="${SCRIPT_DIR}/etc/userconfig.env"
    if [ "$SETUP_MODE" = "full" ]; then
        update_env_variable "$ENV_FILE" "MCP_ENABLED" "true" "# Setup mode: true = MCP + No-Code UI, false = No-Code UI only"
    else
        update_env_variable "$ENV_FILE" "MCP_ENABLED" "false" "# Setup mode: true = MCP + No-Code UI, false = No-Code UI only"
    fi
    export MCP_ENABLED
    log_info "MCP_ENABLED set to: $([ "$SETUP_MODE" = "full" ] && echo "true" || echo "false")"

    echo ""
    log_info "All pre-flight checks passed!"
    echo ""

    # Display summary based on mode
    if [ "$SETUP_MODE" = "full" ]; then
        echo -e "${CYAN}Setup Summary (MCP + No-Code UI):${NC}"
        echo "  Services to be deployed: 7"
        echo "    1. Web UI (oscwebserver)"
        echo "    2. Reverse Proxy (oscreverseproxy)"
        echo "    3. API Service (oscapiservice)"
        echo "    4. Storage Service (cowstorage/MinIO)"
        echo "    5. MCP Client Integration (ccowmcpclient)"
        echo "    6. MCP Bridge Service (ccowmcpbridge)"
        echo "    7. MCP Service (oscmcpservice)"
    else
        echo -e "${CYAN}Setup Summary (No-Code UI Only):${NC}"
        echo "  Services to be deployed: 4"
        echo "    1. Web UI (oscwebserver)"
        echo "    2. Reverse Proxy (oscreverseproxy)"
        echo "    3. API Service (oscapiservice)"
        echo "    4. Storage Service (cowstorage/MinIO)"
    fi
    echo ""

    # Confirm before proceeding
    read -p "Proceed with Open Security Compliance setup? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Setup cancelled by user"
        exit 0
    fi

    # Setup process based on mode
    if [ "$SETUP_MODE" = "full" ]; then
        cleanup_docker
        build_services
        start_services
        wait_for_services
        show_service_status
        show_mcp_info

        log_success "Open Security Compliance setup completed successfully!"
        echo ""
        log_info "Next steps:"
        echo "  1. Access the Web UI at https://localhost:443"
        echo "  2. Create rules manually or using MCP mode"
        echo "  3. Configure external MCP clients (Goose/Claude) at http://localhost:45678"
        echo "  4. Check the README for detailed usage instructions"
    else
        cleanup_docker_nocode
        build_services_nocode
        start_services_nocode
        wait_for_services_nocode
        show_service_status
        show_nocode_info

        log_success "Open Security Compliance No-Code UI setup completed successfully!"
        echo ""
        log_info "Next steps:"
        echo "  1. Access the Web UI at https://localhost:443"
        echo "  2. Create and manage rules using the No-Code web interface"
        echo "  3. To enable AI/MCP features later, re-run this setup with option 1"
    fi
}

# Trap errors
trap 'log_error "Setup failed at line $LINENO. Check the error messages above."' ERR

# Run main function
main "$@"