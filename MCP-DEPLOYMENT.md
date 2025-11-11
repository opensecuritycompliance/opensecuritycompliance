# Open Security Compliance Rule Engine Setup Guide

Complete setup documentation for deploying Open Security Compliance Rule Engine with integrated No-Code UI and MCP capabilities.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Requirements](#system-requirements)
- [Prerequisites](#prerequisites)
- [Directory Structure](#directory-structure)
- [Setup Process](#setup-process)
- [Configuration](#configuration)
- [Services Overview](#services-overview)
- [Connecting MCP Clients](#connecting-mcp-clients)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Important Limitations](#important-limitations)
- [Maintenance](#maintenance)
- [FAQ](#faq)

---

## Overview

Open Security Compliance is a comprehensive rule engine platform that provides:
- **No-Code UI**: Visual interface for creating and managing compliance rules
- **MCP Integration**: Model Context Protocol integration with Goose AI assistant
- **Dual Rule Creation**: Create rules manually via UI or conversationally via MCP
- **Rule Engine**: Powerful execution engine for compliance automation
- **Storage**: MinIO-based object storage for data persistence
- **API Service**: RESTful API for programmatic access

### What You Can Do

✅ Create compliance rules without coding (UI or MCP)  
✅ Execute automated compliance checks  
✅ Store and manage compliance data  
✅ Integrate with AI assistants via MCP  
✅ Build custom compliance workflows

### AI Model Support

This platform **automatically detects and uses the best available Claude model** from your Anthropic API key:
- **Provider**: Anthropic Claude only
- **Supported Models**: Claude Sonnet 4.5, Claude Sonnet 4
- **Auto-Detection**: Setup script tests your API key and configures the highest available model
- **Note**: Other providers (OpenAI, etc.) are not supported at this time

---

## Architecture

### Unified Platform Architecture

```
                        ┌──────────────┐
                        │     User     │
                        └──────┬───────┘
                               │
                ┌──────────────┴──────────────┐
                │                             │
                │  MANUAL FLOW        MCP FLOW│
                │                             │
                ▼                             ▼
    ┌───────────────────┐         ┌──────────────────┐
    │   Web UI          │         │   Web UI         │
    │  (Manual Mode)    │         │  (MCP Mode)      │
    │  oscwebserver     │         │  oscwebserver    │
    │   Port: 3001      │         │   Port: 3001     │
    └────────┬──────────┘         └────────┬─────────┘
             │                             │
             ▼                             ▼
    ┌───────────────────┐         ┌──────────────────┐
    │ Reverse Proxy     │         │ Reverse Proxy    │
    │ oscreverseproxy   │         │ oscreverseproxy  │
    │   Port: 443       │         │   Port: 443      │
    └────────┬──────────┘         └────────┬─────────┘
             │                             │
             │                             ▼
             │                    ┌──────────────────┐
             │                    │  Goose Service   │
             │                    │  oscgooseservice │
             │                    │  Port: 8095      │
             │                    └────────┬─────────┘
             │                             │
             │                             ▼
             │                    ┌──────────────────┐
             │                    │  Goose           │
             │                    │  oscgoose        │
             │                    │  Port: 8976      │
             │                    └────────┬─────────┘
             │                             │
             │                             ▼
             │                    ┌──────────────────┐
             │                    │  MCP Service     │
             │                    │  oscmcpservice   │
             │                    │  Port: 45678     │◄─────────┐
             │                    └────────┬─────────┘          │
             │                             │                    │
             └─────────────┬───────────────┘         ┌──────────┴─────────┐
                           │                         │  External MCP      │
                           │                         │  Clients           │
                           ▼                         │  (Goose Desktop/   │
                  ┌─────────────────┐                │   Goose CLI/       │
                  │  API Service    │                │   Claude Desktop/  │
                  │  oscapiservice  │                │   Claude Code)     │
                  │  Port: 9080     │                │  Direct Connection │
                  └────────┬────────┘                └────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Storage        │
                  │  cowstorage     │
                  │  MinIO:9000/9001│
                  └─────────────────┘
```

### Rule Creation Flows

#### Flow 1: Manual UI Rule Creation
```
User → Web UI (Manual Mode) → Reverse Proxy → API Service → Storage
```
Create rules using the visual interface. This traditional approach provides a guided UI for rule configuration without any AI assistance.

#### Flow 2: AI-Assisted Rule Creation via UI (MCP Mode)
```
User → Web UI (MCP Mode) → Reverse Proxy → Goose Service → Goose → MCP Service → API Service → Storage
```
Create rules conversationally using AI assistance directly from the Web UI. The reverse proxy routes MCP requests through the Goose services, which then call the API Service to access tasks and rules.

#### Flow 3: External MCP Clients (Direct Connection)
```
External MCP Clients (Goose Desktop/CLI/Claude Desktop/Code) 
    ↓
MCP Service (port 45678) - Direct Connection
    ↓
Goose (oscgoose)
    ↓
Goose Service (oscgooseservice)
    ↓
API Service → Storage
```
Create rules using external AI clients. MCP clients connect directly to the MCP service endpoint at port 45678, bypassing the reverse proxy.

**Note**: The platform offers three ways to create rules:
1. Manual through UI (no AI)
2. AI-assisted through UI (MCP mode via reverse proxy)
3. AI-assisted through external clients (direct MCP connection)

---

## System Requirements

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| **CPU** | 8+ cores |
| **RAM** | 16GB+ |
| **Disk** | 30GB+ SSD |
| **Network** | Stable internet (for Anthropic API) |
| **OS** | Linux, macOS, Windows (WSL2) |
| **Docker** | 20.10+ |
| **Docker Compose** | 2.0+ |

### Performance Considerations

- **Production**: 7 services running simultaneously - dedicated server or cloud hosting recommended
- **Development**: Local machine with 16GB+ RAM is sufficient
- ⚠️ **Note**: These services are resource-intensive. A "beefy machine" or cloud hosting is recommended for production use.

---

## Prerequisites

### 1. Docker Installation

#### Linux
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group (optional, to avoid sudo)
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
```

#### macOS
```bash
# Download and install Docker Desktop
# https://docs.docker.com/desktop/install/mac-install/

# Verify installation
docker --version
docker compose version
```

#### Windows (WSL2)
```bash
# Install WSL2 first
wsl --install

# Download and install Docker Desktop
# https://docs.docker.com/desktop/install/windows-install/

# Verify installation in WSL2
docker --version
docker compose version
```

### 2. Get Your Anthropic API Key

You'll need an Anthropic API key to use the AI-assisted features. The platform will **automatically detect and configure the best available Claude model** from your API key.

#### Step-by-Step Instructions:

1. **Create an Anthropic Account**
   - Visit [console.anthropic.com](https://console.anthropic.com/)
   - Click "Sign Up" if you don't have an account
   - Verify your email address

2. **Generate an API Key**
   - Log in to the Anthropic Console
   - Navigate to "API Keys" in the left sidebar
   - Click "Create Key" button
   - Give your key a descriptive name (e.g., "Open Security Compliance")
   - Copy the generated key immediately (it won't be shown again)

3. **Key Format**
   - Your API key will look like: `sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
   - Always starts with `sk-ant-`

4. **Model Detection During Setup**
   - The setup script will automatically test your API key
   - It checks for access to Claude Sonnet 4.5 (best) and Claude Sonnet 4 (minimum)
   - The highest available model is automatically configured in `GOOSE_MODEL`
   - You'll see: "Best available model: Claude Sonnet X.X (model-id)"

5. **Important Notes**
   - ⚠️ Keep your API key secure and never share it
   - ⚠️ Never commit API keys to version control
   - ⚠️ The setup script will validate your key and detect the best model before proceeding
   - 💡 You can add funds or set up billing in the Anthropic Console
   - 💡 Model detection is automatic - no manual configuration needed

### 3. Install Goose (For External MCP Access - Optional)

Goose is an AI assistant that can connect to the Open Security Compliance platform for conversational rule creation. Installing Goose is **optional** - you can use the platform's Web UI MCP mode without it.

**⚠️ Note**: If you only plan to use the Web UI (manual or MCP mode), you can skip this step. Goose installation is only needed if you want to use external MCP clients like Goose Desktop or Goose CLI.

#### Installation Options

Visit the official Goose installation guide for detailed instructions:

**🔗 [Goose Installation Guide](https://block.github.io/goose/docs/getting-started/installation)**

The guide covers:
- **Goose Desktop** - Graphical desktop application (recommended for beginners)
- **Goose CLI** - Command-line interface (for advanced users)
- Installation steps for macOS, Windows, and Linux
- System requirements and prerequisites

**Quick Installation Summary:**

**Goose Desktop:**
- Visit the [installation guide](https://block.github.io/goose/docs/getting-started/installation) and follow platform-specific instructions
- Available for macOS, Windows, and Linux
- Provides a user-friendly graphical interface

**Goose CLI:**
```bash
# Install via pip (requires Python 3.8+)
pip install goose-ai

# Or via pipx (recommended)
pipx install goose-ai

# Verify installation
goose --version
```

For complete installation instructions, troubleshooting, and configuration options, please refer to the [official Goose documentation](https://block.github.io/goose/docs/getting-started/installation).

### 4. SSL Certificates (Optional - Localhost Certificates Included)

**✅ Default Configuration**: The repository includes pre-configured SSL certificates for **localhost** access. You can skip this section if you're running the platform locally.

**🔧 Custom Domain Setup**: If you want to host the platform with a custom domain name (e.g., `compliance.yourcompany.com`), follow these steps to provide your own SSL certificates.

#### Certificate Locations

You can place your SSL certificates in one of two locations:

**Option A: Repository Directory (Recommended)**
```bash
src/oscreverseproxy/certs/
├── fullchain.pem
└── privkey.pem
```

**Option B: Home Directory**
```bash
${HOME}/continube/certs/
├── fullchain.pem
└── privkey.pem
```

#### Required Files

- `fullchain.pem` - Complete certificate chain (certificate + intermediate certificates)
- `privkey.pem` - Private key file

#### How to Get Custom SSL Certificates

**Free Options:**

**1. Let's Encrypt (Recommended)**
```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificate for your domain
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in /etc/letsencrypt/live/yourdomain.com/
# Copy them to your preferred location:
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem src/oscreverseproxy/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem src/oscreverseproxy/certs/

# Set proper permissions
sudo chmod 644 src/oscreverseproxy/certs/fullchain.pem
sudo chmod 600 src/oscreverseproxy/certs/privkey.pem
```

**2. Using DNS-01 Challenge (For Wildcard Certificates)**
```bash
# Example with Cloudflare DNS
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d yourdomain.com \
  -d *.yourdomain.com
```

**Paid Options:**
- [DigiCert](https://www.digicert.com/)
- [Sectigo](https://sectigo.com/)
- [GlobalSign](https://www.globalsign.com/)

#### Certificate Renewal

Let's Encrypt certificates expire after 90 days. Set up automatic renewal:

```bash
# Test renewal process
sudo certbot renew --dry-run

# Set up automatic renewal (runs twice daily)
sudo systemctl enable certbot-renew.timer
sudo systemctl start certbot-renew.timer

# Or add to crontab
sudo crontab -e
# Add this line:
0 0,12 * * * certbot renew --quiet --post-hook "docker compose restart oscreverseproxy"
```

#### Verification

After placing your certificates:

```bash
# Verify certificate files exist
ls -la src/oscreverseproxy/certs/

# Check certificate validity
openssl x509 -in src/oscreverseproxy/certs/fullchain.pem -text -noout

# Check certificate expiration date
openssl x509 -in src/oscreverseproxy/certs/fullchain.pem -noout -enddate

# Verify private key matches certificate
openssl x509 -noout -modulus -in src/oscreverseproxy/certs/fullchain.pem | openssl md5
openssl rsa -noout -modulus -in src/oscreverseproxy/certs/privkey.pem | openssl md5
# The MD5 hashes should match
```

**Note**: After updating certificates, restart the reverse proxy:
```bash
docker compose restart oscreverseproxy
```

### 5. Environment Configuration Files

The repository includes pre-configured environment files. You only need to **update** them with your specific values.

**📝 Note**: The configuration files already exist in the `etc/` directory. You don't need to create them - just edit the values.

#### `etc/userconfig.env` (User Configuration)

**Location**: `etc/userconfig.env`

**What to Update**:
```bash
# ============================================
# USER CONFIGURATION
# ============================================
# Update these values for your setup

# Your email address
USER_EMAIL=admin@example.com  # ← Change this

# Your timezone (e.g., America/New_York, Europe/London, Asia/Tokyo)
USER_TIMEZONE=UTC  # ← Change this if needed

# ============================================
# ANTHROPIC API KEY (REQUIRED FOR MCP)
# ============================================
# Get your API key from: https://console.anthropic.com/
# Your key starts with: sk-ant-

ANTHROPIC_API_KEY=  # ← Add your API key here

# Example:
# ANTHROPIC_API_KEY=sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# ============================================
# AUTO-DETECTED CLAUDE MODEL (DO NOT EDIT)
# ============================================
# This will be automatically set by the setup script
# based on what models your API key has access to
# GOOSE_MODEL=claude-sonnet-4-5-20250929  # Auto-detected best model

# ============================================
# CUSTOM SETTINGS (OPTIONAL)
# ============================================
# Add any additional custom variables below
```

**Required Actions**:
1. Replace `admin@example.com` with your email
2. Update `USER_TIMEZONE` if needed
3. **Add your Anthropic API key** on the `ANTHROPIC_API_KEY=` line
4. **Do NOT edit GOOSE_MODEL** - it will be automatically set during setup

#### `etc/policycow.env` (Platform Configuration)

**Location**: `etc/policycow.env`

**What to Update**:
```bash
# ============================================
# PLATFORM CONFIGURATION
# ============================================
# These are the default settings for the platform
# Only change these if you need custom configuration

# ============================================
# MINIO STORAGE CREDENTIALS
# ============================================
MINIO_ROOT_USER=minioadmin  # ← Change in production!
MINIO_ROOT_PASSWORD=minioadmin  # ⚠️ MUST change in production!

# IMPORTANT SECURITY REQUIREMENTS:
# - Username: Minimum 3 characters, no spaces
# - Password: Minimum 8 characters, no spaces
# - Setup script will validate and prompt if invalid

# ============================================
# STORAGE CONFIGURATION
# ============================================
COW_DATA_PERSISTENCE_TYPE=minio
MINIO_ENDPOINT=cowstorage:9000

# ============================================
# APPLICATION SETTINGS
# ============================================
APP_ENV=production
LOG_LEVEL=info

# ============================================
# ADVANCED SETTINGS (DO NOT MODIFY)
# ============================================
# These are required for proper operation
# Only modify if you know what you're doing
```

**Recommended Actions**:
- ⚠️ **Production Security**: Change both `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD`
- Username must be at least 3 characters (no spaces)
- Password must be at least 8 characters (no spaces)
- The setup script will validate and prompt you if credentials don't meet requirements
- Most other settings can remain as default

#### `etc/.credentials.env` (Optional - External Integrations)

**Location**: `etc/.credentials.env`

**Purpose**: For storing credentials to external services (AWS, GitHub, etc.)

**Note**: This file is **optional** and only needed if you're integrating with external services.

```bash
# ============================================
# EXTERNAL SERVICE CREDENTIALS (OPTIONAL)
# ============================================
# Only needed if integrating with external services
# Used by cowctl service for external integrations

# AWS Credentials (if using AWS integrations)
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

# GitHub Token (if using GitHub integrations)
# GITHUB_TOKEN=

# Other service credentials as needed
```

**Action**: Only edit this file if you need external service integrations.

#### Quick Start Checklist

Before running the setup script, make sure you've:

- [ ] Updated `USER_EMAIL` in `etc/userconfig.env`
- [ ] Updated `USER_TIMEZONE` in `etc/userconfig.env` (optional)
- [ ] **Added your Anthropic API key** to `etc/userconfig.env`
- [ ] Changed `MINIO_ROOT_USER` in `etc/policycow.env` (recommended for production)
- [ ] Changed `MINIO_ROOT_PASSWORD` in `etc/policycow.env` (REQUIRED for production)
- [ ] Added external service credentials to `etc/.credentials.env` (if needed)

**🚀 You're ready for setup!** The setup script will:
- Automatically detect the best Claude model from your API key
- Validate MinIO credentials (username ≥3 chars, password ≥8 chars)
- Configure GOOSE_MODEL with the detected model
- Save everything to the configuration files

Proceed to the [Setup Process](#setup-process) section.

---

## Directory Structure

After setup, your directory structure will look like this:

```
policycow/
├── setup-mcp.sh                    # Unified setup script (handles both UI and MCP)
├── docker-compose.yaml             # Docker Compose service definitions
├── export_env.sh                   # Environment variable export script (optional)
│
├── etc/                            # Configuration files (✅ PRE-CONFIGURED)
│   ├── userconfig.env             # User configuration (UPDATE VALUES)
│   │                              # GOOSE_MODEL auto-set by setup script
│   ├── policycow.env              # Platform configuration (UPDATE IF NEEDED)
│   │                              # MinIO credentials validated by script
│   └── .credentials.env           # External credentials (OPTIONAL)
│
├── src/                            # Source code (if building locally)
│   └── oscreverseproxy/           # Reverse proxy source
│       └── certs/                 # SSL certificates (✅ LOCALHOST CERTS INCLUDED)
│           ├── fullchain.pem      # Certificate chain (default for localhost)
│           └── privkey.pem        # Private key (default for localhost)
│
├── catalog/                        # Rule catalog
│   ├── globalcatalog/             # Global rule definitions
│   │   ├── tasks/                 # Task definitions
│   │   ├── rules/                 # Rule definitions
│   │   ├── methods/               # Method definitions
│   │   └── dashboards/            # Dashboard definitions
│   ├── localcatalog/              # Local customizations
│   └── applicationtypes/          # Application connectors
│
├── exported-data/                  # Exported compliance data
│
├── goose-config/                   # Goose configuration
│
├── goose-sessions/                 # Goose session data
│   └── sessions/                  # Persistent session storage
│
└── ${HOME}/                        # External directories
    ├── continube/certs/           # SSL certificates (OPTION 2 - if not using repo certs)
    │   ├── fullchain.pem
    │   └── privkey.pem
    └── tmp/cowctl/minio/          # MinIO data storage
```

**✅ Pre-Configured Items**:
- SSL certificates for localhost (in `src/oscreverseproxy/certs/`)
- Environment configuration files (in `etc/`)
- Docker Compose configuration
- Service definitions

**📝 Items You Need to Update**:
- Anthropic API key in `etc/userconfig.env`
- User email and timezone in `etc/userconfig.env`
- MinIO username and password in `etc/policycow.env` (validated by setup script)
- SSL certificates (only if using custom domain)

**🤖 Auto-Generated During Setup**:
- `GOOSE_MODEL` in `etc/userconfig.env` (auto-detected from your API key)

**Note**: This deployment uses pre-built Docker images from GitHub Container Registry. No local Dockerfiles are required.

---

## Setup Process

### Unified Setup Script

The platform now uses a single script that handles both No-Code UI and MCP capabilities with automatic model detection and enhanced validation.

#### Services Included (7)

1. **Web UI** (`oscwebserver`) - React-based UI on port 3001
2. **Reverse Proxy** (`oscreverseproxy`) - HTTPS proxy on port 443
3. **API Service** (`oscapiservice`) - REST API on port 9080
4. **Storage** (`cowstorage`) - MinIO on ports 9000/9001
5. **Goose** (`oscgoose`) - AI assistant on port 8976
6. **Goose Service** (`oscgooseservice`) - MCP orchestration on port 8095
7. **MCP Service** (`oscmcpservice`) - MCP server on port 45678

#### Setup Steps

```bash
# 1. Update configuration files (see Environment Configuration section above)
nano etc/userconfig.env    # Add your API key and update user settings
nano etc/policycow.env     # Update MinIO credentials (will be validated)

# 2. Make setup script executable
chmod +x setup-mcp.sh

# 3. Run setup
./setup-mcp.sh
```

#### What the Script Does (Enhanced)

**Pre-Flight Checks:**
1. ✅ Checks Docker installation and access (with/without sudo)
2. ✅ Validates system resources (CPU, RAM, disk)
3. ✅ Checks for Anthropic API key in `etc/userconfig.env`
4. ✅ Validates API key format (sk-ant-...)
5. ✅ **Tests API key against Anthropic API** (new)
6. ✅ **Auto-detects best available Claude model** (new)
   - Tests Claude Sonnet 4.5 access
   - Falls back to Claude Sonnet 4 if needed
   - Saves detected model to `GOOSE_MODEL` in `etc/userconfig.env`
7. ✅ **Validates MinIO credentials** (new)
   - Username must be ≥3 characters, no spaces
   - Password must be ≥8 characters, no spaces
   - Prompts for missing or invalid credentials
   - Confirms password with re-entry
   - Saves validated credentials to `etc/policycow.env`
8. ✅ Verifies SSL certificates (uses localhost certs by default)
9. ✅ Checks environment configuration files
10. ✅ Sources environment variables from `etc/userconfig.env`
11. ✅ Runs `export_env.sh` if present

**Build and Deploy:**
12. ✅ Cleans up existing containers and images
13. ✅ Creates necessary directories including Goose sessions
14. ✅ Builds all Docker images
15. ✅ Starts services in correct order:
    - Storage first (cowstorage)
    - MCP service next (oscmcpservice) with 20-second settle time
    - Remaining services (oscapiservice, oscwebserver, oscreverseproxy, oscgoose, oscgooseservice)
16. ✅ Waits for services to be healthy
17. ✅ Displays access URLs and commands with detected model info

#### Expected Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Open Security Compliance MCP + No-Code UI Setup         ║
║                   (WITH SUDO SUPPORT)                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Starting Open Security Compliance Setup...

[INFO] Checking Anthropic API key...
[INFO] Validating Anthropic API key...
[SUCCESS] Anthropic API key is valid

[INFO] Detecting best available Claude model...
[INFO] Testing access to Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)...
[SUCCESS] Claude Sonnet 4.5 access confirmed
[SUCCESS] Best available model: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
[SUCCESS] API key saved to etc/userconfig.env
[SUCCESS] GOOSE_MODEL set to: Claude Sonnet 4.5

[INFO] Checking MinIO credentials...
[SUCCESS] MinIO credentials validated successfully
[INFO] Username: myuser (6 characters)
[INFO] Password: ******** (12 characters)
[SUCCESS] MinIO credentials saved to etc/policycow.env

[INFO] Using default localhost SSL certificates...
...

[INFO] Starting MCP service...
[SUCCESS] MCP service started
[INFO] Waiting 20 seconds for MCP service to settle...
Time remaining: 1 seconds ✓ MCP service settled

[SUCCESS] Setup completed successfully!

╔═══════════════════════════════════════════════════════════╗
║      Open Security Compliance Setup Completed!            ║
╚═══════════════════════════════════════════════════════════╝

Access URLs:
  - Web UI (HTTPS): https://localhost:443
  - Web UI (HTTP): http://localhost:3001
  - API Service: http://localhost:9080
  - MinIO Console: http://localhost:9001
  - Goose Service: http://localhost:8095
  - Goose Web: http://localhost:8976
  - MCP Service: http://localhost:45678

AI Model Configuration:
  - Provider: Anthropic only
  - Detected Model: Claude Sonnet 4.5
  - Model ID: claude-sonnet-4-5-20250929
  - Goose Sessions: ./goose-sessions/sessions
  - API Key: Configured (from environment)

Rule Creation Methods:
  1. Manual UI: Web UI → Reverse Proxy → API Service
  2. MCP UI Mode: Web UI → Reverse Proxy → Goose → MCP
  3. External MCP: Goose/Claude → MCP (port 45678)
```

#### New Features in Setup Script

**🆕 Automatic Model Detection:**
- Tests your API key against Anthropic's API
- Checks for Claude Sonnet 4.5 access (best)
- Falls back to Claude Sonnet 4 (minimum required)
- Automatically sets `GOOSE_MODEL` in `etc/userconfig.env`
- No manual model configuration needed!

**🆕 Enhanced MinIO Credential Validation:**
- Validates username (≥3 characters, no spaces)
- Validates password (≥8 characters, no spaces)
- Prompts for missing credentials
- Requires password confirmation
- Automatically saves validated credentials
- Removes invalid credentials and prompts for new ones

**🆕 Improved API Key Validation:**
- Tests key against live Anthropic API
- Provides detailed error messages
- Removes invalid keys and prompts for new ones
- Validates key format before testing
- Supports retry on failure

**🆕 Enhanced Service Startup:**
- MCP service starts with 20-second settle time
- Prevents race conditions with dependent services
- Progress indicator during wait period
- Better startup reliability

---

## Configuration

### Environment Variables

#### User Configuration (`etc/userconfig.env`)
```bash
# User settings
USER_EMAIL=admin@example.com
USER_TIMEZONE=UTC

# MCP/Anthropic settings
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx
GOOSE_MODEL=claude-sonnet-4-5-20250929  # Auto-detected by setup script

# Custom application settings
CUSTOM_VAR1=value1
CUSTOM_VAR2=value2
```

**Loaded by**: Setup script automatically sources this file at startup  
**Auto-Generated**: `GOOSE_MODEL` is automatically set during setup based on your API key

#### Platform Configuration (`etc/policycow.env`)
```bash
# MinIO Configuration (validated by setup script)
MINIO_ROOT_USER=minioadmin  # Min 3 chars, no spaces
MINIO_ROOT_PASSWORD=minioadmin  # Min 8 chars, no spaces

# Storage
COW_DATA_PERSISTENCE_TYPE=minio
MINIO_ENDPOINT=cowstorage:9000

# Application
APP_ENV=production
LOG_LEVEL=info
```

**Loaded by**: Docker Compose via `env_file` directive  
**Validated by**: Setup script checks credential requirements before startup

### Port Configuration

Default ports can be changed in `docker-compose-osc.yaml`:

```yaml
services:
  oscwebserver:
    ports:
      - "3001:80"  # Change 3001 to your preferred port
  
  oscreverseproxy:
    ports:
      - "443:443"  # HTTPS port
      - "80:80"    # HTTP port
  
  oscapiservice:
    ports:
      - "9080:80"  # API service port
  
  cowstorage:
    ports:
      - "9000:9000"  # MinIO API
      - "9001:9001"  # MinIO Console
  
  oscgooseservice:
    ports:
      - "8095:8080"  # Goose service
  
  oscgoose:
    ports:
      - "8976:8080"  # Goose web interface
  
  oscmcpservice:
    ports:
      - "45678:8080"  # MCP service
```

---

## Services Overview

### 1. cowlibrary (Base Image)
**Purpose**: Shared library and dependencies for all services  
**Type**: Base Docker image  
**Dependencies**: None

### 2. cowstorage (MinIO)
**Purpose**: Object storage for rules, data, and artifacts  
**Technology**: MinIO (S3-compatible storage)  
**Ports**:
- `9000` - MinIO API
- `9001` - MinIO Web Console

**Data Volume**: `${HOME}/tmp/cowctl/minio`  
**Credentials**:
- Configured in `etc/policycow.env`
- Validated by setup script (username ≥3 chars, password ≥8 chars)
- ⚠️ **Must change default credentials in production!**

### 3. oscapiservice
**Purpose**: REST API for rule management and execution  
**Technology**: Go-based API service  
**Port**: `9080`  
**Responsibilities**:
- Rule CRUD operations
- Task management
- Rule execution backend
- Application management
- Serves both manual UI and MCP-assisted workflows

**Endpoints**:
- `/api/v1/rules` - Rule management
- `/api/v1/tasks` - Task operations
- `/api/v1/executions` - Rule execution
- `/api/v1/applications` - Application management

### 4. oscwebserver
**Purpose**: React-based web interface  
**Technology**: Node.js + React + Nginx  
**Port**: `3001`  
**Features**:
- Visual rule builder (manual creation)
- AI-assisted rule creation (MCP mode)
- Execution dashboard
- Result visualization
- Application management

**Note**: The UI supports both manual rule creation and AI-assisted creation via MCP integration.

### 5. oscreverseproxy
**Purpose**: HTTPS termination and routing  
**Technology**: Go-based reverse proxy  
**Ports**: `443` (HTTPS), `80` (HTTP)  
**SSL Certificates**: Localhost certificates included by default  
**Routes**:
- `/` → oscwebserver (serves both manual and MCP UI modes)
- `/api` → oscapiservice (for manual operations)
- `/goose` → oscgooseservice (for MCP operations from UI)

### 6. oscgooseservice
**Purpose**: MCP orchestration layer  
**Technology**: Go-based service  
**Port**: `8095`  
**Key Features**:
- Bridges UI requests to MCP infrastructure
- Manages AI conversation context
- Coordinates rule creation via natural language

### 7. oscgoose
**Purpose**: Goose AI assistant integration  
**Technology**: Goose framework  
**Port**: `8976`  
**Provider**: Anthropic Claude  
**Model**: Auto-detected during setup (Claude Sonnet 4.5 or 4)  
**Session Storage**: `./goose-sessions/sessions`  
**Startup**: Waits for MCP service to be ready (20-second settle time)

### 8. oscmcpservice
**Purpose**: Model Context Protocol server  
**Technology**: Python-based MCP server  
**Port**: `45678`  
**Features**:
- MCP protocol implementation
- Integration with oscgoose
- Rule creation assistance
- External client connections
- Calls API service for task and rule access

**Startup Order**: Started before oscgoose with 20-second settle time

---

## Connecting MCP Clients

### Overview

The platform provides two ways to use MCP for AI-assisted rule creation:

#### 1. Via Web UI (MCP Mode) - No Additional Setup Required
Access AI-assisted rule creation directly from the web interface:
- Navigate to the MCP mode in the Web UI
- Requests route through: Web UI → Reverse Proxy → Goose Service → MCP Service → API Service
- No additional configuration needed - works out of the box!
- **Automatically uses the detected Claude model** from your API key

#### 2. Via External MCP Clients (Goose or Claude) - Optional
Connect external AI clients directly to the MCP service at `http://localhost:45678/mcp`:
- **Goose Desktop/CLI** - Full configuration instructions provided below
- **Claude Desktop/Code** - Requires file-based configuration

**Note**: Installing and configuring external MCP clients is completely **optional**. The Web UI MCP mode provides full AI-assisted functionality without any external clients.

External clients bypass the reverse proxy and connect directly to port 45678.

### Capabilities

With MCP integration (UI or external clients), you can:
- Create and manage compliance rules via natural language
- Query existing rules and configurations
- Execute compliance checks through conversational interface
- Get guidance on rule creation and best practices

**Note**: This platform **automatically detects and uses the best available Claude model** from your Anthropic API key.

### Supported External MCP Clients

The following external MCP clients are supported (all optional):
- **Goose Desktop** - Graphical desktop application (recommended)
- **Goose CLI** - Command-line interface
- **Claude Desktop** - Anthropic's desktop application (requires manual MCP configuration)
- **Claude Code** - VS Code extension for Claude (requires manual MCP configuration)

**Note**: Claude Desktop and Claude Code require file-based MCP configuration. For detailed setup instructions, please refer to the official Anthropic documentation.

---

## Configuring Goose Desktop (Optional)

**⚠️ Note**: This section is **optional**. You only need to configure Goose Desktop if you want to use an external MCP client. The Web UI MCP mode works without any additional setup.

### Prerequisites
- Goose Desktop installed (see [Installation Guide](https://block.github.io/goose/docs/getting-started/installation))
- Open Security Compliance platform running (setup completed)
- Anthropic API key configured
- **GOOSE_MODEL automatically detected** during setup

### Step-by-Step Configuration

#### Step 1: Locate Goose Configuration Directory

Goose Desktop stores its configuration in a platform-specific location:

**macOS:**
```bash
~/.config/goose/
```

**Linux:**
```bash
~/.config/goose/
```

**Windows:**
```bash
%USERPROFILE%\.config\goose\
```

#### Step 2: Create or Edit Configuration File

Create or edit the `config.yaml` file in the Goose configuration directory:

```bash
# macOS/Linux
mkdir -p ~/.config/goose
nano ~/.config/goose/config.yaml

# Windows (in PowerShell)
mkdir -Force $env:USERPROFILE\.config\goose
notepad $env:USERPROFILE\.config\goose\config.yaml
```

#### Step 3: Add MCP Server Configuration

Add the following configuration to your `config.yaml`:

```yaml
# Goose Configuration for Open Security Compliance

# MCP Server Configuration
mcp:
  servers:
    grc-rule-creator:
      enabled: true
      type: streamable_http
      name: grc-rule-creator
      description: Open Security Compliance Rule Creator
      uri: http://localhost:45678/mcp
      envs: {
        "ENABLE_CCOW_API_TOOLS": false,
        "MCP_TOOLS_TO_BE_INCLUDED": "rules",
        "OSC_GOOSE": true
      }
      env_keys: []
      headers: {}
      timeout: 300

# Provider Configuration (Anthropic only)
provider: anthropic

# Model will be auto-detected from your etc/userconfig.env
# Check GOOSE_MODEL value in etc/userconfig.env for your configured model
# Possible values:
#   - claude-sonnet-4-5-20250929 (Claude Sonnet 4.5 - best)
#   - claude-sonnet-4-20250514 (Claude Sonnet 4 - minimum)
model: claude-sonnet-4-5-20250929  # Update this to match your GOOSE_MODEL

# API Key (optional - can also be set via environment variable)
# anthropic_api_key: sk-ant-xxxxxxxxxxxxx
```

**Important Configuration Notes:**

1. **MCP Server URI**: `http://localhost:45678/mcp`
   - This connects to your local Open Security Compliance MCP service
   - Make sure the platform is running before connecting

2. **Provider**: Set to `anthropic` (only provider supported)

3. **Model**: Update to match your `GOOSE_MODEL` from `etc/userconfig.env`
   - After setup, check: `cat etc/userconfig.env | grep GOOSE_MODEL`
   - Use the exact model ID shown there
   - Common values:
     - `claude-sonnet-4-5-20250929` (if you have Claude Sonnet 4.5 access)
     - `claude-sonnet-4-20250514` (if you have Claude Sonnet 4 access)

4. **API Key**: You can either:
   - Set `ANTHROPIC_API_KEY` environment variable (recommended)
   - Add `anthropic_api_key` to this config file (less secure)

#### Step 4: Verify Your Model Configuration

Before launching Goose, verify which model was detected during setup:

```bash
# Check your detected model
cat etc/userconfig.env | grep GOOSE_MODEL

# Output example:
# GOOSE_MODEL=claude-sonnet-4-5-20250929

# Update your Goose config.yaml to match this model
```

#### Step 5: Set API Key (If Not Using Environment Variable)

If you haven't set the `ANTHROPIC_API_KEY` environment variable, you can add it to the config:

```yaml
anthropic_api_key: sk-ant-xxxxxxxxxxxxx
```

**Security Warning**: Config files may be readable by other users. Environment variables are more secure.

#### Step 6: Launch Goose Desktop

1. **Start the Open Security Compliance Platform**
   ```bash
   cd /path/to/policycow
   ./setup-mcp.sh
   ```

2. **Launch Goose Desktop**
   - macOS: Open from Applications folder
   - Windows: Launch from Start menu
   - Linux: Run the AppImage

3. **Verify MCP Connection**
   In Goose Desktop, type:
   ```
   What MCP tools are available?
   ```
   
   You should see tools like:
   - `get_tasks` - List available compliance tasks
   - `get_rules` - Retrieve existing rules
   - `create_rule` - Create new compliance rules
   - And more...

#### Step 7: Test the Connection

Try creating a simple rule:
```
Create a compliance rule that checks if all EC2 instances have encryption enabled
```

Goose should:
1. Connect to the MCP service
2. Use the auto-detected Claude model (Sonnet 4.5 or 4)
3. Understand your request
4. Create the rule using the Open Security Compliance API
5. Confirm the rule creation

---

## Configuring Goose CLI (Optional)

**⚠️ Note**: This section is **optional**. You only need to configure Goose CLI if you want to use an external MCP client. The Web UI MCP mode works without any additional setup.

### Prerequisites
- Goose CLI installed via pip or pipx (see [Installation Guide](https://block.github.io/goose/docs/getting-started/installation))
- Open Security Compliance platform running
- Anthropic API key configured
- **GOOSE_MODEL automatically detected** during setup

### Step-by-Step Configuration

#### Step 1: Locate Goose Configuration Directory

```bash
# macOS/Linux
~/.config/goose/

# Windows
%USERPROFILE%\.config\goose\
```

#### Step 2: Create Configuration File

```bash
# macOS/Linux
mkdir -p ~/.config/goose
nano ~/.config/goose/config.yaml

# Windows (PowerShell)
mkdir -Force $env:USERPROFILE\.config\goose
notepad $env:USERPROFILE\.config\goose\config.yaml
```

#### Step 3: Add MCP Server Configuration

Use the same configuration as Goose Desktop, but verify your model:

```yaml
# Goose CLI Configuration for Open Security Compliance

mcp:
  servers:
    grc-rule-creator:
      enabled: true
      type: streamable_http
      name: grc-rule-creator
      description: Open Security Compliance Rule Creator
      uri: http://localhost:45678/mcp
      envs: {
        "ENABLE_CCOW_API_TOOLS": false,
        "MCP_TOOLS_TO_BE_INCLUDED": "rules",
        "OSC_GOOSE": true
      }
      env_keys: []
      headers: {}
      timeout: 300

provider: anthropic

# Check etc/userconfig.env for your GOOSE_MODEL value
# Update this to match: cat etc/userconfig.env | grep GOOSE_MODEL
model: claude-sonnet-4-5-20250929  # Update to match your detected model
```

#### Step 4: Verify Your Model Configuration

```bash
# Check your detected model
cat etc/userconfig.env | grep GOOSE_MODEL

# Example output:
# GOOSE_MODEL=claude-sonnet-4-5-20250929

# Update config.yaml model field to match
```

#### Step 5: Set API Key Environment Variable

```bash
# macOS/Linux (add to ~/.bashrc or ~/.zshrc)
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx

# Windows (PowerShell - add to $PROFILE)
$env:ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"

# Or set it temporarily in current session
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx  # macOS/Linux
$env:ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"  # Windows
```

#### Step 6: Launch Goose CLI

```bash
# Start a new Goose session
goose session start

# Or run a specific command
goose run "What MCP tools are available?"
```

#### Step 7: Verify MCP Connection

```bash
goose run "List all available compliance tasks"
```

You should see output showing the MCP tools and tasks from the Open Security Compliance platform, using your auto-detected Claude model.

### Common CLI Commands

```bash
# Start interactive session
goose session start

# List available sessions
goose session list

# Resume a previous session
goose session resume <session-id>

# Run a one-off command
goose run "Create a rule for checking S3 bucket encryption"

# Get help
goose --help
```

---

## MCP Configuration Troubleshooting

### Common Issues

#### 1. "MCP Server Not Found" Error

**Cause**: Goose can't connect to the MCP service

**Solution**:
```bash
# Verify the platform is running
docker ps | grep oscmcpservice

# Check MCP service logs
docker compose logs oscmcpservice

# Verify MCP service started properly (should have 20-second settle time)
docker compose logs oscmcpservice | grep -i "settle"

# Test MCP endpoint manually
curl http://localhost:45678/mcp
```

#### 2. "Invalid API Key" Error

**Cause**: Anthropic API key is missing or invalid

**Solution**:
```bash
# Verify API key is set in etc/userconfig.env
cat etc/userconfig.env | grep ANTHROPIC_API_KEY

# Verify detected model
cat etc/userconfig.env | grep GOOSE_MODEL

# Test API key manually with detected model
GOOSE_MODEL=$(grep GOOSE_MODEL etc/userconfig.env | cut -d'=' -f2)
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "{\"model\":\"$GOOSE_MODEL\",\"max_tokens\":1024,\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}"

# Re-run setup to validate and detect model again
./setup-mcp.sh
```

#### 3. "Model Not Supported" Error

**Cause**: Trying to use a model that your API key doesn't have access to

**Solution**:
```bash
# Check what model was auto-detected
cat etc/userconfig.env | grep GOOSE_MODEL

# Update your Goose config.yaml to match this model
nano ~/.config/goose/config.yaml

# Or re-run setup to re-detect available models
./setup-mcp.sh
```

#### 4. Connection Timeout

**Cause**: Network issues or service not responding

**Solution**:
```bash
# Check if all services are healthy
docker compose ps

# Restart MCP stack (including settle time)
docker compose restart oscmcpservice oscgoose oscgooseservice

# Wait for MCP service to settle (20 seconds)
sleep 20

# Increase timeout in config.yaml
timeout: 600  # Increase from 300 to 600 seconds
```

#### 5. Configuration File Not Found

**Cause**: Config file in wrong location or incorrect permissions

**Solution**:
```bash
# Verify config file exists
ls -la ~/.config/goose/config.yaml

# Check file permissions
chmod 644 ~/.config/goose/config.yaml

# Verify YAML syntax
python -c "import yaml; yaml.safe_load(open('~/.config/goose/config.yaml'))"
```

#### 6. Wrong Model Configured

**Cause**: Goose config.yaml model doesn't match your API key's available models

**Solution**:
```bash
# 1. Check what model was auto-detected during setup
cat etc/userconfig.env | grep GOOSE_MODEL

# Example output:
# GOOSE_MODEL=claude-sonnet-4-5-20250929

# 2. Update Goose config.yaml to match
nano ~/.config/goose/config.yaml

# 3. Change the model line to match GOOSE_MODEL:
# model: claude-sonnet-4-5-20250929  # Match your detected model

# 4. Save and restart Goose Desktop/CLI

# 5. If you want to re-detect the model, re-run setup:
./setup-mcp.sh
```

---

## Usage

### Accessing Services

#### Web UI
```
HTTPS: https://localhost:443
HTTP:  http://localhost:3001
```

**Features**:
- Create rules manually via visual builder
- Create rules via MCP mode (AI-powered) - **No external clients needed!**
- Execute compliance checks
- View execution results
- Manage applications
- **Automatically uses detected Claude model** (Sonnet 4.5 or 4)

**SSL Configuration**:
- **Default**: Uses localhost certificates (works immediately)
- **Custom Domain**: Replace certificates in `src/oscreverseproxy/certs/` for your domain

#### API Service
```
Base URL: http://localhost:9080/api/v1
```

#### Goose Service (MCP Orchestration)
```
Base URL: http://localhost:8095
```

#### Goose Web Interface
```
URL: http://localhost:8976
Model: Auto-detected (check etc/userconfig.env)
```

#### MinIO Console
```
URL: http://localhost:9001
Username: From etc/policycow.env (MINIO_ROOT_USER)
Password: From etc/policycow.env (MINIO_ROOT_PASSWORD)
Note: Change default credentials in production!
```

#### MCP Service (For External Clients - Optional)
```
URL: http://localhost:45678/mcp
Model: Auto-detected from your API key
```

**Note**: External MCP clients are optional. The Web UI provides full MCP functionality.

### Managing Services

#### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f oscapiservice
docker compose logs -f oscgooseservice
docker compose logs -f oscgoose
docker compose logs -f oscmcpservice

# Check for model configuration in logs
docker compose logs oscgoose | grep -i "model"
docker compose logs oscmcpservice | grep -i "model"
```

#### Stop Services
```bash
docker compose down
```

#### Restart Services
```bash
docker compose restart

# Or restart MCP stack specifically (with settle time)
docker compose restart oscmcpservice
sleep 20  # Wait for MCP service to settle
docker compose restart oscgoose oscgooseservice
```

#### Check Service Status
```bash
docker compose ps

# Check which model is configured
cat etc/userconfig.env | grep GOOSE_MODEL
```

---

## Troubleshooting

### Common Issues

#### 1. Service Won't Start
```bash
# Check logs
docker compose logs <service-name>

# Verify configuration
cat etc/userconfig.env
cat etc/policycow.env

# Check for model configuration issues
cat etc/userconfig.env | grep GOOSE_MODEL

# Restart service
docker compose restart <service-name>
```

#### 2. MCP Connection Issues (Web UI)
```bash
# Verify MCP service is running
docker ps | grep oscmcpservice

# Check MCP service logs
docker compose logs oscmcpservice

# Verify MCP service had proper settle time (20 seconds)
docker compose logs oscmcpservice | grep -i "ready\|listening"

# Restart MCP stack with proper timing
docker compose restart oscmcpservice
sleep 20  # Critical settle time
docker compose restart oscgoose oscgooseservice
```

#### 3. Anthropic API Key Invalid or Model Issues
```bash
# Check if key and model are set
cat etc/userconfig.env | grep ANTHROPIC_API_KEY
cat etc/userconfig.env | grep GOOSE_MODEL

# Test key and detect model manually
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: YOUR_API_KEY_FROM_CONFIG" \
  -H "anthropic-version: 2023-06-01"

# Re-run setup to re-detect model
./setup-mcp.sh

# This will:
# 1. Validate your API key
# 2. Test access to Claude Sonnet 4.5
# 3. Fall back to Claude Sonnet 4 if needed
# 4. Update GOOSE_MODEL automatically
```

#### 4. MinIO Credential Issues
```bash
# Check current credentials
cat etc/policycow.env | grep MINIO_ROOT

# Validate credentials meet requirements
# Username: minimum 3 characters, no spaces
# Password: minimum 8 characters, no spaces

# Update credentials
nano etc/policycow.env

# Or re-run setup to validate and set new credentials
./setup-mcp.sh

# Restart storage service
docker compose restart cowstorage
```

#### 5. Goose Desktop/CLI Can't Connect (If Using External Clients)

**Check Platform Status:**
```bash
# Verify all services are running
docker compose ps

# Check MCP service specifically
docker compose logs oscmcpservice

# Verify MCP service settle time was respected
docker compose logs oscmcpservice | tail -20

# Test MCP endpoint
curl http://localhost:45678/mcp
```

**Verify Configuration:**
```bash
# Check Goose config file
cat ~/.config/goose/config.yaml

# Verify model matches platform configuration
cat etc/userconfig.env | grep GOOSE_MODEL
cat ~/.config/goose/config.yaml | grep "model:"

# Verify API key
echo $ANTHROPIC_API_KEY
```

**Fix Model Mismatch:**
```bash
# Get correct model from platform
PLATFORM_MODEL=$(grep GOOSE_MODEL etc/userconfig.env | cut -d'=' -f2)
echo "Platform model: $PLATFORM_MODEL"

# Update Goose config
nano ~/.config/goose/config.yaml
# Change model: line to match $PLATFORM_MODEL
```

**Restart Everything:**
```bash
# Restart platform with proper timing
docker compose restart oscmcpservice
sleep 20  # Critical settle time
docker compose restart oscgoose oscgooseservice

# Close and reopen Goose Desktop/CLI
```

#### 6. SSL Certificate Issues (Custom Domain)

**If using a custom domain and seeing certificate errors:**

```bash
# Verify certificate files exist
ls -la src/oscreverseproxy/certs/

# Check certificate validity
openssl x509 -in src/oscreverseproxy/certs/fullchain.pem -text -noout

# Verify certificate matches domain
openssl x509 -in src/oscreverseproxy/certs/fullchain.pem -noout -text | grep "Subject:"

# Restart reverse proxy after certificate update
docker compose restart oscreverseproxy
```

**If using localhost (default):**
```bash
# The included certificates work for localhost
# You may see browser warnings - this is normal for self-signed certificates
# Click "Advanced" and "Proceed to localhost (unsafe)" to continue
```

#### 7. Wrong Claude Model Being Used

**Symptoms**: Rules failing, API errors, or model not found errors

**Solution**:
```bash
# 1. Check what model is currently configured
cat etc/userconfig.env | grep GOOSE_MODEL

# 2. Verify your API key has access to this model
CURRENT_MODEL=$(grep GOOSE_MODEL etc/userconfig.env | cut -d'=' -f2)
curl -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: $(grep ANTHROPIC_API_KEY etc/userconfig.env | cut -d'=' -f2)" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "{\"model\":\"$CURRENT_MODEL\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"Hi\"}]}"

# 3. If you get 404 or 403, your key doesn't have access to that model
# Re-run setup to detect the correct model:
./setup-mcp.sh

# 4. Verify the new detected model
cat etc/userconfig.env | grep GOOSE_MODEL

# 5. Restart services to apply new model
docker compose restart oscgoose oscgooseservice
```

---

## Important Limitations

### Multi-tenancy
- ❌ **NOT SUPPORTED**: This setup is single-tenant only
- Each deployment serves a single organization/user

### Scalability
- ❌ **NOT TESTED AT SCALE**: Designed for development/testing
- No horizontal scaling configured
- No load balancing included

### AI Model Support
- ✅ **Anthropic Claude Only**: No other providers supported
- ✅ **Auto-Detection**: Setup automatically detects best available model
- ✅ **Supported Models**: Claude Sonnet 4.5, Claude Sonnet 4
- ❌ **No OpenAI/Other Providers**: Platform is Anthropic-specific
- ⚠️ **Model Requirements**: Your API key must have access to at least Claude Sonnet 4

### MCP Client Support
- ✅ **Web UI MCP Mode**: Built-in, no external clients needed
- ✅ **Goose Desktop**: Optional external client (fully supported)
- ✅ **Goose CLI**: Optional external client (fully supported)
- ✅ **Claude Desktop**: Optional external client (requires file-based MCP config)
- ✅ **Claude Code**: Optional external client (requires file-based MCP config)
- ⚠️ **Model Consistency**: External clients should use same model as `GOOSE_MODEL`
- ❌ **No OpenAI/Other Providers**: Platform is Anthropic-specific

### Security Considerations
- ✅ **SSL Included**: Localhost certificates included by default
- ⚠️ **Custom Domain**: Requires your own SSL certificates
- ⚠️ **Default Credentials**: Setup validates but you must change MinIO credentials
- ⚠️ **Credential Requirements**: Username ≥3 chars, password ≥8 chars (enforced by setup)
- ⚠️ **API Security**: No authentication/authorization by default
- ⚠️ **API Key Protection**: Never commit API keys to version control

---

## Maintenance

### Backup Important Data
```bash
# Create backup directory
mkdir -p ${HOME}/policycow-backups/$(date +%Y%m%d)

# Backup MinIO data
cp -r ${HOME}/tmp/cowctl/minio \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/minio

# Backup Goose sessions
cp -r goose-sessions \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/goose-sessions

# Backup catalogs
cp -r catalog \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/catalog

# Backup environment files (excluding API key for security)
cp etc/policycow.env \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/
# Note: Do NOT backup userconfig.env with API key to external storage

# Backup model configuration (safe - just model ID)
grep GOOSE_MODEL etc/userconfig.env > \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/model-config.txt
```

### Update Services
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose down
docker compose build --no-cache

# Re-run setup to ensure latest configuration and model detection
./setup-mcp.sh
```

### Update Model Configuration
```bash
# If you upgrade your Anthropic API key to access better models:

# 1. Update API key in etc/userconfig.env
nano etc/userconfig.env

# 2. Re-run setup to detect new available models
./setup-mcp.sh

# 3. Verify new model was detected
cat etc/userconfig.env | grep GOOSE_MODEL

# 4. Update external Goose clients (if using)
nano ~/.config/goose/config.yaml
# Update model: line to match new GOOSE_MODEL
```

### SSL Certificate Renewal (Custom Domain Only)

If using Let's Encrypt certificates:

```bash
# Renew certificates
sudo certbot renew

# Copy new certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem src/oscreverseproxy/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem src/oscreverseproxy/certs/

# Set proper permissions
sudo chmod 644 src/oscreverseproxy/certs/fullchain.pem
sudo chmod 600 src/oscreverseproxy/certs/privkey.pem

# Restart reverse proxy
docker compose restart oscreverseproxy
```

---

## FAQ

### General Questions

**Q: What is Open Security Compliance?**  
A: Open Security Compliance is a comprehensive rule engine platform for creating and managing compliance rules through manual UI, AI-assisted UI (MCP mode), or optional external AI clients (Goose).

**Q: How many ways can I create rules?**  
A: Three ways:
1. Manual through Web UI (traditional visual builder)
2. AI-assisted through Web UI (MCP mode via reverse proxy) - **No external setup needed!**
3. AI-assisted through optional external clients (Goose Desktop or Goose CLI connecting directly to port 45678)

**Q: Do I need to install Goose to use AI-assisted features?**  
A: **No!** The Web UI has built-in MCP mode that provides full AI-assisted functionality without any external clients. Goose is only needed if you prefer using an external AI client.

**Q: What AI models are supported?**  
A: Only **Anthropic Claude** is supported. The setup script **automatically detects** the best available model from your API key:
- **Best**: Claude Sonnet 4.5 (if your key has access)
- **Minimum**: Claude Sonnet 4 (required at minimum)
- Other providers like OpenAI are not currently supported.

**Q: How does model detection work?**  
A: During setup:
1. Script validates your Anthropic API key
2. Tests access to Claude Sonnet 4.5 (best model)
3. Falls back to Claude Sonnet 4 if 4.5 not available
4. Automatically saves detected model to `GOOSE_MODEL` in `etc/userconfig.env`
5. You see: "Best available model: Claude Sonnet X.X"
6. No manual model configuration needed!

**Q: Can I change which model is used?**  
A: The model is auto-detected based on your API key's permissions. To change:
1. Upgrade your Anthropic API key to access better models
2. Re-run `./setup-mcp.sh` to re-detect available models
3. The script will automatically configure the best available model

**Q: Where do I get an Anthropic API key?**  
A: Visit [console.anthropic.com](https://console.anthropic.com/), sign up or log in, navigate to "API Keys", and create a new key. See the [Get Your Anthropic API Key](#2-get-your-anthropic-api-key) section for detailed steps.

**Q: How do I install Goose (if I want to use it)?**  
A: Visit the [official Goose installation guide](https://block.github.io/goose/docs/getting-started/installation) for detailed instructions on installing:
- **Goose Desktop**: Graphical interface for macOS, Windows, and Linux
- **Goose CLI**: Command-line interface via pip or pipx

**Q: Do I need to create configuration files?**  
A: **No!** All configuration files are already included in the repository. You only need to:
1. Update the `ANTHROPIC_API_KEY` in `etc/userconfig.env`
2. Optionally update `USER_EMAIL` and `USER_TIMEZONE`
3. Update `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` in `etc/policycow.env` (validated by setup)
4. The `GOOSE_MODEL` is automatically set during setup

**Q: What are the MinIO credential requirements?**  
A: The setup script enforces:
- **Username**: Minimum 3 characters, no spaces
- **Password**: Minimum 8 characters, no spaces
- Script validates credentials and prompts you to fix them if invalid
- Password confirmation required for security

**Q: Do I need SSL certificates?**  
A: **No!** The repository includes localhost SSL certificates by default. You only need custom certificates if hosting with a custom domain name (not localhost).

**Q: How do I use custom SSL certificates?**  
A: If hosting with a custom domain:
1. Obtain certificates from Let's Encrypt or another CA
2. Place `fullchain.pem` and `privkey.pem` in `src/oscreverseproxy/certs/`
3. Restart the reverse proxy: `docker compose restart oscreverseproxy`

See the [SSL Certificates](#4-ssl-certificates-optional---localhost-certificates-included) section for detailed steps.

**Q: What's the role of the API service?**  
A: The API service (`oscapiservice`) handles all rule CRUD operations, task management, and execution backend. It serves manual UI workflows, MCP UI workflows, and optional external MCP client workflows.

**Q: Can I create rules without using MCP?**  
A: Yes! The manual UI mode is available for traditional visual rule creation without any AI assistance.

**Q: Do I need an Anthropic API key if I only use manual UI?**  
A: The setup script requires the key to be configured, but if you only plan to use manual UI rule creation, the MCP services will start but you won't actively use them.

**Q: How does MCP work from the Web UI?**  
A: When you use MCP mode in the Web UI, requests go: Web UI → Reverse Proxy → Goose Service → Goose → MCP Service → API Service. This is built-in and requires no external clients. It uses the auto-detected Claude model from your API key.

**Q: What's the difference between UI MCP mode and external MCP clients?**  
A: UI MCP mode is built into the web interface and requires no additional setup. External MCP clients (Goose Desktop/CLI, Claude Desktop/Code) are optional tools that connect directly to port 45678, providing a different interface for the same AI-assisted functionality.

**Q: Can I use both the Web UI MCP mode and external clients (Goose/Claude) at the same time?**  
A: Yes! They're independent ways to access the same underlying MCP service. You can use whichever interface you prefer at any time. Just ensure external clients use the same model as `GOOSE_MODEL`.

**Q: What model should I configure in Goose (if using it)?**  
A: Check your auto-detected model:
```bash
cat etc/userconfig.env | grep GOOSE_MODEL
```
Use the exact model ID shown there in your Goose `config.yaml`. Common values:
- `claude-sonnet-4-5-20250929` (Claude Sonnet 4.5)
- `claude-sonnet-4-20250514` (Claude Sonnet 4)

**Q: Can I access the Web UI without HTTPS?**  
A: Yes! The Web UI is accessible via both:
- HTTPS: `https://localhost:443` (default localhost certificates)
- HTTP: `http://localhost:3001` (direct access)

**Q: Why does the MCP service have a 20-second settle time?**  
A: The MCP service needs time to initialize properly before other services (like oscgoose) connect to it. The 20-second wait prevents connection race conditions and ensures stable startup.

**Q: What happens if my API key doesn't have access to Claude Sonnet 4?**  
A: The setup script will fail with a clear error message:
```
[ERROR] No compatible Claude model found
  - This platform requires at least Claude Sonnet 4
  - Your API key does not have access to any supported models
```
You'll need to upgrade your Anthropic account or get a new API key with proper model access.

**Q: Can I manually set GOOSE_MODEL instead of auto-detection?**  
A: Not recommended. The auto-detection ensures you're using a model your API key actually has access to. Manual configuration could lead to authentication errors. If you need a different model, upgrade your API key and re-run setup.

**Q: How do I verify my current model configuration?**  
A: Check the configuration:
```bash
# Check platform model
cat etc/userconfig.env | grep GOOSE_MODEL

# Check Goose client model (if using external clients)
cat ~/.config/goose/config.yaml | grep "model:"

# Verify they match
```

**Q: What should I do if I see "model not found" errors?**  
A: This means there's a mismatch between configured model and API key access:
1. Check your current model: `cat etc/userconfig.env | grep GOOSE_MODEL`
2. Re-run setup to re-detect: `./setup-mcp.sh`
3. Verify new model: `cat etc/userconfig.env | grep GOOSE_MODEL`
4. Update external clients if needed: `nano ~/.config/goose/config.yaml`
5. Restart services: `docker compose restart oscgoose oscgooseservice`

**Q: Can I use Claude Desktop or Claude Code with this platform?**  
A: Yes! Both **Claude Desktop** and **Claude Code** are supported as optional external clients. However, they require file-based MCP configuration. We provide configuration instructions for Goose clients in this README. For Claude Desktop/Code setup, please refer to the [official Anthropic MCP documentation](https://docs.anthropic.com/claude/docs/mcp).

**Q: Do I need sudo to run the setup script?**  
A: The script automatically detects if Docker needs sudo:
- If you're in the docker group: runs without sudo
- If not in docker group: uses sudo automatically
- You'll see: "Docker accessible without sudo" or "Running Docker commands with sudo"

**Q: What's the compose command format?**  
A: The script automatically detects:
- `docker compose` (plugin) - preferred
- `docker-compose` (standalone) - fallback
- Uses sudo if needed

**Q: Where are Goose sessions stored?**  
A: Sessions persist in `./goose-sessions/sessions/` directory, maintained across container restarts.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                     QUICK REFERENCE                         │
├─────────────────────────────────────────────────────────────┤
│ Setup Script:                                               │
│  ./setup-mcp.sh          - Unified setup (7 services)       │
│                          - Auto-detects best Claude model   │
│                          - Validates MinIO credentials      │
│                                                             │
│ Access URLs:                                                │
│  https://localhost:443   - Web UI (HTTPS)                   │
│  http://localhost:3001   - Web UI (HTTP)                    │
│  http://localhost:9080   - API Service                      │
│  http://localhost:8095   - Goose Service (MCP)              │
│  http://localhost:8976   - Goose Web                        │
│  http://localhost:9001   - MinIO Console                    │
│  http://localhost:45678/mcp - MCP Service                   │
│                                                             │
│ AI Model Configuration:                                     │
│  Provider: Anthropic only                                   │
│  Auto-Detection: Yes (setup script)                         │
│  Supported Models:                                          │
│    - Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)         │
│    - Claude Sonnet 4 (claude-sonnet-4-20250514)             │
│  Model Config: etc/userconfig.env (GOOSE_MODEL)             │
│  External Clients: Goose Desktop/CLI, Claude Desktop/Code   │
│  Note: Claude clients require file-based MCP config         │
│                                                             │
│ Credential Requirements:                                    │
│  MinIO Username: ≥3 chars, no spaces (validated)            │
│  MinIO Password: ≥8 chars, no spaces (validated)            │
│  API Key: sk-ant-... format (validated + model tested)      │
│                                                             │
│ Rule Creation Methods:                                      │
│  1. Manual UI: Web UI → Reverse Proxy → API Service         │
│  2. MCP UI Mode: Web UI → Reverse Proxy → Goose → MCP       │
│  3. External MCP: Goose/Claude → MCP (port 45678)           │
│                                                             │
│ Goose Configuration:                                        │
│  Config File: ~/.config/goose/config.yaml                   │
│  MCP URI: http://localhost:45678/mcp                        │
│  Model: Check etc/userconfig.env GOOSE_MODEL value          │
│  Update: Match config.yaml model to GOOSE_MODEL             │
│                                                             │
│ Check Your Model:                                           │
│  cat etc/userconfig.env | grep GOOSE_MODEL                  │
│                                                             │
│ Useful Commands:                                            │
│  docker compose logs -f              - View all logs        │
│  docker compose logs oscgooseservice - View Goose Svc logs  │
│  docker compose logs oscmcpservice   - View MCP logs        │
│  docker compose ps                   - Service status       │
│  docker compose down                 - Stop services        │
│  docker compose restart              - Restart all          │
│                                                             │
│ MCP Service Restart (with settle time):                     │
│  docker compose restart oscmcpservice                       │
│  sleep 20  # Wait for MCP service to settle                 │
│  docker compose restart oscgoose oscgooseservice            │
│                                                             │
│ Re-detect Model:                                            │
│  ./setup-mcp.sh          - Validates API key & detects model│
│  cat etc/userconfig.env | grep GOOSE_MODEL - Check result   │
│                                                             │
│ Goose Commands:                                             │
│  goose session start                 - Start CLI session    │
│  goose run "query"                   - Run one-off command  │
│  goose --help                        - Get help             │
│                                                             │
│ Important Files:                                            │
│  etc/userconfig.env                  - User config + API key│
│                                      - GOOSE_MODEL (auto)   │
│  etc/policycow.env                   - Platform config      │
│                                      - MinIO credentials    │
│  ~/.config/goose/config.yaml         - Goose configuration  │
│  src/oscreverseproxy/certs/          - SSL certs (opt 1)    │
│  goose-sessions/sessions/            - Goose sessions       │
│                                                             │
│ Validation Features:                                        │
│  ✓ API key format validation                                │
│  ✓ API key authentication test                              │
│  ✓ Best model auto-detection                                │
│  ✓ MinIO credential validation                              │
│  ✓ 20-second MCP service settle time                        │
│  ✓ Sudo auto-detection                                      │
└─────────────────────────────────────────────────────────────┘
```

---

**Last Updated**: November 2025  
**Version**: 2.2.0  
**Maintained By**: Open Security Compliance Team

---

## Changelog

### Version 2.2.0 (Current)
- ✨ **Automatic Claude model detection** from API key
- ✨ **Enhanced MinIO credential validation** (username ≥3, password ≥8)
- ✨ **Improved API key validation** with live authentication test
- ✨ **MCP service settle time** (20 seconds) for stable startup
- ✨ **Auto-detection of Docker sudo requirement**
- ✨ **Automatic GOOSE_MODEL configuration** in userconfig.env
- 🔧 Enhanced error messages for credential validation
- 🔧 Support for password confirmation during setup
- 🔧 Better handling of invalid credentials (removal + re-prompt)
- 🔧 Model fallback logic (4.5 → 4) with clear messaging
- 📚 Updated documentation for all new features

### Version 2.1.0
- Initial unified MCP + No-Code UI setup
- Support for 7 services deployment
- Localhost SSL certificates included
- Basic API key validation