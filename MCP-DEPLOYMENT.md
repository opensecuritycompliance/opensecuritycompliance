# Open Security Compliance Rule Engine Setup Guide

Complete setup documentation for deploying Open Security Compliance Rule Engine with integrated No-Code UI and MCP capabilities.

> **Don't have an Anthropic API key?** You can still use the No-Code web interface without any AI features.
> The setup script offers two modes — see [Setup Modes](#setup-modes) below, or jump directly to the **[No-Code UI Deployment Guide](NOCODE-DEPLOYMENT.md)**.

---

## Table of Contents (Detailed Documentation)

For more detailed information, see the following sections:

- [Setup Modes](#setup-modes)
- [Overview](#overview)
- [Quick Start Guide](#quick-start-guide)
- [Appendix](#appendix)

---

## Setup Modes

The setup script (`setup.sh`) presents two options at startup:

| Mode | Anthropic API Key | Services | Guide |
|------|-------------------|----------|-------|
| **1) MCP + No-Code UI** | Required | 7 services (oscmcpservice, ccowmcpclient, ccowmcpbridge, oscwebserver, oscreverseproxy, oscapiservice, cowstorage) | This document |
| **2) No-Code UI Only** | Not required | 4 services (oscapiservice, oscreverseproxy, oscwebserver, cowstorage) | [NOCODE-DEPLOYMENT.md](NOCODE-DEPLOYMENT.md) |

Choose **Option 1** if you have a valid Anthropic API key and want AI-powered rule creation via MCP alongside the No-Code web interface. The rest of this document covers this mode.

Choose **Option 2** if you don't have an Anthropic API key or only need the No-Code web interface for manual rule creation. See the **[No-Code UI Deployment Guide](NOCODE-DEPLOYMENT.md)** for details.

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

### AI Model Support

This platform **automatically detects and uses the best available Claude model** from your Anthropic API key:
- **Provider**: Anthropic Claude only
- **Supported Models**: Claude Sonnet 4.5, Claude Sonnet 4
- **Auto-Detection**: Setup script tests your API key and configures the highest available model
- **Note**: Other providers (OpenAI, etc.) are not supported at this time


---

## Quick Start Guide

### Pre-requisites:

 - Docker (Steps to install can be found in the [Appendix](#1-docker-installation) below)
 - Anthropic key — required for MCP mode only (Steps to procure one can be found in the [Appendix](#2-anthropic-api-key-procurement) below)
 - System Requirements
   - CPU: 8+ cores
   - RAM: 16GB+
   - Disk: 30GB+ SSD
   - Docker: 20.10+
   - Docker Compose: 2.0+

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/opensecuritycompliance/opensecuritycompliance.git

# Navigate to the project directory
cd opensecuritycompliance
```

### Step 2: Run the Setup Script

The setup script will guide you through the entire installation process, including:
- ✅ Asking you to choose a setup mode (MCP + No-Code UI **or** No-Code UI Only)
- ✅ Checking system requirements
- ✅ Validating your Anthropic API key (MCP mode only)
- ✅ Auto-detecting the best available Claude model (MCP mode only)
- ✅ Configuring MinIO storage credentials
- ✅ Setting up all required services
- ✅ Starting the platform
More details can be found in the Appendix below.

For troubleshooting any issues you may encounter while running the script below, please refer to the **“Common Setup Issues and Solutions”** section in the Appendix.


```bash
# Make the setup script executable
chmod +x setup.sh

# Run the setup
sudo ./setup.sh
```

**That's it!** The setup script will handle everything else automatically.

---
## Appendix

### 1. Docker installation

Before running the setup script, ensure Docker is installed:

#### Linux
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Verify installation
docker --version
docker compose version
```

#### macOS
```bash
# Download and install Docker Desktop from:
# https://docs.docker.com/desktop/install/mac-install/

# Verify installation
docker --version
docker compose version
```

#### Windows (WSL2)
```bash
# Install WSL2 first
wsl --install

# Download and install Docker Desktop from:
# https://docs.docker.com/desktop/install/windows-install/

# Verify installation in WSL2
docker --version
docker compose version
```

---

### 2. Anthropic API Key Procurement

You'll need an Anthropic API key for AI-assisted features. The setup script will automatically detect and configure the best available Claude model from your key.

**How to get your API key:**

1. Visit [console.anthropic.com](https://console.anthropic.com/)
2. Sign up or log in to your account
3. Navigate to "API Keys" in the left sidebar
4. Click "Create Key" button
5. Give your key a name (e.g., "Open Security Compliance")
6. **Copy the key immediately** (it won't be shown again)

Your API key will look like: `sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX...`

**Note:** The setup script will validate your key and automatically detect the best Claude model you have access to (Claude Sonnet 4.5 or Claude Sonnet 4).

**Note:** The setup script will check your system and warn you if requirements aren't met.

---

### 3. What the Setup Script (setup.sh) does

The script will automatically:

1. ✅ Ask you to choose a setup mode (MCP + No-Code UI or No-Code UI Only)
2. ✅ Check Docker installation and access (detects if sudo is needed)
3. ✅ Validate system resources (CPU, RAM, disk)
4. ✅ Prompt for your Anthropic API key if not configured (MCP mode only)
5. ✅ Validate your API key against Anthropic's API (MCP mode only)
6. ✅ Auto-detect the best available Claude model (MCP mode only)
7. ✅ Save the detected model to configuration (MCP mode only)
8. ✅ Prompt for MinIO credentials (validates requirements)
9. ✅ Verify SSL certificates (uses localhost certs by default)
10. ✅ Check environment configuration files
11. ✅ Clean up existing Docker resources
12. ✅ Build Docker images for the selected mode
13. ✅ Start services in the correct order
14. ✅ Wait for services to be healthy
15. ✅ Display access URLs and next steps

#### Expected Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Open Security Compliance MCP + No-Code UI Setup         ║
║                   (WITH SUDO SUPPORT)                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════
  Choose your setup mode
════════════════════════════════════════════════════════════

  1) MCP + No-Code UI  (Requires a valid Anthropic API key)
  2) No-Code UI Only   (No Anthropic API key needed)

Select setup mode [1/2]: 1

[INFO] Selected: MCP + No-Code UI (full setup)

[INFO] Checking Anthropic API key...
[INFO] Validating Anthropic API key...
[SUCCESS] Anthropic API key is valid

[INFO] Detecting best available Claude model...
[SUCCESS] Claude Sonnet 4.5 access confirmed
[SUCCESS] Best available model: Claude Sonnet 4.5

[INFO] Checking MinIO credentials...
[SUCCESS] MinIO credentials validated successfully

[SUCCESS] Setup completed successfully!

Access URLs:
  - Web UI (HTTPS): https://localhost:443
  - Web UI (HTTP): http://localhost:3001
  - API Service: http://localhost:9080
  - MinIO Console: http://localhost:9001
  - MCP Service: http://localhost:45678

AI Model Configuration:
  - Provider: Anthropic only
  - Detected Model: Claude Sonnet 4.5
  - Model ID: claude-sonnet-4-5-20250929
```

---

### 4. Common Setup Issues and Solutions

#### 4.1. Docker "credsStore" Error (macOS with older Docker versions)

**Error Message:**
```
Error loading metadata for library...
```

**Solution:**

In case you run into any errors related to loading metadata for certain libraries, rename the key `credsStore` to `credStore` in the docker config file in your system (For instance in Mac: `~/.docker/config.json`). This is a known issue in Docker.

```bash
# Edit Docker config file
nano ~/.docker/config.json

# Change "credsStore" to "credStore" (note the lowercase 's')
# Before:
{
  "credsStore": "desktop"
}

# After:
{
  "credStore": "desktop"
}

# Save the file and restart Docker Desktop
```

**Note:** You may have to restart Docker after making this change.

#### 4.2. Permission Denied When Running Docker

**Error Message:**
```
permission denied while trying to connect to the Docker daemon socket
```

**Solution:**

The setup script automatically detects if you need sudo and will use it. However, if you want to avoid using sudo:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Log out and log back in for changes to take effect
# Then verify:
docker ps
```

#### 4.3. Invalid API Key

**Error Message:**
```
[ERROR] Anthropic API key validation failed
```

**Solution:**

The setup script will prompt you to re-enter your API key. Make sure:
1. You copied the complete key (starts with `sk-ant-`)
2. The key is active (not expired or revoked)
3. Your key has access to at least Claude Sonnet 4

#### 4.4. MinIO Credential Requirements Not Met

**Error Message:**
```
[ERROR] MinIO username must be at least 3 characters long
[ERROR] MinIO password must be at least 8 characters long
```

**Solution:**

The setup script will prompt you again. Ensure:
- Username: At least 3 characters, no spaces
- Password: At least 8 characters, no spaces
- Password confirmation matches

#### 4.5. Insufficient System Resources

**Warning Message:**
```
[WARNING] System has less than 16GB RAM
```

**Solution:**

You can continue, but performance may be degraded. For production use:
- Use a machine with 16GB+ RAM
- Consider cloud hosting (AWS, GCP, Azure)
- Close other resource-intensive applications

---

### 5. Next Steps After Installation

#### 5.1. Access the Web UI

Open your browser and navigate to:
```
https://localhost:443
```

**Note:** You may see a security warning for the self-signed certificate. Click "Advanced" and "Proceed to localhost (unsafe)" to continue.

#### 5.2. Choose Your Rule Creation Method

The platform offers three ways to create compliance rules:

#### Option A: Manual UI (No AI)
- Traditional visual interface
- Step-by-step guided configuration
- No AI assistance required

#### Option B: AI-Assisted via Web UI (MCP Mode)
- Built-in AI assistant
- Conversational rule creation
- No external tools needed
- Uses your auto-detected Claude model

#### Option C: External AI Clients (Optional)
- Goose Desktop or Goose CLI
- Claude Desktop or Claude Code
- Requires additional setup (see Appendix A)

**Recommendation for beginners:** Start with Option B (AI-Assisted via Web UI) - it's the easiest way to create rules!

#### 5.3. Verify Services Are Running

```bash
# Check service status
docker compose ps

# You should see 7 services running:
# - oscwebserver (Web UI)
# - oscreverseproxy (Reverse Proxy)
# - oscapiservice (API Service)
# - cowstorage (MinIO Storage)
# - ccowmcpclient (MCP Client Integration)
# - ccowmcpbridge (MCP Bridge Service)
# - oscmcpservice (MCP Service)
```

#### 5.4. Check Your Configuration

```bash
# View your detected Claude model
cat etc/userconfig.env | grep MCP_MODEL

# View MinIO credentials (for console access)
cat etc/policycow.env | grep MINIO_ROOT
```

---

## 6. Managing Your Installation

### Viewing Logs

```bash
# View all service logs
docker compose logs -f

# View specific service logs
docker compose logs -f oscapiservice
docker compose logs -f oscmcpservice
```

### Stopping Services

```bash
# Stop all services
docker compose down
```

### Restarting Services

```bash
# Restart all services
docker compose restart

# Restart specific service
docker compose restart oscmcpservice
```

### Updating the Platform

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose down
docker compose build --no-cache
./setup.sh
```


---

### 7. Architecture Overview

#### Unified Platform Architecture

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
             │                    │  MCP Bridge      │
             │                    │  ccowmcpbridge   │
             │                    │  Port: 8095      │
             │                    └────────┬─────────┘
             │                             │
             │                             ▼
             │                    ┌──────────────────┐
             │                    │  MCP Client      │
             │                    │  ccowmcpclient   │
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
                           ▼                         │  (Optional)        │
                  ┌─────────────────┐                └────────────────────┘
                  │  API Service    │
                  │  oscapiservice  │
                  │  Port: 9080     │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Storage        │
                  │  cowstorage     │
                  │  MinIO:9000/9001│
                  └─────────────────┘
```

#### Rule Creation Flows

##### Flow 1: Manual UI Rule Creation
```
User → Web UI (Manual Mode) → Reverse Proxy → API Service → Storage
```

##### Flow 2: AI-Assisted Rule Creation via UI (MCP Mode)
```
User → Web UI (MCP Mode) → Reverse Proxy → MCP Bridge → MCP Client → MCP Service → API Service → Storage
```

##### Flow 3: External MCP Clients (Optional)
```
External MCP Clients (Goose/Claude) → MCP Service (port 45678) → API Service → Storage
```

---

### 8. Services Overview

The platform consists of 7 interconnected services:

| Service | Purpose | Ports | Notes |
|-----------|-------------|-----------|-------------|
| cowstorage (MinIO) | Object storage for rules, data, and artifacts | 9000 (API), 9001 (Console) | Credentials: Configured during setup (validated) |
| oscapiservice | REST API for rule management and execution  | 9080 | Responsibilities: Rule CRUD, task management, rule execution |
| oscwebserver | React-based web interface | 3001 | Features: Visual rule builder, AI-assisted creation, execution dashboard |
| oscreverseproxy | HTTPS termination and routing | 443 (HTTPS), 80 (HTTP) | SSL: Localhost certificates included by default
| ccowmcpbridge | MCP orchestration layer | 8095 | Features: Bridges UI requests to MCP infrastructure |
| ccowmcpclient | MCP client integration | 8976 | Provider: Anthropic Claude (auto-detected model) |
| oscmcpservice | Model Context Protocol server | 45678 | Features: MCP protocol implementation, external client connections |

---

### 9. Configuration Details

#### Environment Variables

The platform uses two main configuration files:

##### `etc/userconfig.env` (User Settings)
```bash

# Anthropic API Key (set during setup)
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx

# Auto-detected Claude Model (set by setup script)
MCP_MODEL=claude-sonnet-4-5-20250929
```

##### `etc/policycow.env` (Platform Settings)
```bash
# MinIO Credentials (set during setup)
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin

# Storage Configuration
COW_DATA_PERSISTENCE_TYPE=minio
MINIO_ENDPOINT=cowstorage:9000

# Application Settings
APP_ENV=production
LOG_LEVEL=info
```

#### Directory Structure

After setup, your directory structure will look like this:

```
opensecuritycompliance/
├── setup.sh                    # Setup script
├── docker-compose-osc.yaml         # Docker Compose configuration
├── export_env.sh                   # Environment export script
│
├── etc/                            # Configuration files
│   ├── userconfig.env             # User configuration
│   ├── policycow.env              # Platform configuration
│   └── .credentials.env           # External credentials (optional)
│
├── src/                            # Source code
│   └── oscreverseproxy/
│       └── certs/                 # SSL certificates
│           ├── fullchain.pem      # Certificate chain
│           └── privkey.pem        # Private key
│
├── catalog/                        # Rule catalog
├── exported-data/                  # Exported compliance data
├── mcp-config/                   # mcp configuration
└── mcp-sessions/                 # mcp session data
```

---

### 10. Troubleshooting Guide

#### Service Won't Start

```bash
# Check logs
docker compose logs <service-name>

# Verify configuration
cat etc/userconfig.env
cat etc/policycow.env

# Restart service
docker compose restart <service-name>
```

#### MCP Connection Issues

```bash
# Verify MCP service is running
docker ps | grep oscmcpservice

# Check MCP service logs
docker compose logs oscmcpservice

# Restart MCP stack
docker compose restart oscmcpservice
sleep 20  # Wait for settle time
docker compose restart ccowmcpclient ccowmcpbridge
```

#### API Key or Model Issues

```bash
# Check current configuration
cat etc/userconfig.env | grep ANTHROPIC_API_KEY
cat etc/userconfig.env | grep MCP_MODEL

# Re-run setup to re-detect model
./setup.sh
```

#### MinIO Credential Issues

```bash
# Check current credentials
cat etc/policycow.env | grep MINIO_ROOT

# Update credentials (must meet requirements)
nano etc/policycow.env

# Or re-run setup for validation
./setup.sh

# Restart storage
docker compose restart cowstorage
```

---

## 11. External MCP Clients Setup (Optional)

**⚠️ Note:** This section is completely optional. The Web UI provides full AI-assisted functionality without external clients.

#### Installing Goose (Optional)

For detailed installation instructions, visit the official guide:
**🔗 [Goose Installation Guide](https://block.github.io/goose/docs/getting-started/installation)**

Quick installation options:

**Goose Desktop (Recommended for beginners):**
- Download from the installation guide
- Available for macOS, Windows, and Linux
- Provides graphical interface

**Goose CLI (For advanced users):**
```bash
# Install via pip
pip install goose-ai

# Or via pipx (recommended)
pipx install goose-ai

# Verify installation
goose --version
```

#### Configuring Goose Desktop (Optional)

##### Step 1: Locate Configuration Directory

```bash
# macOS/Linux
~/.config/goose/

# Windows
%USERPROFILE%\.config\goose\
```

##### Step 2: Create Configuration File

```bash
# macOS/Linux
mkdir -p ~/.config/goose
nano ~/.config/goose/config.yaml

# Windows (PowerShell)
mkdir -Force $env:USERPROFILE\.config\goose
notepad $env:USERPROFILE\.config\goose\config.yaml
```

##### Step 3: Add Configuration

```yaml
# Goose Configuration for Open Security Compliance

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
        "IS_OSC_CCOW_MCP_CLIENT": true
      }
      env_keys: []
      headers: {}
      timeout: 300

provider: anthropic

# Check your GOOSE_MODEL in etc/userconfig.env and match it here
model: claude-sonnet-4-5-20250929  # Update to match your detected model
```

##### Step 4: Verify Your Model

```bash
# Check your detected model
cat etc/userconfig.env | grep GOOSE_MODEL

# Update config.yaml to match this model
nano ~/.config/goose/config.yaml
```

##### Step 5: Set API Key

```bash
# macOS/Linux (add to ~/.bashrc or ~/.zshrc)
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx

# Windows (PowerShell - add to $PROFILE)
$env:ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"
```

##### Step 6: Test Connection

1. Start the Open Security Compliance platform
2. Launch Goose Desktop
3. Type: `What MCP tools are available?`
4. You should see compliance-related tools listed

#### Configuring Goose CLI (Optional)

Follow the same steps as Goose Desktop, then:

```bash
# Start interactive session
goose session start

# Run a command
goose run "List all available compliance tasks"
```

#### Configuring Claude Desktop/Code (Optional)

**Note:** Claude Desktop and Claude Code require file-based MCP configuration. For detailed setup instructions, please refer to:
**🔗 [Anthropic MCP Documentation](https://docs.anthropic.com/claude/docs/mcp)**

---

### 12. Custom SSL Certificates (Optional)

**✅ Default:** The repository includes localhost certificates. This section is only needed for custom domains.

#### Certificate Locations

Place your certificates in one of these locations:

**Option A (Recommended):**
```bash
src/oscreverseproxy/certs/
├── fullchain.pem
└── privkey.pem
```

**Option B:**
```bash
${HOME}/continube/certs/
├── fullchain.pem
└── privkey.pem
```

#### Getting Certificates from Let's Encrypt

```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem src/oscreverseproxy/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem src/oscreverseproxy/certs/

# Set permissions
sudo chmod 644 src/oscreverseproxy/certs/fullchain.pem
sudo chmod 600 src/oscreverseproxy/certs/privkey.pem

# Restart reverse proxy
docker compose restart oscreverseproxy
```

#### Certificate Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Setup automatic renewal
sudo systemctl enable certbot-renew.timer
sudo systemctl start certbot-renew.timer
```

---

### 13. Advanced Configuration

#### Port Configuration

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
```

#### Data Backup

```bash
# Create backup directory
mkdir -p ${HOME}/policycow-backups/$(date +%Y%m%d)

# Backup MinIO data
cp -r ${HOME}/tmp/cowctl/minio \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/minio

# Backup CCowMCPClient sessions
cp -r mcp-sessions \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/mcp-sessions

# Backup catalogs
cp -r catalog \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/catalog

# Backup environment files
cp etc/policycow.env \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/
```

---

### 14. FAQ

**Q: Do I need an Anthropic API key to use this platform?**
A: No. The setup script offers two modes. If you don't have an Anthropic API key, choose **Option 2 (No-Code UI Only)** to use just the web interface without AI features. See the [No-Code UI Deployment Guide](NOCODE-DEPLOYMENT.md).

**Q: Do I need to be technical to use this platform?**
A: No! The setup script handles all technical details automatically. Just follow the Quick Start Guide.

**Q: What AI models are supported?**
A: Only Anthropic Claude (MCP mode). The setup script automatically detects the best model your API key has access to (Claude Sonnet 4.5 or Claude Sonnet 4).

**Q: Do I need to install external tools like Goose?**
A: No! The Web UI has built-in AI assistance (MCP mode). External tools like Goose are completely optional.

**Q: What if I don't have enough RAM?**  
A: The setup script will warn you but allow you to continue. For best performance, use a machine with 16GB+ RAM or consider cloud hosting.

**Q: Can I use this in production?**  
A: The platform is designed for development and testing. For production use, you'll need to:
- Change default MinIO credentials (setup validates this)
- Consider custom SSL certificates for your domain
- Review security settings
- Plan for scaling and high availability

**Q: How do I get help?**  
A: Check the Troubleshooting Guide section, review logs with `docker compose logs`, or visit the GitHub repository for issues and discussions.

**Q: Where are my rules and data stored?**  
A: All data is stored in MinIO (object storage) at `${HOME}/tmp/cowctl/minio/`. Make sure to backup this directory regularly.

**Q: Can I use a different AI provider?**
A: No, currently only Anthropic Claude is supported for MCP mode. Other providers like OpenAI are not available at this time. If you don't have access to Anthropic, you can use the No-Code UI Only mode instead.

---

### 15. Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                     QUICK REFERENCE                         │
├─────────────────────────────────────────────────────────────┤
│ Initial Setup:                                              │
│  git clone https://github.com/opensecuritycompliance/...    │
│  cd opensecuritycompliance                                  │
│  chmod +x setup.sh                                      │
│  ./setup.sh                                             │
│                                                             │
│ Access URLs:                                                │
│  https://localhost:443   - Web UI (HTTPS)                   │
│  http://localhost:9001   - MinIO Console                    │
│  http://localhost:45678/mcp - MCP Service                   │
│                                                             │
│ AI Configuration:                                           │
│  Provider: Anthropic only                                   │
│  Models: Auto-detected (Sonnet 4.5 or 4)                    │
│  Config: etc/userconfig.env (MCP_MODEL)                     │
│                                                             │
│ Useful Commands:                                            │
│  docker compose logs -f              - View all logs        │
│  docker compose ps                   - Service status       │
│  docker compose down                 - Stop services        │
│  docker compose restart              - Restart all          │
│                                                             │
│ Check Configuration:                                        │
│  cat etc/userconfig.env | grep MCP_MODEL                    │
│  cat etc/policycow.env | grep MINIO_ROOT                    │
│                                                             │
│ Important Notes:                                            │
│  ⚠️  Setup script handles everything automatically          │
│  ⚠️  External MCP clients are optional                      │
│  ⚠️  Change MinIO credentials for production                │
│  ⚠️  Backup data regularly from MinIO storage               │
└─────────────────────────────────────────────────────────────┘
```

---

**Last Updated**: February 2026
**Version**: 2.3.0  
**Maintained By**: Open Security Compliance Team  
**Repository**: https://github.com/opensecuritycompliance/opensecuritycompliance