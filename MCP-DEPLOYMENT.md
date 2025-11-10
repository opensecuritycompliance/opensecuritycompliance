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

This platform currently supports:
- **Provider**: Anthropic Claude only
- **Maximum Model**: Claude Sonnet 4
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

You'll need an Anthropic API key to use the AI-assisted features. This platform supports **Anthropic Claude only** with a maximum model of **Claude Sonnet 4**.

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

4. **Important Notes**
   - ⚠️ Keep your API key secure and never share it
   - ⚠️ Never commit API keys to version control
   - ⚠️ The setup script will validate your key before proceeding
   - 💡 You can add funds or set up billing in the Anthropic Console

### 3. Download and Install Goose (For External MCP Access)

Goose is an AI assistant that can connect to the Open Security Compliance platform for conversational rule creation. You have two options:

#### Option A: Goose Desktop (Recommended for Beginners)

**Download Goose Desktop:**
- Visit the official Goose releases page: [https://github.com/block/goose/releases](https://github.com/block/goose/releases)
- Download the appropriate version for your operating system:
  - **macOS**: `Goose-darwin-x64.dmg` or `Goose-darwin-arm64.dmg` (Apple Silicon)
  - **Windows**: `Goose-win32-x64.exe`
  - **Linux**: `Goose-linux-x64.AppImage`

**Installation Steps:**

**macOS:**
```bash
# 1. Download the .dmg file for your architecture
# 2. Open the .dmg file
# 3. Drag Goose to your Applications folder
# 4. Open Goose from Applications (you may need to allow it in System Preferences > Security)
```

**Windows:**
```bash
# 1. Download the .exe installer
# 2. Run the installer
# 3. Follow the installation wizard
# 4. Launch Goose from the Start menu
```

**Linux:**
```bash
# 1. Download the .AppImage file
# 2. Make it executable
chmod +x Goose-linux-x64.AppImage

# 3. Run the AppImage
./Goose-linux-x64.AppImage
```

#### Option B: Goose CLI (For Advanced Users)

**Installation via pip:**
```bash
# Install Goose CLI
pip install goose-ai

# Verify installation
goose --version
```

**Installation via pipx (recommended):**
```bash
# Install pipx if you don't have it
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install Goose via pipx
pipx install goose-ai

# Verify installation
goose --version
```

**Note**: The CLI requires Python 3.8 or higher.

### 4. SSL Certificates (Required for HTTPS)

You need SSL certificates for the reverse proxy to serve HTTPS traffic.

#### Option A: Place in Repository
```bash
mkdir -p src/oscreverseproxy/certs
cp /path/to/your/fullchain.pem src/oscreverseproxy/certs/
cp /path/to/your/privkey.pem src/oscreverseproxy/certs/
```

#### Option B: Place in Home Directory
```bash
mkdir -p ${HOME}/continube/certs
cp /path/to/your/fullchain.pem ${HOME}/continube/certs/
cp /path/to/your/privkey.pem ${HOME}/continube/certs/
```

**Required Files:**
- `fullchain.pem` - Complete certificate chain
- `privkey.pem` - Private key file

#### How to Get SSL Certificates

**Free Options:**
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates
- [Certbot](https://certbot.eff.org/) - Automated Let's Encrypt client

```bash
# Example: Using Certbot
sudo apt-get install certbot
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in /etc/letsencrypt/live/yourdomain.com/
```

### 5. Environment Configuration Files

Create the required environment configuration files:

```bash
mkdir -p etc
```

#### `etc/userconfig.env` (User Configuration)
```bash
# User-specific configuration
# Add your custom environment variables here

# Example configurations:
USER_EMAIL=admin@example.com
USER_TIMEZONE=UTC

# Anthropic API key (will be added by script if not present)
# ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx
```

#### `etc/policycow.env` (Platform Configuration)
```bash
# Open Security Compliance platform configuration
# MinIO credentials
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin

# Storage configuration
COW_DATA_PERSISTENCE_TYPE=minio
MINIO_ENDPOINT=cowstorage:9000

# Application settings
APP_ENV=production
LOG_LEVEL=info
```

#### `etc/.credentials.env` (Optional - Sensitive Credentials)
```bash
# Sensitive credentials for external integrations
# This file is optional and used by cowctl service

# Example:
# AWS_ACCESS_KEY_ID=xxxxxxxxxxxxx
# AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxx
# GITHUB_TOKEN=xxxxxxxxxxxxx
```

---

## Directory Structure

After setup, your directory structure will look like this:

```
policycow/
├── setup-mcp.sh                    # Unified setup script (handles both UI and MCP)
├── docker-compose.yaml             # Docker Compose service definitions
├── export_env.sh                   # Environment variable export script (optional)
│
├── etc/                            # Configuration files
│   ├── userconfig.env             # User configuration (REQUIRED)
│   ├── policycow.env              # Platform configuration (REQUIRED)
│   └── .credentials.env           # Sensitive credentials (OPTIONAL)
│
├── src/                            # Source code (if building locally)
│   └── oscreverseproxy/           # Reverse proxy source
│       └── certs/                 # SSL certificates location (OPTION 1)
│           ├── fullchain.pem
│           └── privkey.pem
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
    ├── continube/certs/           # SSL certificates (OPTION 2)
    │   ├── fullchain.pem
    │   └── privkey.pem
    └── tmp/cowctl/minio/          # MinIO data storage
```

**Note**: This deployment uses pre-built Docker images from GitHub Container Registry. No local Dockerfiles are required.

---

## Setup Process

### Unified Setup Script

The platform now uses a single script that handles both No-Code UI and MCP capabilities.

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
# 1. Make script executable
chmod +x setup-mcp.sh

# 2. Run setup
./setup-mcp.sh
```

#### What the Script Does

1. ✅ Checks Docker installation and access
2. ✅ Validates system resources (CPU, RAM, disk)
3. ✅ Checks for Anthropic API key
4. ✅ Validates API key format (sk-ant-...)
5. ✅ Tests API key against Anthropic API
6. ✅ Saves API key to `etc/userconfig.env`
7. ✅ Verifies SSL certificates
8. ✅ Checks environment configuration files
9. ✅ Sources environment variables from `etc/userconfig.env`
10. ✅ Runs `export_env.sh` if present
11. ✅ Cleans up existing containers and images
12. ✅ Creates necessary directories including Goose sessions
13. ✅ Builds all Docker images
14. ✅ Starts all services
15. ✅ Waits for services to be healthy
16. ✅ Displays access URLs and commands

#### Expected Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    Open Security Compliance MCP + No-Code UI Setup        ║
║                   (WITH SUDO SUPPORT)                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Starting Open Security Compliance Setup...
[INFO] Checking Anthropic API key...
[SUCCESS] Anthropic API key is valid
...
[SUCCESS] Setup completed successfully!

Access URLs:
  - Web UI: https://localhost:443
  - Web UI (HTTP): http://localhost:3001
  - API Service: http://localhost:9080
  - MinIO Console: http://localhost:9001
  - Goose Service: http://localhost:8095
  - Goose Web: http://localhost:8976
  - MCP Service: http://localhost:45678

Configuration:
  - Provider: Anthropic only
  - Maximum Model: Claude Sonnet 4
  - Goose Sessions: ./goose-sessions/sessions
  - API Key: Configured (from environment)
```

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

# Custom application settings
CUSTOM_VAR1=value1
CUSTOM_VAR2=value2
```

**Loaded by**: Setup script automatically sources this file at startup

#### Platform Configuration (`etc/policycow.env`)
```bash
# MinIO Configuration
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_ENDPOINT=cowstorage:9000

# Storage
COW_DATA_PERSISTENCE_TYPE=minio

# Application
APP_ENV=production
LOG_LEVEL=info
```

**Loaded by**: Docker Compose via `env_file` directive

### Port Configuration

Default ports can be changed in `docker-compose.yaml`:

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
**Default Credentials**:
- Username: `minioadmin`
- Password: `minioadmin`

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
**Maximum Model**: Claude Sonnet 4  
**Session Storage**: `./goose-sessions/sessions`

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

---

## Connecting MCP Clients

### Overview

The platform provides two ways to use MCP for AI-assisted rule creation:

#### 1. Via Web UI (MCP Mode)
Access AI-assisted rule creation directly from the web interface:
- Navigate to the MCP mode in the Web UI
- Requests route through: Web UI → Reverse Proxy → Goose Service → MCP Service → API Service
- No additional configuration needed

#### 2. Via External MCP Clients (Goose or Claude)
Connect external AI clients directly to the MCP service at `http://localhost:45678/mcp`:
- **Goose Desktop/CLI** - Full configuration instructions provided below
- **Claude Desktop/Code** - Requires file-based configuration (see Anthropic docs)

External clients bypass the reverse proxy and connect directly to port 45678.

### Capabilities

With MCP integration (UI or external clients), you can:
- Create and manage compliance rules via natural language
- Query existing rules and configurations
- Execute compliance checks through conversational interface
- Get guidance on rule creation and best practices

**Note**: This platform uses **Anthropic Claude only** with a maximum model of **Claude Sonnet 4**.

### Supported External MCP Clients

The following external MCP clients are supported:
- **Goose Desktop** - Graphical desktop application (recommended)
- **Goose CLI** - Command-line interface
- **Claude Desktop** - Anthropic's desktop application (requires manual MCP configuration)
- **Claude Code** - VS Code extension for Claude (requires manual MCP configuration)

**Note**: Claude Desktop and Claude Code require file-based MCP configuration. For detailed setup instructions, please refer to the official Anthropic documentation.

---

## Configuring Goose Desktop

### Prerequisites
- Goose Desktop installed (see [Download and Install Goose](#3-download-and-install-goose-for-external-mcp-access))
- Open Security Compliance platform running (setup completed)
- Anthropic API key configured

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
model: claude-sonnet-4-20250514  # Claude Sonnet 4 (maximum supported model)

# API Key (optional - can also be set via environment variable)
# anthropic_api_key: sk-ant-xxxxxxxxxxxxx
```

**Important Configuration Notes:**

1. **MCP Server URI**: `http://localhost:45678/mcp`
   - This connects to your local Open Security Compliance MCP service
   - Make sure the platform is running before connecting

2. **Provider**: Set to `anthropic` (only provider supported)

3. **Model**: Set to `claude-sonnet-4-20250514` (Claude Sonnet 4)
   - This is the maximum model supported by the platform
   - Do not change this to other models

4. **API Key**: You can either:
   - Set `ANTHROPIC_API_KEY` environment variable (recommended)
   - Add `anthropic_api_key` to this config file (less secure)

#### Step 4: Set API Key (If Not Using Environment Variable)

If you haven't set the `ANTHROPIC_API_KEY` environment variable, you can add it to the config:

```yaml
anthropic_api_key: sk-ant-xxxxxxxxxxxxx
```

**Security Warning**: Config files may be readable by other users. Environment variables are more secure.

#### Step 5: Launch Goose Desktop

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

#### Step 6: Test the Connection

Try creating a simple rule:
```
Create a compliance rule that checks if all EC2 instances have encryption enabled
```

Goose should:
1. Connect to the MCP service
2. Understand your request
3. Create the rule using the Open Security Compliance API
4. Confirm the rule creation

---

## Configuring Goose CLI

### Prerequisites
- Goose CLI installed via pip or pipx (see [Download and Install Goose](#3-download-and-install-goose-for-external-mcp-access))
- Open Security Compliance platform running
- Anthropic API key configured

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

Use the same configuration as Goose Desktop:

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
        "OSC_GOOSE":true
      }
      env_keys: []
      headers: {}
      timeout: 300

provider: anthropic
model: claude-sonnet-4-20250514  # Claude Sonnet 4 (maximum supported)
```

#### Step 4: Set API Key Environment Variable

```bash
# macOS/Linux (add to ~/.bashrc or ~/.zshrc)
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx

# Windows (PowerShell - add to $PROFILE)
$env:ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"

# Or set it temporarily in current session
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx  # macOS/Linux
$env:ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"  # Windows
```

#### Step 5: Launch Goose CLI

```bash
# Start a new Goose session
goose session start

# Or run a specific command
goose run "What MCP tools are available?"
```

#### Step 6: Verify MCP Connection

```bash
goose run "List all available compliance tasks"
```

You should see output showing the MCP tools and tasks from the Open Security Compliance platform.

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

# Test MCP endpoint manually
curl http://localhost:45678/mcp
```

#### 2. "Invalid API Key" Error

**Cause**: Anthropic API key is missing or invalid

**Solution**:
```bash
# Verify API key is set
echo $ANTHROPIC_API_KEY

# Test API key manually
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
```

#### 3. Connection Timeout

**Cause**: Network issues or service not responding

**Solution**:
```bash
# Check if all services are healthy
docker compose ps

# Restart MCP service
docker compose restart oscmcpservice oscgoose oscgooseservice

# Increase timeout in config.yaml
timeout: 600  # Increase from 300 to 600 seconds
```

#### 4. "Model Not Supported" Error

**Cause**: Trying to use a model other than Claude Sonnet 4

**Solution**:
```yaml
# Update config.yaml to use correct model
model: claude-sonnet-4-20250514  # Use this exact model string
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
- Create rules via MCP assistant (AI-powered)
- Execute compliance checks
- View execution results
- Manage applications

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
```

#### MinIO Console
```
URL: http://localhost:9001
Username: minioadmin
Password: minioadmin
```

#### MCP Service (For External Clients)
```
URL: http://localhost:45678/mcp
```

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
```

#### Stop Services
```bash
docker compose down
```

#### Restart Services
```bash
docker compose restart
```

#### Check Service Status
```bash
docker compose ps
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

# Restart service
docker compose restart <service-name>
```

#### 2. MCP Connection Issues
```bash
# Verify MCP service is running
docker ps | grep oscmcpservice

# Check MCP service logs
docker compose logs oscmcpservice

# Restart MCP stack
docker compose restart oscmcpservice oscgoose oscgooseservice
```

#### 3. Anthropic API Key Invalid
```bash
# Test key manually
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'

# Re-add key to environment
nano etc/userconfig.env

# Restart services
docker compose restart
```

#### 4. Goose Desktop/CLI Can't Connect

**Check Platform Status:**
```bash
# Verify all services are running
docker compose ps

# Check MCP service specifically
docker compose logs oscmcpservice

# Test MCP endpoint
curl http://localhost:45678/mcp
```

**Verify Configuration:**
```bash
# Check Goose config file
cat ~/.config/goose/config.yaml

# Verify API key
echo $ANTHROPIC_API_KEY
```

**Restart Everything:**
```bash
# Restart platform
docker compose restart

# Close and reopen Goose Desktop/CLI
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
- ✅ **Maximum Model**: Claude Sonnet 4
- ❌ **No OpenAI/Other Providers**: Platform is Anthropic-specific

### MCP Client Support
- ✅ **Goose Desktop**: Fully supported with detailed configuration below
- ✅ **Goose CLI**: Fully supported with detailed configuration below
- ✅ **Claude Desktop**: Supported (requires file-based MCP config - see Anthropic docs)
- ✅ **Claude Code**: Supported (requires file-based MCP config - see Anthropic docs)
- ❌ **No OpenAI/Other Providers**: Platform is Anthropic-specific

### Security Considerations
- ⚠️ **SSL Required**: Strongly recommended for production
- ⚠️ **Default Credentials**: Change MinIO default credentials
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

# Backup environment files
cp -r etc \
   ${HOME}/policycow-backups/$(date +%Y%m%d)/etc
```

### Update Services
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## FAQ

### General Questions

**Q: What is Open Security Compliance?**  
A: Open Security Compliance is a comprehensive rule engine platform for creating and managing compliance rules through manual UI, AI-assisted UI (MCP mode), or external AI clients (Goose).

**Q: How many ways can I create rules?**  
A: Three ways:
1. Manual through Web UI (traditional visual builder)
2. AI-assisted through Web UI (MCP mode via reverse proxy)
3. AI-assisted through external clients (Goose Desktop or Goose CLI connecting directly to port 45678)

**Q: What AI models are supported?**  
A: Only **Anthropic Claude** is supported, with a maximum model of **Claude Sonnet 4**. Other providers like OpenAI are not currently supported.

**Q: Can I use Claude Desktop or Claude Code with this platform?**  
A: Yes! Both **Claude Desktop** and **Claude Code** are supported. However, they require file-based MCP configuration. We provide configuration instructions for Goose clients below. For Claude Desktop/Code setup, please refer to the [official Anthropic MCP documentation](https://docs.anthropic.com/claude/docs/mcp).

**Q: Do I need to choose between Goose Desktop and Goose CLI?**  
A: No! You can use both. They connect to the same MCP service and can be used interchangeably based on your preference.

**Q: Where do I get an Anthropic API key?**  
A: Visit [console.anthropic.com](https://console.anthropic.com/), sign up or log in, navigate to "API Keys", and create a new key. See the [Get Your Anthropic API Key](#2-get-your-anthropic-api-key) section for detailed steps.

**Q: How do I download Goose?**  
A: Download from [github.com/block/goose/releases](https://github.com/block/goose/releases). Choose:
- **Goose Desktop**: For a graphical interface (.dmg for macOS, .exe for Windows, .AppImage for Linux)
- **Goose CLI**: Install via `pip install goose-ai` or `pipx install goose-ai`

**Q: What's the role of the API service?**  
A: The API service (`oscapiservice`) handles all rule CRUD operations, task management, and execution backend. It serves manual UI workflows, MCP UI workflows, and external MCP client workflows.

**Q: Can I create rules without using MCP?**  
A: Yes! The manual UI mode is available for traditional visual rule creation without any AI assistance.

**Q: Do I need an Anthropic API key if I only use manual UI?**  
A: The setup script requires the key, but if you only plan to use manual UI rule creation, the MCP services will start but you won't actively use them.

**Q: How does MCP work from the Web UI?**  
A: When you use MCP mode in the Web UI, requests go: Web UI → Reverse Proxy → Goose Service → Goose → MCP Service → API Service. This is different from external clients which connect directly to the MCP service.

**Q: What's the difference between UI MCP mode and external MCP clients?**  
A: UI MCP mode routes through the reverse proxy and is integrated into the web interface. External MCP clients (Goose Desktop/CLI) connect directly to port 45678, bypassing the reverse proxy. Both provide AI-assisted rule creation but through different access methods.

**Q: Can I use both the Web UI MCP mode and external clients (Goose/Claude) at the same time?**  
A: Yes! They're independent ways to access the same underlying MCP service. You can use whichever interface you prefer at any time.

**Q: What model should I configure in Goose?**  
A: Always use `claude-sonnet-4-20250514` (Claude Sonnet 4). This is the maximum model supported by the platform. Do not use other models.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                     QUICK REFERENCE                         │
├─────────────────────────────────────────────────────────────┤
│ Setup Script:                                               │
│  ./setup-mcp.sh          - Unified setup (7 services)       │
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
│  Maximum Model: Claude Sonnet 4 (claude-sonnet-4-20250514)  │
│  Supported Clients: Goose Desktop/CLI, Claude Desktop/Code  │
│  Note: Claude clients require file-based MCP config         │
│                                                             │
│ Rule Creation Methods:                                      │
│  1. Manual UI: Web UI → Reverse Proxy → API Service         │
│  2. MCP UI Mode: Web UI → Reverse Proxy → Goose → MCP       │
│  3. External MCP: Goose/Claude → MCP (port 45678)           │
│                                                             │
│ Goose Configuration:                                        │
│  Config File: ~/.config/goose/config.yaml                   │
│  MCP URI: http://localhost:45678/mcp                        │
│  Model: claude-sonnet-4-20250514                            │
│                                                             │
│ Useful Commands:                                            │
│  docker compose logs -f              - View all logs        │
│  docker compose logs oscgooseservice - View Goose Svc logs  │
│  docker compose logs oscmcpservice   - View MCP logs        │
│  docker compose ps                   - Service status       │
│  docker compose down                 - Stop services        │
│  docker compose restart              - Restart all          │
│                                                             │
│ Goose Commands:                                             │
│  goose session start                 - Start CLI session    │
│  goose run "query"                   - Run one-off command  │
│  goose --help                        - Get help             │
│                                                             │
│ Important Files:                                            │
│  etc/userconfig.env                  - User config + API key│
│  etc/policycow.env                   - Platform config      │
│  ~/.config/goose/config.yaml         - Goose configuration  │
│  src/oscreverseproxy/certs/          - SSL certs (opt 1)    │
│  goose-sessions/sessions/            - Goose sessions       │
└─────────────────────────────────────────────────────────────┘
```

---

**Last Updated**: November 2025  
**Version**: 2.1.0  
**Maintained By**: Open Security Compliance Team