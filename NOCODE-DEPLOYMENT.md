# Open Security Compliance — No-Code UI Deployment Guide

Setup documentation for deploying Open Security Compliance with the No-Code web interface only (no Anthropic API key required).

> **Have an Anthropic API key?** You can enable AI-powered rule creation via MCP.
> See the **[MCP + No-Code UI Deployment Guide](MCP-DEPLOYMENT.md)** for the full setup.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start Guide](#quick-start-guide)
- [Appendix](#appendix)

---

## Overview

The No-Code UI Only mode deploys a lightweight subset of the Open Security Compliance platform, giving you:

- **No-Code UI**: Visual interface for creating and managing compliance rules
- **Rule Engine**: Powerful execution engine for compliance automation
- **Storage**: MinIO-based object storage for data persistence
- **API Service**: RESTful API for programmatic access

No Anthropic API key or AI model is needed. Rule creation is done entirely through the web interface.

### What You Can Do

- Create compliance rules through the No-Code web interface
- Execute automated compliance checks
- Store and manage compliance data
- Access rule data via the REST API

### Architecture

```
                    ┌──────────────┐
                    │     User     │
                    └──────┬───────┘
                           │
                           ▼
                ┌───────────────────┐
                │   Web UI          │
                │  oscwebserver     │
                │   Port: 3001      │
                └────────┬──────────┘
                         │
                         ▼
                ┌───────────────────┐
                │ Reverse Proxy     │
                │ oscreverseproxy   │
                │   Port: 443       │
                └────────┬──────────┘
                         │
                         ▼
                ┌─────────────────┐
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

### Services

| Service | Purpose | Ports |
|---------|---------|-------|
| cowstorage (MinIO) | Object storage for rules, data, and artifacts | 9000 (API), 9001 (Console) |
| oscapiservice | REST API for rule management and execution | 9080 |
| oscwebserver | React-based web interface | 3001 |
| oscreverseproxy | HTTPS termination and routing | 443 (HTTPS), 80 (HTTP) |

---

## Quick Start Guide

### Pre-requisites

- Docker (Steps to install can be found in the [Appendix](#1-docker-installation) below)
- System Requirements
  - CPU: 4+ cores
  - RAM: 8GB+
  - Disk: 20GB+ SSD
  - Docker: 20.10+
  - Docker Compose: 2.0+

> **Note:** No Anthropic API key is required for this mode.

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/opensecuritycompliance/opensecuritycompliance.git

# Navigate to the project directory
cd opensecuritycompliance
```

### Step 2: Run the Setup Script

```bash
# Make the setup script executable
chmod +x setup.sh

# Run the setup
sudo ./setup.sh
```

When prompted, **select option 2 (No-Code UI Only)**:

```
════════════════════════════════════════════════════════════
  Choose your setup mode
════════════════════════════════════════════════════════════

  1) MCP + No-Code UI  (Requires a valid Anthropic API key)
  2) No-Code UI Only   (No Anthropic API key needed)

Select setup mode [1/2]: 2
```

The script will then:
- Check Docker installation and access
- Validate system resources
- Prompt for MinIO storage credentials
- Verify SSL certificates
- Build and start the 4 required services

**That's it!** No API key setup, no model detection — just the web platform.

---

## Appendix

### 1. Docker Installation

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

### 2. What the Setup Script Does (No-Code UI Mode)

When you select option 2, the script will:

1. Check Docker installation and access (detects if sudo is needed)
2. Validate system resources (CPU, RAM, disk)
3. Prompt for MinIO credentials (validates requirements)
4. Verify SSL certificates (uses localhost certs by default)
5. Check environment configuration files
6. Clean up existing Docker resources
7. Build Docker images for the 4 services
8. Start services in the correct order
9. Wait for services to be healthy
10. Display access URLs and next steps

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

Select setup mode [1/2]: 2

[INFO] Selected: No-Code UI Only

[INFO] Checking MinIO credentials...
[SUCCESS] MinIO credentials validated successfully

[SUCCESS] All pre-flight checks passed!

Setup Summary (No-Code UI Only):
  Services to be deployed: 4
    1. Web UI (oscwebserver)
    2. Reverse Proxy (oscreverseproxy)
    3. API Service (oscapiservice)
    4. Storage Service (cowstorage/MinIO)

╔═══════════════════════════════════════════════════════════╗
║    Open Security Compliance No-Code UI Setup Completed!   ║
╚═══════════════════════════════════════════════════════════╝

Access URLs:
  - Web UI (HTTPS): https://localhost:443
  - Web UI (HTTP): http://localhost:3001
  - API Service: http://localhost:9080
  - MinIO Console: http://localhost:9001
```

---

### 3. Next Steps After Installation

#### Access the Web UI

Open your browser and navigate to:
```
https://localhost:443
```

**Note:** You may see a security warning for the self-signed certificate. Click "Advanced" and "Proceed to localhost (unsafe)" to continue.

#### Create Rules

Use the No-Code web interface to:
- Create and configure compliance rules visually
- Define tasks and wire inputs/outputs
- Execute rules and view results

#### Verify Services Are Running

```bash
# Check service status
docker compose ps

# You should see 4 services running:
# - oscwebserver (Web UI)
# - oscreverseproxy (Reverse Proxy)
# - oscapiservice (API Service)
# - cowstorage (MinIO Storage)
```

---

### 4. Managing Your Installation

#### Viewing Logs

```bash
# View all service logs
docker compose -f docker-compose-osc.yaml logs -f

# View specific service logs
docker compose -f docker-compose-osc.yaml logs -f oscapiservice
```

#### Stopping Services

```bash
docker compose -f docker-compose-osc.yaml down
```

#### Restarting Services

```bash
docker compose -f docker-compose-osc.yaml restart
```

---

### 5. Upgrading to MCP Mode

If you later obtain an Anthropic API key and want to enable AI-powered rule creation:

1. Stop the current services:
   ```bash
   docker compose -f docker-compose-osc.yaml down
   ```

2. Re-run the setup script and select **option 1**:
   ```bash
   sudo ./setup.sh
   ```

3. Follow the prompts to enter your Anthropic API key.

See the **[MCP + No-Code UI Deployment Guide](MCP-DEPLOYMENT.md)** for full details.

---

### 6. Common Issues and Solutions

#### Docker "credsStore" Error (macOS)

**Error:** `Error loading metadata for library...`

**Solution:** Rename `credsStore` to `credStore` in `~/.docker/config.json` and restart Docker.

#### Permission Denied When Running Docker

**Solution:** The setup script auto-detects if sudo is needed. To avoid sudo permanently:
```bash
sudo usermod -aG docker $USER
# Log out and log back in
```

#### MinIO Credential Requirements Not Met

Ensure:
- Username: At least 3 characters, no spaces
- Password: At least 8 characters, no spaces

---

### 7. FAQ

**Q: Do I need an Anthropic API key for this mode?**
A: No. The No-Code UI Only mode requires no API key and no AI model access.

**Q: Can I upgrade to MCP mode later?**
A: Yes. Re-run `setup.sh` and select option 1. See [Upgrading to MCP Mode](#5-upgrading-to-mcp-mode).

**Q: What are the minimum system requirements?**
A: 4+ CPU cores, 8GB+ RAM, 20GB+ SSD. Lighter than the full MCP setup since only 4 services run.

**Q: Where are my rules and data stored?**
A: All data is stored in MinIO (object storage) at `${HOME}/tmp/cowctl/minio/`. Back up this directory regularly.

**Q: Can I use this in production?**
A: The platform is designed for development and testing. For production, change default MinIO credentials, consider custom SSL certificates, and review security settings.

---

### 8. Quick Reference

```
┌─────────────────────────────────────────────────────────────-┐
│              NO-CODE UI — QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────-┤
│ Setup:                                                       │
│  chmod +x setup.sh                                       │
│  sudo ./setup.sh        → Select option 2                │
│                                                              │
│ Access URLs:                                                 │
│  https://localhost:443       - Web UI (HTTPS)                │
│  http://localhost:3001       - Web UI (HTTP)                 │
│  http://localhost:9080       - API Service                   │
│  http://localhost:9001       - MinIO Console                 │
│                                                              │
│ Useful Commands:                                             │
│  docker compose -f docker-compose-osc.yaml logs -f           │
│  docker compose -f docker-compose-osc.yaml ps                │
│  docker compose -f docker-compose-osc.yaml down              │
│  docker compose -f docker-compose-osc.yaml restart           │
│                                                              │
│ Upgrade to MCP:                                              │
│  Stop services → Re-run setup.sh → Select option 1       │
└─────────────────────────────────────────────────────────────-┘
```

---

**Last Updated**: February 2026
**Version**: 1.0.0
**Maintained By**: Open Security Compliance Team
**Repository**: https://github.com/opensecuritycompliance/opensecuritycompliance
