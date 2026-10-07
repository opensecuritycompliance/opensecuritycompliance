# Running OpenSecurityCompliance on Windows

The PowerShell scripts here are thin wrappers around the repo's shell scripts
(`build.sh`, `run.sh`, `build_and_run.sh`), run through Git Bash, so Windows and Linux
share one code path.

## Prerequisites

| Tool | Notes |
|---|---|
| Git for Windows | provides Git Bash (`bash.exe`) |
| `yq` (mikefarah) | `winget install MikeFarah.yq` |
| Docker Desktop (Linux containers) | includes the `docker compose` plugin |

## Docker Desktop with Linux containers (Windows 10/11)

Docker Desktop with the WSL2 backend, in its default "Linux containers" mode. The original
Linux Dockerfiles and `docker-compose.yaml` are used unchanged.

Needs hardware virtualization (BIOS/UEFI on), WSL2 enabled, and a Docker Desktop licence
that fits your organisation.

## Usage

```powershell
.\windows_setup\build_and_run.ps1   # build images, start the stack, open a shell in cowctl
.\windows_setup\build.ps1           # build only
.\windows_setup\run.ps1             # start + shell
```

## Verification status

Verified on Windows Server 2025 with Docker Desktop (WSL2 backend, Linux containers): build, start,
and `cowctl` inside the container. Windows-containers-only hosts are covered on the
`windows-containers` branch.
