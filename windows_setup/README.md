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

## Podman instead of Docker Desktop

Install Podman for Windows (needs WSL2), run `podman machine init --memory 6144 --now`, then set
`$env:COW_ENGINE = 'podman'` before the commands below (not needed when Docker is not installed).
If there is no Docker CLI, Podman also needs a compose provider (`docker-compose` or `podman-compose`).
Docker Desktop and Podman cannot run at the same time (both use the `docker_engine` pipe).
Details: "Using Podman instead of Docker" in the main README.

## Usage

```powershell
.\windows_setup\build_and_run.ps1   # build images, start the stack, open a shell in cowctl
.\windows_setup\build.ps1           # build only
.\windows_setup\run.ps1             # start + shell
.\windows_setup\down.ps1            # stop and remove the containers (down.ps1 cowctl | osc for one stack)
```

`setup.sh` (MCP + No-Code UI) is run from Git Bash: `bash ./setup.sh`.

## Verification status

Verified on Windows Server 2025 (WSL2), with Docker Desktop 4.94 and with Podman 6.1 (each on its own):
build and start of the cowctl stack, `cowctl` inside the container, a rule run (`cowctl exec rule`),
the interactive prompt via `run.ps1`, `setup.sh` in No-Code UI mode, the full MCP + UI compose stack
(the goose container needs the secret and LLM key that `setup.sh` full mode asks for), and `down.ps1`.
Also verified with Podman and no Docker CLI installed.

Not verified: `setup.sh` full mode (needs an LLM API key), Windows 10/11 client editions, Windows on ARM.
Windows-containers-only hosts (no Linux VM) are covered on the `windows-containers` branch.
