#!/bin/bash
# Container engine selection, sourced by export_env.sh and setup.sh.
#
# Docker is the default. When there is no working Docker engine but Podman is installed
# (or COW_ENGINE=podman is set), the docker CLI and compose are pointed at Podman's
# Docker-compatible socket, so the rest of the scripts stay engine-agnostic.
#
#   COW_ENGINE=docker|podman   force an engine (default: auto)
#   OSC_HTTP_PORT / OSC_HTTPS_PORT   host ports of the reverse proxy; rootless Podman cannot
#                                    publish 80/443, so they default to 8081/8443 there

# Git Bash on Windows has no sudo, and Docker Desktop there needs no elevation: make `sudo cmd` run cmd.
# (setup.sh calls `sudo docker ...` before it has sourced anything else.)
command -v sudo >/dev/null 2>&1 || sudo() { "$@"; }

# Run a command with a time limit when `timeout` exists (not on stock macOS); a half-started
# Docker Desktop can make `docker info` hang instead of fail.
cow_with_timeout() {
    local secs=$1; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
    else "$@"; fi
}

cow_engine_detect() {
    case "${COW_ENGINE:-auto}" in
        docker|podman) ;;
        *)
            if cow_with_timeout 20 docker info >/dev/null 2>&1; then
                COW_ENGINE=docker
            elif command -v podman >/dev/null 2>&1; then
                COW_ENGINE=podman
            else
                COW_ENGINE=docker
            fi
            ;;
    esac
    export COW_ENGINE
    if [ "$COW_ENGINE" = "podman" ]; then
        cow_engine_podman || return 1
    fi
    return 0
}

cow_engine_podman() {
    if ! command -v podman >/dev/null 2>&1; then
        echo "ERROR: COW_ENGINE=podman but podman is not installed" >&2
        return 1
    fi

    # macOS/Windows: the engine lives in a VM that may not be running yet
    if ! podman info >/dev/null 2>&1 && podman machine list --format '{{.Name}}' 2>/dev/null | grep -q .; then
        echo "Starting the podman machine..."
        podman machine start >/dev/null 2>&1 </dev/null
    fi
    if ! podman info >/dev/null 2>&1; then
        echo "ERROR: podman is not running (try: podman machine start)" >&2
        return 1
    fi

    # Docker-compatible API endpoint: the VM's forwarded socket on macOS, the user socket on Linux
    local sock pipe
    sock=$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null | head -n1 | tr -d '\r')
    if [ -z "$sock" ] || [ ! -S "$sock" ]; then
        sock=$(podman info --format '{{.Host.RemoteSocket.Path}}' 2>/dev/null | head -n1 | tr -d '\r')
        if [ -n "$sock" ] && [ ! -S "$sock" ]; then
            systemctl --user start podman.socket >/dev/null 2>&1
        fi
    fi
    if [ -n "$sock" ] && [ -S "$sock" ]; then
        export DOCKER_HOST="unix://$sock"
    else
        pipe=$(podman machine inspect --format '{{.ConnectionInfo.PodmanPipe.Path}}' 2>/dev/null | head -n1 | tr -d '\r')
        if [ -z "$pipe" ]; then
            echo "ERROR: could not find podman's API socket" >&2
            return 1
        fi
        export DOCKER_HOST="npipe:////./pipe/${pipe##*\\}"
    fi

    # Build through podman's own builder: BuildKit runs amd64 images under QEMU, which crashes
    # Go on Apple Silicon (podman's builder uses the VM's Rosetta instead).
    export DOCKER_BUILDKIT=0 COMPOSE_BAKE=false
    export PODMAN_COMPOSE_WARNING_LOGS=false

    # rootless: no privileged host ports, no sudo
    export OSC_HTTP_PORT="${OSC_HTTP_PORT:-8081}" OSC_HTTPS_PORT="${OSC_HTTPS_PORT:-8443}"
    sudo() { "$@"; }

    # no docker CLI installed: let `docker ...` (and `docker compose ...`) mean podman
    if ! command -v docker >/dev/null 2>&1; then
        docker() { podman "$@"; }
        # `podman compose` only forwards to an external provider; without a docker CLI there is none by default
        if ! podman compose version >/dev/null 2>&1 </dev/null; then
            echo "ERROR: Podman has no compose provider. Install one of:" >&2
            echo "         - docker-compose (standalone binary: https://docs.docker.com/compose/install/standalone/," >&2
            echo "           or: brew install docker-compose)" >&2
            echo "         - podman-compose (pip install podman-compose)" >&2
            return 1
        fi
    fi

    export MSYS_NO_PATHCONV=1
    cow_engine_prepare_vm

    local mem
    mem=$(podman machine inspect --format '{{.Resources.Memory}}' 2>/dev/null | head -n1)
    if [ -n "$mem" ] && [ "$mem" -lt 4096 ] 2>/dev/null; then
        echo "WARNING: the podman machine has ${mem} MiB of RAM; the full stack needs ~6 GiB" >&2
        echo "         (podman machine stop && podman machine set --memory 6144 && podman machine start)" >&2
    fi
    return 0
}

# One-time setup of the Podman machine's user containers.conf (idempotent, runs once per shell chain):
#  - host_containers_internal_ip: lets `host.docker.internal:host-gateway` in the compose files resolve
#  - pids_limit=0: WSL2 machines (Windows) do not delegate the pids cgroup controller to the user,
#    so crun fails with "controller `pids` is not available" unless the PID limit is off
# The remote script is passed base64-encoded so it needs no quoting, which differs between
# Git Bash, PowerShell and zsh when handed to `podman machine ssh`.
cow_engine_prepare_vm() {
    [ "$COW_ENGINE" = "podman" ] || return 0
    [ -n "$COW_VM_PREPARED" ] && return 0
    podman machine list --format '{{.Name}}' 2>/dev/null | grep -q . || return 0   # native Linux: nothing to do

    local script b64
    script='f=$HOME/.config/containers/containers.conf
mkdir -p "$(dirname "$f")"; touch "$f"
set_key() {
  grep -q "^[[:space:]]*$1[[:space:]]*=" "$f" && return 1
  if grep -q "^\[containers\]" "$f"; then sed -i "/^\[containers\]/a $1 = $2" "$f"
  else printf "[containers]\n%s = %s\n" "$1" "$2" >> "$f"; fi
  return 0
}
changed=0
ip=$(getent hosts host.containers.internal | cut -d" " -f1)
[ -n "$ip" ] && set_key host_containers_internal_ip "\"$ip\"" && changed=1
set_key pids_limit 0 && changed=1
if [ $changed = 1 ]; then
  systemctl --user stop podman.service podman.socket >/dev/null 2>&1
  systemctl --user start podman.socket >/dev/null 2>&1
  echo changed
fi'
    b64=$(printf '%s\n' "$script" | base64 | tr -d '\n\r')
    # </dev/null: `podman machine ssh` forwards stdin and would swallow piped/typed-ahead input
    if [ "$(podman machine ssh "echo $b64 | base64 -d | sh" 2>/dev/null </dev/null | tr -d '\r')" = "changed" ]; then
        echo "Configured the podman machine (containers.conf)"
    fi
    export COW_VM_PREPARED=1
    return 0
}
