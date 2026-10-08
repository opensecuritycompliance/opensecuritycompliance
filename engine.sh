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

cow_engine_detect() {
    case "${COW_ENGINE:-auto}" in
        docker|podman) ;;
        *)
            if docker info >/dev/null 2>&1; then
                COW_ENGINE=docker
            elif command -v podman >/dev/null 2>&1; then
                COW_ENGINE=podman
            else
                COW_ENGINE=docker
            fi
            ;;
    esac
    export COW_ENGINE
    [ "$COW_ENGINE" = "podman" ] && cow_engine_podman
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
        podman machine start >/dev/null 2>&1
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
    command -v docker >/dev/null 2>&1 || docker() { podman "$@"; }

    local mem
    mem=$(podman machine inspect --format '{{.Resources.Memory}}' 2>/dev/null | head -n1)
    if [ -n "$mem" ] && [ "$mem" -lt 4096 ] 2>/dev/null; then
        echo "WARNING: the podman machine has ${mem} MiB of RAM; the full stack needs ~6 GiB" >&2
        echo "         (podman machine stop && podman machine set --memory 6144 && podman machine start)" >&2
    fi
    return 0
}

# One-time VM setup for the compose files' `host.docker.internal:host-gateway`.
# Podman cannot resolve host-gateway in a machine until host_containers_internal_ip is set.
cow_engine_prepare_vm() {
    [ "$COW_ENGINE" = "podman" ] || return 0
    podman machine list --format '{{.Name}}' 2>/dev/null | grep -q . || return 0   # native Linux: nothing to do

    local ip conf='~/.config/containers/containers.conf'
    ip=$(podman machine ssh 'getent hosts host.containers.internal' 2>/dev/null | awk '{print $1}' | head -n1)
    [ -n "$ip" ] || return 0
    if podman machine ssh "grep -qs host_containers_internal_ip $conf" 2>/dev/null; then
        return 0
    fi

    echo "Configuring the podman machine (host.containers.internal = $ip)..."
    # insert into the existing [containers] table; a second table header would break podman
    podman machine ssh "mkdir -p ~/.config/containers && touch $conf &&
        if grep -q '^\[containers\]' $conf; then
            sed -i '/^\[containers\]/a host_containers_internal_ip = \"$ip\"' $conf
        else
            printf '[containers]\nhost_containers_internal_ip = \"$ip\"\n' >> $conf
        fi" >/dev/null 2>&1
    podman machine ssh 'systemctl --user restart podman.socket' >/dev/null 2>&1
    return 0
}
