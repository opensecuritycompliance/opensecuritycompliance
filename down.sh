#!/bin/bash
# Stop and remove the containers of the stacks started by build_and_run.sh / run.sh (cowctl)
# and by setup.sh (MCP + No-Code UI). Images and your data (e.g. ~/tmp/cowctl/minio) are kept.
# Uses Docker or Podman, like the other scripts (see engine.sh).
#
#   sh down.sh            both stacks
#   sh down.sh cowctl     only the cowctl stack
#   sh down.sh osc        only the MCP + No-Code UI stack

source ./export_env.sh

which="${1:-all}"
case "$which" in
    all|cowctl|osc) ;;
    *) echo "usage: sh down.sh [all|cowctl|osc]" >&2; exit 1 ;;
esac

CONTAINERS_COWCTL="cowctl cowlibrary cowstorage"
CONTAINERS_OSC="oscmcpservice ccowmcpclient ccowmcpbridge oscwebserver oscreverseproxy oscapiservice cowstorage"

NETWORKS_COWCTL="policycow_default policycow_internal"
NETWORKS_OSC="osc_default osc_internal"

# $1 = compose file, $2 = container names, $3 = network names. The sweep afterwards catches
# anything that another project name started; removing a network that is still in use fails safely.
down_stack() {
    echo "Stopping $1 ..."
    docker compose -f "$1" down 2>&1 | grep -vE "level=warning|^$"
    for name in $2; do
        docker rm -f "$name" >/dev/null 2>&1
    done
    for net in $3; do
        docker network rm "$net" >/dev/null 2>&1
    done
}

if [ "$which" = "all" ] || [ "$which" = "cowctl" ]; then
    down_stack docker-compose.yaml "$CONTAINERS_COWCTL" "$NETWORKS_COWCTL"
fi
if [ "$which" = "all" ] || [ "$which" = "osc" ]; then
    # setup.sh starts this stack under the default (folder-name) project, not "policycow"
    ( unset COMPOSE_PROJECT_NAME; down_stack docker-compose-osc.yaml "$CONTAINERS_OSC" "$NETWORKS_OSC" )
fi
echo "Done."
