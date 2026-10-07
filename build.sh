#!/bin/bash

source ./export_env.sh

if [[ ! $(docker network ls | grep cow_default) ]]; then
    docker network create cow_default $COW_NETWORK_ARGS
fi

if [[ ! $(docker network ls | grep cow_internal) ]]; then
   docker network create cow_internal
fi
# the file set comes from COMPOSE_FILE (see export_env.sh)
docker compose build cowlibrary || exit 1
docker compose build cowctl || exit 1
