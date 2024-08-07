#!/bin/bash

source export_env.sh

if [[ ! $(docker network ls | grep cow_default) ]]; then
    docker network create cow_default --driver bridge --scope local
fi

if [[ ! $(docker network ls | grep cow_internal) ]]; then
   docker network create cow_internal
fi
docker compose -f docker-compose.yaml build cowlibrary
docker compose -f docker-compose.yaml build cowctl
