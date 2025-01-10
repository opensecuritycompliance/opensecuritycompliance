# set envs

. "$PSScriptRoot\export_env.ps1"

#& "$PSScriptRoot\export_env.ps1"

# Check if the 'cow_default' Docker network exists, and create it if it doesn't
if (-not (docker network ls | Select-String -Pattern 'cow_default')) {
    docker network create cow_default --driver bridge --scope local
}

# Check if the 'cow_internal' Docker network exists, and create it if it doesn't
if (-not (docker network ls | Select-String -Pattern 'cow_internal')) {
    docker network create cow_internal
}

# Build Docker containers using Docker Compose
docker compose -f $dockerComposeFilePath build cowlibrary
docker compose -f $dockerComposeFilePath build cowctl
