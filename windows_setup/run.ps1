# set envs

. "$PSScriptRoot\export_env.ps1"

docker compose -f $dockerComposeFilePath run cowctl