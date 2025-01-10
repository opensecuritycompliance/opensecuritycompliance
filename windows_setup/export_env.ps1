# Get the directory where the script is located

# Specify the name of the YAML file you're looking for
$yamlFileName = "docker-compose.yaml"

$parentFolder =".."

# Check if the YAML file exists in the current directory
if (Test-Path -Path $yamlFileName -PathType Leaf) {
    $parentFolder = $PWD
    #Write-Host "Found YAML file in current directory: $PWD\$yamlFileName"
} else {
    # If not found in the current directory, check the parent directory
    $parentDirectory = (Get-Item $PWD).Parent
    $parentYamlPath = Join-Path $parentDirectory.FullName $yamlFileName
    if (Test-Path -Path $parentYamlPath -PathType Leaf) {
        #Write-Host "Found YAML file in parent directory: $parentYamlPath"
        $parentFolder = $parentDirectory.FullName
    } else {
        #Write-Host "YAML file not found in current or parent directory."
    }
}



# change the path based on the script execution.
$configYamlPath = Join-Path $parentFolder 'etc/cowconfig.yaml' # change the path respectively.
$dockerComposeFilePath = Join-Path $parentFolder  'docker-compose.yaml' # change the path respectively.



$userHomeFirectory = $env:USERPROFILE
[Environment]::SetEnvironmentVariable("HOME", $userHomeFirectory, [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable("HOME",$userHomeFirectory)

$envVarData = @(
    @{ Name = "POLICYCOW_DOWNLOADSPATH"; Path = ".pathConfiguration.downloadsPath" },
    @{ Name = "POLICYCOW_RULESPATH"; Path = ".pathConfiguration.rulesPath" },
    @{ Name = "POLICYCOW_EXECUTIONPATH"; Path = ".pathConfiguration.executionPath" },
    @{ Name = "POLICYCOW_RULEGROUPPATH"; Path = ".pathConfiguration.ruleGroupPath" },
    @{ Name = "POLICYCOW_SYNTHESIZERPATH"; Path = ".pathConfiguration.synthesizersPath" },
    @{ Name = "POLICYCOW_DOWNLOADSPATH"; Path = ".pathConfiguration.downloadsPath" }
)

foreach ($entry in $envVarData) {
    $envVarName = $entry.Name
    $yamlPath = $entry.Path

    $value = & 'yq' e $yamlPath $configYamlPath

    if  ($null -ne $value) {
        [Environment]::SetEnvironmentVariable($envVarName, $value, [System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable($envVarName,$value)
        #Write-Host "Set $envVarName = $value"
    } else {
        #Write-Host "Failed to set $envVarName. Value not found in YAML."
    }
}

[Environment]::SetEnvironmentVariable("COW_DATA_PERSISTENCE_TYPE", "minio", [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable("COW_DATA_PERSISTENCE_TYPE", "minio")
