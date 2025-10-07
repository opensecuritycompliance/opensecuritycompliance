# Check if pip is available
$PIP_COMMAND = $null
# Check if pip is available
if (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "pip is available."
    $PIP_COMMAND="pip"
}elseif (Get-Command pip3 -ErrorAction SilentlyContinue) {
    Write-Host "pip3 is available."
    $PIP_COMMAND="pip3"
} else {
    Write-Host "Error: Neither pip nor pip3 found. Please install pip."
    exit 1
}

. "$PSScriptRoot\export_env.ps1"


$ccPathReq = Join-Path $parentFolder "src\compliancecowcards\requirements.txt"
$appConnReq = Join-Path $parentFolder "catalog\applicationtypes\python\requirements.txt"

& $PIP_COMMAND install -r $ccPathReq
& $PIP_COMMAND install -r $libraryReq
& $PIP_COMMAND install -r $appConnReq

$ccCardsPath=Join-Path $parentFolder "src\compliancecowcards"
$appPath=Join-Path $parentFolder "catalog\applicationtypes\python"

& $PIP_COMMAND install $ccCardsPath
& $PIP_COMMAND install $ccPath
& $PIP_COMMAND install $appPath

$GoVersion = "1.21.3"

# Check if Go is installed
if (Test-Path "$env:GOPATH\bin\go.exe") {
    Write-Host "Go is installed."
} else {
    Write-Host "Go is not installed. Please install Go with version '$GoVersion' and set up GOPATH."
}
