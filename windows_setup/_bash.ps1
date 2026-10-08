# Runs a repo-root shell script with Git Bash, so Windows and Linux share one code path.
param([Parameter(Mandatory)][string]$Script, [Parameter(ValueFromRemainingArguments)][string[]]$ScriptArgs)
# Pick up tools installed after this shell was opened (Docker, Git, yq ...) without a restart:
# add the registry PATH entries this session lacks, keeping whatever the session already has.
$current = @($env:Path -split ';' | Where-Object { $_ })
$registry = @([Environment]::GetEnvironmentVariable('Path', 'Machine'), [Environment]::GetEnvironmentVariable('Path', 'User')) -split ';' | Where-Object { $_ }
$env:Path = (@($current) + @($registry | Where-Object { $current -notcontains $_ })) -join ';'
$root = Split-Path -Parent $PSScriptRoot
# Prefer Git Bash: with WSL installed, `bash` on PATH is the WSL launcher (System32\bash.exe).
$gitBash = @("$env:ProgramFiles\Git\bin\bash.exe", "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
             "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $gitBash) {
    $git = (Get-Command git -ErrorAction SilentlyContinue).Source
    if ($git) { $gitBash = Join-Path (Split-Path (Split-Path $git)) "bin\bash.exe" }
}
if (-not $gitBash -or -not (Test-Path $gitBash)) { throw "Git Bash not found. Install Git for Windows." }
$bash = $gitBash
if (-not (Get-Command yq -ErrorAction SilentlyContinue)) { throw "yq not found on PATH." }
Push-Location $root
try { & $bash $Script @ScriptArgs; exit $LASTEXITCODE } finally { Pop-Location }
