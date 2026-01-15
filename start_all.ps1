param(
  [string]$ApiUrl = "http://localhost:8090",
  [string]$CloudUrl = "http://localhost:8081",
  [string]$CloudApiKey = "WGzOYOAJ5j8bEzxiYIITi6TfhbI5JGOPIBEnS9RmRRc=",
  [switch]$LocalCloud,
  [switch]$SkipDocker,
  [switch]$SkipCore,
  [switch]$SkipUi,
  [switch]$Release
)

$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Require-Command {
  param(
    [string]$Name,
    [string]$Hint
  )

  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Write-Error "$Name not found. $Hint"
    exit 1
  }
}

function Start-Terminal {
  param(
    [string]$Title,
    [string]$WorkingDir,
    [string]$Command
  )

  $escapedDir = $WorkingDir.Replace("'", "''")
  $escapedCmd = $Command.Replace("'", "''")
  $script = @"
`$host.UI.RawUI.WindowTitle = '$Title'
Set-Location '$escapedDir'
$escapedCmd
"@

  Start-Process powershell -ArgumentList "-NoExit", "-Command", $script
}

Write-Host "[AEGIS] Starting system from $root"

if (-not $SkipDocker -and -not $LocalCloud) {
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    $composeCmd = "docker compose"
  } elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    $composeCmd = "docker-compose"
  } else {
    Write-Error "Docker not found. Install Docker Desktop and ensure it is running."
    exit 1
  }

  Start-Terminal `
    -Title "AEGIS - Docker" `
    -WorkingDir $root `
    -Command "$composeCmd up --build"
}

if ($LocalCloud) {
  Require-Command -Name "go" -Hint "Install Go and ensure it is in PATH"

  $uploadDir = Join-Path $root "cloud\\api\\uploads"
  $reportDir = Join-Path $root "cloud\\sandbox\\reports"
  New-Item -ItemType Directory -Force -Path $uploadDir | Out-Null
  New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

  $cloudUri = $null
  try {
    $cloudUri = [Uri]$CloudUrl
  } catch {
    $cloudUri = $null
  }
  $cloudPort = if ($cloudUri) { $cloudUri.Port } else { 8081 }

  $cloudCmd = @"
`$env:PORT = "$cloudPort"
`$env:AEGIS_ANALYSIS_MODE = "sandbox"
`$env:AEGIS_API_KEYS = "$CloudApiKey"
`$env:AEGIS_UPLOAD_DIR = "$uploadDir"
go run .
"@

  Start-Terminal `
    -Title "AEGIS - Cloud API" `
    -WorkingDir (Join-Path $root "cloud\\api") `
    -Command $cloudCmd

  $sandboxCmd = @"
`$env:SANDBOX_UPLOAD_DIR = "$uploadDir"
`$env:SANDBOX_REPORT_DIR = "$reportDir"
`$env:SANDBOX_API_URL = "$CloudUrl"
`$env:SANDBOX_API_KEY = "$CloudApiKey"
`$env:SANDBOX_WORKERS = "2"
`$env:SANDBOX_POLL_MS = "1000"
`$env:SANDBOX_MIN_AGE_SEC = "2"
`$env:SANDBOX_MAX_READ_MB = "4"
go run .
"@

  Start-Terminal `
    -Title "AEGIS - Sandbox" `
    -WorkingDir (Join-Path $root "cloud\\sandbox") `
    -Command $sandboxCmd
}

if (-not $SkipCore) {
  Require-Command -Name "cargo" -Hint "Install Rust via https://rustup.rs"
  $coreCmd = @"
`$env:AEGIS_CLOUD_URL = "$CloudUrl"
`$env:AEGIS_CLOUD_API_KEY = "$CloudApiKey"
`$env:AEGIS_CLOUD_CLIENT_ID = `$env:COMPUTERNAME
$(if ($Release) { "cargo run --release" } else { "cargo run" })
"@

  Start-Terminal `
    -Title "AEGIS - Core" `
    -WorkingDir (Join-Path $root "core") `
    -Command $coreCmd
}

if (-not $SkipUi) {
  Require-Command -Name "npm" -Hint "Install Node.js from https://nodejs.org"

  $uiCmd = @"
`$env:VITE_API_URL = "$ApiUrl"
if (-not (Test-Path 'node_modules')) { npm install }
npm run dev
"@

  Start-Terminal `
    -Title "AEGIS - UI" `
    -WorkingDir (Join-Path $root "ui") `
    -Command $uiCmd
}

Write-Host "[AEGIS] Startup commands launched."
