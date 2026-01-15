param(
  [string]$Version = "1.22.6",
  [switch]$Quiet
)

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
  Write-Error "Run this script as Administrator."
  exit 1
}

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$msiName = "go$Version.windows-$arch.msi"
$downloadUrl = "https://go.dev/dl/$msiName"
$tempPath = Join-Path $env:TEMP $msiName

Write-Host "[GO] Downloading $downloadUrl"
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath

if (-not (Test-Path $tempPath)) {
  Write-Error "Download failed: $tempPath"
  exit 1
}

$msiArgs = "/i `"$tempPath`" /norestart"
if ($Quiet) {
  $msiArgs = "/i `"$tempPath`" /qn /norestart"
}

Write-Host "[GO] Installing Go $Version"
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
  Write-Error "Go installation failed with exit code $($proc.ExitCode)"
  exit $proc.ExitCode
}

$goRoot = "C:\Program Files\Go"
$goExe = Join-Path $goRoot "bin\go.exe"
if (Test-Path $goExe) {
  if (-not $env:Path.Contains("$goRoot\bin")) {
    $env:Path = "$goRoot\bin;$env:Path"
  }
  & $goExe version
  Write-Host "[GO] Installed successfully. Restart your terminal to refresh PATH."
} else {
  Write-Host "[GO] Installed. Open a new terminal and run: go version"
}

Remove-Item -Force $tempPath -ErrorAction SilentlyContinue
