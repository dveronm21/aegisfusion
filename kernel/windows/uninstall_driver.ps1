param(
  [string]$ServiceName = "AegisFusion"
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

$existing = & sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -eq 0) {
  & sc.exe stop $ServiceName | Out-Null
  Start-Sleep -Seconds 1
  & sc.exe delete $ServiceName | Out-Null
  Write-Host "Service removed: $ServiceName"
} else {
  Write-Host "Service not found: $ServiceName"
}

$dest = Join-Path $env:SystemRoot "System32\\drivers\\AegisFusion.sys"
if (Test-Path $dest) {
  Remove-Item -Force $dest
  Write-Host "Driver file removed: $dest"
}
