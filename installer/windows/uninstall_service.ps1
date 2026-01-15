param(
  [string]$ServiceName = "AegisFusionCore"
)

$existing = & sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Service $ServiceName is not installed."
  exit 0
}

& sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 1
& sc.exe delete $ServiceName | Out-Null

Write-Host "Service $ServiceName removed."
