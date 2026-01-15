param(
  [Parameter(Mandatory = $true)]
  [string]$BinaryPath,
  [string]$ServiceName = "AegisFusionCore",
  [string]$DisplayName = "Aegis Fusion Core Service",
  [string]$Description = "Aegis Fusion core service"
)

if (-not (Test-Path $BinaryPath)) {
  Write-Error "Binary not found: $BinaryPath"
  exit 1
}

$existing = & sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -eq 0) {
  & sc.exe stop $ServiceName | Out-Null
  Start-Sleep -Seconds 1
  & sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 1
}

$binPath = "`"$BinaryPath`" --service"
& sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "`"$DisplayName`"" | Out-Null
& sc.exe description $ServiceName $Description | Out-Null
& sc.exe start $ServiceName | Out-Null

Write-Host "Service $ServiceName installed and started."
