param(
  [string]$DriverPath = ".\\build\\Release\\AegisFusion.sys",
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
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne "Stopped") {
    & sc.exe stop $ServiceName | Out-Null
    $wait = 0
    while ($wait -lt 20) {
      Start-Sleep -Milliseconds 500
      $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if (-not $svc -or $svc.Status -eq "Stopped") {
        break
      }
      $wait++
    }
    if ($svc -and $svc.Status -ne "Stopped") {
      & fltmc.exe unload $ServiceName | Out-Null
      Start-Sleep -Seconds 1
    }
  }

  & sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 1
}

if (-not (Test-Path $DriverPath)) {
  Write-Error "Driver not found at $DriverPath"
  exit 1
}

$dest = Join-Path $env:SystemRoot "System32\\drivers\\AegisFusion.sys"
try {
  Copy-Item -Force -ErrorAction Stop $DriverPath $dest
} catch {
  Write-Error "Failed to copy driver to $dest. Ensure the driver is stopped and try again."
  exit 1
}

& sc.exe create $ServiceName type= kernel start= demand binPath= "\SystemRoot\System32\drivers\AegisFusion.sys" | Out-Null
& sc.exe config $ServiceName start= demand | Out-Null

$serviceKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$ServiceName"
New-Item -Path "$serviceKey\\Instances" -Force | Out-Null
New-ItemProperty -Path "$serviceKey\\Instances" -Name "DefaultInstance" -PropertyType String -Value "AegisFusion Instance" -Force | Out-Null
New-Item -Path "$serviceKey\\Instances\\AegisFusion Instance" -Force | Out-Null
New-ItemProperty -Path "$serviceKey\\Instances\\AegisFusion Instance" -Name "Altitude" -PropertyType String -Value "370000" -Force | Out-Null
New-ItemProperty -Path "$serviceKey\\Instances\\AegisFusion Instance" -Name "Flags" -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name "DependOnService" -PropertyType MultiString -Value @("FltMgr") -Force | Out-Null

& sc.exe start $ServiceName | Out-Null

Write-Host "Driver installed and started: $ServiceName"
