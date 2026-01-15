param(
  [string]$SdkVersion = "10.0.19041.0",
  [switch]$SkipBuildTools
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

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Write-Error "winget not found. Install App Installer from Microsoft Store."
  exit 1
}

if (-not $SkipBuildTools) {
  Write-Host "[WDK] Installing Visual Studio 2022 Build Tools (C++ workload)"
  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget `
    --accept-package-agreements --accept-source-agreements `
    --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --includeOptional"
}

Write-Host "[WDK] Installing Windows SDK $SdkVersion"
$sdkId = "Microsoft.WindowsSDK.$SdkVersion"
winget install --id $sdkId -e --source winget `
  --accept-package-agreements --accept-source-agreements

Write-Host "[WDK] Installing Windows Driver Kit (WDK)"
$wdkInstalled = $false
$wdkIds = @(
  "Microsoft.WindowsDriverKit",
  "Microsoft.WindowsWDK"
)

foreach ($id in $wdkIds) {
  winget install --id $id -e --source winget `
    --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -eq 0) {
    $wdkInstalled = $true
    break
  }
}

if (-not $wdkInstalled) {
  Write-Warning "WDK install did not complete via winget. Open the official WDK download page:"
  Write-Warning "https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
  exit 1
}

Write-Host "[WDK] Installation finished. Reopen your terminal before building the driver."
