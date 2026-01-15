param(
  [ValidateSet("Debug","Release")]
  [string]$Configuration = "Release",
  [string]$WdkRoot = "C:\Program Files (x86)\Windows Kits\10",
  [string]$WdkVersion = ""
)

if (-not (Test-Path $WdkRoot)) {
  Write-Error "WDK root not found at $WdkRoot"
  exit 1
}

$includePath = Join-Path $WdkRoot "Include"
$versions = Get-ChildItem -Directory -Path $includePath |
  Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
  Sort-Object { [Version]$_.Name }

if (-not $versions) {
  Write-Error "No WDK versions found under $includePath"
  exit 1
}

if ($WdkVersion) {
  $candidateKm = Join-Path $includePath "$WdkVersion\\km"
  if (-not (Test-Path $candidateKm)) {
    $prefix = $WdkVersion
    if ($WdkVersion -match '^(\d+\.\d+\.\d+)\.') {
      $prefix = "$($matches[1])."
    }
    $match = $versions | Where-Object { $_.Name -like "$prefix*" } | Select-Object -Last 1
    if ($match) {
      $WdkVersion = $match.Name
    } else {
      Write-Warning "Requested WDK version '$WdkVersion' not found. Falling back to latest."
      $WdkVersion = $versions[-1].Name
    }
  }
} else {
  $WdkVersion = $versions[-1].Name
}

$kmPath = Join-Path $WdkRoot "Include\\$WdkVersion\\km"
if (-not (Test-Path $kmPath)) {
  Write-Error "WDK headers not found at $kmPath. Available versions: $($versions.Name -join ', ')"
  exit 1
}

$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmakeCmd) {
  $cmakeFallback = "C:\\Program Files\\CMake\\bin\\cmake.exe"
  if (Test-Path $cmakeFallback) {
    $cmakeCmd = Get-Command $cmakeFallback
  }
}

if (-not $cmakeCmd) {
  Write-Error "cmake not found. Install CMake and ensure it is in PATH."
  exit 1
}

$root = $PSScriptRoot
$buildDir = Join-Path $root "build"

Write-Host "[DRIVER] Using WDK $WdkVersion at $WdkRoot"
& $cmakeCmd.Source -S $root -B $buildDir -G "Visual Studio 17 2022" -A x64 `
  -DWDK_ROOT="$WdkRoot" -DWDK_VERSION="$WdkVersion"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cmakeCmd.Source --build $buildDir --config $Configuration
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[DRIVER] Build complete: $buildDir\\$Configuration\\AegisFusion.sys"
