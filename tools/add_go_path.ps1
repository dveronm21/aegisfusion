param(
  [switch]$Machine
)

$goRoot = "C:\Program Files\Go\bin"
if (-not (Test-Path $goRoot)) {
  Write-Error "Go bin not found at $goRoot"
  exit 1
}

if ($Machine) {
  $current = [Environment]::GetEnvironmentVariable("Path", "Machine")
  if ($current -notlike "*$goRoot*") {
    [Environment]::SetEnvironmentVariable("Path", "$current;$goRoot", "Machine")
    Write-Host "Added Go to MACHINE Path. Restart your terminal."
  } else {
    Write-Host "Go already in MACHINE Path."
  }
} else {
  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($current -notlike "*$goRoot*") {
    [Environment]::SetEnvironmentVariable("Path", "$current;$goRoot", "User")
    Write-Host "Added Go to USER Path. Restart your terminal."
  } else {
    Write-Host "Go already in USER Path."
  }
}
