param(
  [string]$DriverPath = ".\\build\\Release\\AegisFusion.sys",
  [string]$CertSubject = "CN=AegisFusionTest"
)

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Path $DriverPath)) {
  Write-Error "Driver not found at $DriverPath"
  exit 1
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($signtool -and ($signtool.Source -notmatch "\\x64\\signtool.exe$")) {
  $signtool = $null
}

if (-not $signtool) {
  $kitsRoot = "C:\\Program Files (x86)\\Windows Kits\\10\\bin"
  if (Test-Path $kitsRoot) {
    $candidates = Get-ChildItem -Path $kitsRoot -Recurse -Filter signtool.exe |
      Where-Object { $_.FullName -match "\\x64\\signtool.exe$" } |
      ForEach-Object {
        if ($_.FullName -match "\\bin\\([^\\]+)\\x64\\signtool.exe$") {
          [pscustomobject]@{ File = $_; Version = $matches[1] }
        }
      } | Where-Object { $_ }

    if ($env:WDK_VERSION) {
      $selected = $candidates | Where-Object { $_.Version -eq $env:WDK_VERSION } | Select-Object -First 1
    }

    if (-not $selected) {
      $selected = $candidates | Sort-Object { [version]$_.Version } -Descending | Select-Object -First 1
    }

    if ($selected) {
      $signtool = $selected.File
    }
  }
}

if (-not $signtool) {
  Write-Error "signtool.exe not found. Install WDK/SDK or add signtool to PATH."
  exit 1
}

if (Test-Admin) {
  $certStore = "Cert:\LocalMachine\My"
  $trustRoot = "Cert:\LocalMachine\Root"
  $trustPublisher = "Cert:\LocalMachine\TrustedPublisher"
  $signtoolStoreArg = "/sm"
} else {
  $certStore = "Cert:\CurrentUser\My"
  $trustRoot = "Cert:\CurrentUser\Root"
  $trustPublisher = "Cert:\CurrentUser\TrustedPublisher"
  $signtoolStoreArg = ""
}

$cert = Get-ChildItem $certStore | Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1
if (-not $cert) {
  Write-Host "[DRIVER] Creating test certificate $CertSubject"
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject -CertStoreLocation $certStore

  $tempCert = Join-Path $env:TEMP "AegisFusionTest.cer"
  Export-Certificate -Cert $cert -FilePath $tempCert | Out-Null
  Import-Certificate -FilePath $tempCert -CertStoreLocation $trustPublisher | Out-Null
  Import-Certificate -FilePath $tempCert -CertStoreLocation $trustRoot | Out-Null
  Remove-Item $tempCert -Force
}

Write-Host "[DRIVER] Signing $DriverPath"
& $signtool.FullName sign $signtoolStoreArg /s My /sha1 $cert.Thumbprint /fd sha256 /tr http://timestamp.digicert.com /td sha256 $DriverPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[DRIVER] Signed successfully"
