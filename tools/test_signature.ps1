param(
    [string]$Path,
    [int]$WaitSeconds = 3,
    [switch]$Keep
)

$content = 'AEGIS_TEST_SIGNATURE_2026'
$expectedHash = '47fecb84a360203813e56ab3a1fdfa824e415c1c785eab90abbe26219863e0e1'

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $env:TEMP 'aegis_test_signature.js'
}

Write-Host "[AEGIS] Creating test signature file at: $Path"
[IO.File]::WriteAllBytes($Path, [System.Text.Encoding]::ASCII.GetBytes($content))

$hash = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
if ($hash -eq $expectedHash) {
    Write-Host "[AEGIS] Hash OK: $hash"
} else {
    Write-Warning "[AEGIS] Hash mismatch: $hash (expected $expectedHash)"
}

if ($WaitSeconds -gt 0) {
    Write-Host "[AEGIS] Waiting $WaitSeconds second(s) for scan..."
    Start-Sleep -Seconds $WaitSeconds
}

if (-not $Keep) {
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
    Write-Host "[AEGIS] Test file removed"
} else {
    Write-Host "[AEGIS] Test file kept"
}
