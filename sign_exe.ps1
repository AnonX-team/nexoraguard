# =============================================================================
# NexoraGuard - Self-Signed Code Signing Script (FIXED VERSION)
# Nexora Cyber Tech - 2026
# =============================================================================

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

# Files to sign
$FilesToSign = @(
    (Join-Path $Root "dist\NexoraGuard\NexoraGuard.exe"),
    (Join-Path $Root "installer\NexoraGuard_Setup.exe")
)

$PfxPath = Join-Path $Root "NexoraCyberTech.pfx"
$CertPass = ConvertTo-SecureString -String "NexoraSign2024!" -Force -AsPlainText
$Subject = "CN=Nexora Cyber Tech, O=Nexora Cyber Tech, L=Islamabad, C=PK"
$FriendlyName = "Nexora Cyber Tech Code Signing"

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  NexoraGuard Code Signing - Nexora Cyber Tech" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# -- Step 1: Check all target files exist -------------------------------------
foreach ($f in $FilesToSign) {
    if (-not (Test-Path $f)) {
        Write-Host "[ERROR] Not found: $f" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Found: $f" -ForegroundColor Green
}

# -- Step 2: Create or reuse self-signed certificate --------------------------
Write-Host "[*] Checking for existing Nexora Cyber Tech certificate..." -ForegroundColor White
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*Nexora Cyber Tech*" -and $_.HasPrivateKey } | Select-Object -First 1

if ($cert) {
    Write-Host "[OK] Reusing existing certificate: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "[*] Creating new self-signed Authenticode certificate..." -ForegroundColor White
    $cert = New-SelfSignedCertificate -Subject $Subject -FriendlyName $FriendlyName -Type CodeSigningCert -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
    Write-Host "[OK] Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
}

# -- Step 3: Export to PFX ----------------------------------------------------
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $CertPass | Out-Null
Write-Host "[OK] PFX exported to $PfxPath" -ForegroundColor Green

# -- Step 4: Add to Trusted Root CA ------------------------------------------
Write-Host "[*] Adding certificate to Trusted Root CA..." -ForegroundColor White
try {
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    if (-not ($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) { $rootStore.Add($cert) }
    $rootStore.Close()
    Write-Host "[OK] Added to LocalMachine\Root" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Admin rights needed for LocalMachine. Trying CurrentUser..." -ForegroundColor Yellow
    $userStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $userStore.Open("ReadWrite")
    if (-not ($userStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) { $userStore.Add($cert) }
    $userStore.Close()
    Write-Host "[OK] Added to CurrentUser\Root" -ForegroundColor Green
}

# -- Step 5: Sign all target files --------------------------------------------
$TIMESTAMP_SERVERS = @("http://timestamp.digicert.com", "http://timestamp.sectigo.com")

foreach ($target in $FilesToSign) {
    Write-Host "[*] Signing: $target" -ForegroundColor White
    $signed = $false
    foreach ($ts in $TIMESTAMP_SERVERS) {
        try {
            $sigResult = Set-AuthenticodeSignature -FilePath $target -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $ts
            if ($sigResult.Status -eq "Valid") {
                Write-Host "[OK] Signed with timestamp ($ts)" -ForegroundColor Green
                $signed = $true; break
            }
        } catch { continue }
    }

    if (-not $signed) {
        $sigResult = Set-AuthenticodeSignature -FilePath $target -Certificate $cert -HashAlgorithm SHA256
        if ($sigResult.Status -eq "Valid") { Write-Host "[OK] Signed (No Timestamp)" -ForegroundColor Green }
        else { Write-Host "[FAIL] Could not sign $target" -ForegroundColor Red; exit 1 }
    }
    Unblock-File -Path $target
}

Write-Host "`n[SUCCESS] ALL FILES SIGNED AND TRUSTED!" -ForegroundColor Green