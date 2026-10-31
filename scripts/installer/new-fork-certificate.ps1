# Creates (or reuses) the fork's self-signed code-signing certificate and exports it.
#
# The fork ships self-built Full installers whose sparse-MSIX package identity only
# needs a CONSISTENT publisher subject (CN=elboaf) - Windows derives package identity
# from the subject string, not from trust. The certificate exists so signtool can seal
# the payloads and the identity scripts' publisher checks pass. Nothing here chains to
# a public CA; machines that want Authenticode-valid installs import the exported .cer.
#
#   powershell -File scripts\installer\new-fork-certificate.ps1 -PfxPath out.pfx -PasswordText <pw>
#
# CI calls this per run: the certificate is created on the runner, used, exported beside
# the artifacts, and discarded. Same subject every time, so the package family name is
# stable across releases even though the key pair is not.
param(
  [string]$Subject = 'CN=elboaf',
  [Parameter(Mandatory = $true)][string]$PfxPath,
  [Parameter(Mandatory = $true)][string]$PasswordText
)
$ErrorActionPreference = 'Stop'
if ($Subject -notmatch '^CN=[^,]+$') { throw "Fork identity needs a single-component subject like CN=elboaf (got '$Subject')" }

$existing = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Subject -eq $Subject -and $_.HasPrivateKey -and
    ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq 'Code Signing' })
  } | Sort-Object NotAfter -Descending | Select-Object -First 1

if ($existing) {
  Write-Host "==> Reusing existing code-signing certificate $($existing.Thumbprint)"
  $cert = $existing
} else {
  Write-Host "==> Creating self-signed code-signing certificate $Subject"
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(10) -CertStoreLocation Cert:\CurrentUser\My
}

$password = ConvertTo-SecureString -String $PasswordText -Force -AsPlainText
$parent = Split-Path -Parent $PfxPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $password | Out-Null
$cerPath = $PfxPath -replace '\.pfx$', '.cer'
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
Write-Host "==> Exported $PfxPath and $cerPath (thumbprint $($cert.Thumbprint), subject '$($cert.Subject)')"
