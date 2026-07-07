// Convert PFX to PEM files using Node.js built-in
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const pfxPath = path.join(__dirname, 'cert.pfx');
const certPath = path.join(__dirname, 'cert.pem');
const keyPath = path.join(__dirname, 'key.pem');

if (!fs.existsSync(pfxPath)) {
  console.log('Pas de certificat PFX trouvé. Génération via PowerShell...');
  execSync(`powershell -Command "$cert = New-SelfSignedCertificate -DnsName localhost -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddYears(1) -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256; Export-PfxCertificate -Cert Cert:\\CurrentUser\\My\\$($cert.Thumbprint) -FilePath '${pfxPath.replace(/\\/g, '\\')}' -Password (ConvertTo-SecureString -String 'password123' -Force -AsPlainText)"`, { stdio: 'inherit' });
}

// Use PowerShell to convert PFX to PEM
const psScript = `
$pfxPath = '${pfxPath.replace(/\\/g, "'}'")}' 
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, "password123")
$certPem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----"
$keyRsa = [System.Security.Cryptography.X509Certificates.RSACryptoServiceProvider]($cert.PrivateKey)
$keyXml = $keyRsa.ToXmlString($true)
$keyPem = "-----BEGIN RSA PRIVATE KEY-----`n" + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($keyXml), [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END RSA PRIVATE KEY-----"
Set-Content -Path '${certPath.replace(/\\/g, '\\')}' -Value $certPem
Set-Content -Path '${keyPath.replace(/\\/g, '\\')}' -Value $keyPem
Write-Host "PEM files created"
`;

// Simpler approach: use Node's tls to read the pfx and export
const https = require('https');
const tls = require('tls');
const forge = null; // We'll do it differently

// Actually let's just write a self-signed cert using pure Node.js crypto with proper ASN.1
// This is the simplest reliable approach

console.log('Generating self-signed cert with pure Node.js...');
require('./generate-cert-final.js');
