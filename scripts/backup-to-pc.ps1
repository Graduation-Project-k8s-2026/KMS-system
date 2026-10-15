# Run on the operator's PC in PowerShell. SSH alias kms-oci must already work.
$ErrorActionPreference = 'Stop'
ssh -t ubuntu@kms-oci 'sudo bash ~/workspace/KMS-system/scripts/export-backup.sh --final'
if ($LASTEXITCODE -ne 0) { throw 'Server encryption failed; backup was not downloaded.' }
scp ubuntu@kms-oci:kms-final-v2-backup.tar.gpg .
if ($LASTEXITCODE -ne 0) { throw 'Download failed.' }
$checksum = ssh ubuntu@kms-oci 'cat kms-final-v2-backup.tar.gpg.sha256'
if ($LASTEXITCODE -ne 0) { throw 'Could not read server checksum.' }
$expected = $checksum.Trim().Split()[0]
$actual = (Get-FileHash .\kms-final-v2-backup.tar.gpg -Algorithm SHA256).Hash
if ($actual -ine $expected) { throw 'Checksum mismatch; keep the server copy and retry.' }
Write-Host 'External backup downloaded and SHA256 verified.'
Write-Host 'Keep the backup passphrase separately from this file.'
