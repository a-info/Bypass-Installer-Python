$TargetDir = "C:\Users\Silent-Entity\Desktop\Dev\Bypass-Installer-Python-main\dist\"
$TargetPath = "C:\Users\Silent-Entity\Desktop\Dev\Bypass-Installer-Python-main\dist\Bypass Installer.exe"

Write-Host "Adding Windows Defender Exclusion..."
Start-Process powershell -ArgumentList "-NoProfile -NonInteractive -Command Add-MpPreference -ExclusionPath '$TargetDir' -ErrorAction SilentlyContinue" -Verb RunAs -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 1000

Write-Host "Checking for existing Code Signing Certificate..."
$cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like '*CN=A! Shop*' -and $_.Subject -like '*mahabuburrahamanarnob@gmail.com*' } | Select-Object -First 1

if ($cert -eq $null) { 
    Write-Host "Certificate not found. Generating a new Self-Signed Certificate..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=A! Shop, E=mahabuburrahamanarnob@gmail.com' -CertStoreLocation Cert:\CurrentUser\My -FriendlyName 'A! Shop Code Signing'
    
    $tempFile = [System.IO.Path]::GetTempFileName() + '.cer'
    [System.IO.File]::WriteAllBytes($tempFile, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    
    Write-Host "Importing Certificate to Trusted Root..."
    Start-Process powershell -ArgumentList ("-NoProfile -Command Import-Certificate -FilePath '" + $tempFile + "' -CertStoreLocation Cert:\LocalMachine\Root") -Verb RunAs -Wait
    
    Remove-Item $tempFile -Force
} else {
    Write-Host "Certificate found: $($cert.Thumbprint)"
}

$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
if (-not (Test-Path $signtool)) { 
    $signtool = 'C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe'
}

Write-Host "Signing executable using signtool..."
& $signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td sha256 /sha1 $cert.Thumbprint $TargetPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully signed the executable!"
} else {
    Write-Host "Failed to sign executable."
}
