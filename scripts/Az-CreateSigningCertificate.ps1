param(
    [string] [Parameter(Mandatory = $true)] $vaultName
)

$ErrorActionPreference = 'Stop'
$DeploymentScriptOutputs = @{}

$existingCert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name SignCert

if ($existingCert -and $existingCert.Certificate.Subject -eq "CN=Azure DTL Gateway") {

    Write-Host 'Certificate SignCert in vault $vaultName is already present.'

    # $existingSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $existingCert.Name -AsPlainText

    $DeploymentScriptOutputs['thumbprint'] = $existingCert.Thumbprint
    $existingCert | Out-String
}
else {
    $policy = New-AzKeyVaultCertificatePolicy -SubjectName "CN=Azure DTL Gateway" `
        -SecretContentType "application/x-pkcs12" `
        -IssuerName Self `
        -ValidityInMonths 12 `
        -KeySize 2048 `
        -Ekus "1.3.6.1.5.5.7.3.2" `
        -KeyUsage DigitalSignature `
        -Verbose

    # private key is added as a secret that can be retrieved in the Resource Manager template
    Add-AzKeyVaultCertificate -VaultName $vaultName -Name SignCert -CertificatePolicy $policy -Verbose

    # it takes a few seconds for KeyVault to finish
    $tries = 0
    do {
        Write-Host 'Waiting for certificate creation completion...'
        Start-Sleep -Seconds 10
        $operation = Get-AzKeyVaultCertificateOperation -VaultName $vaultName -Name SignCert
        $tries++

        if ($operation.Status -eq 'failed') {
            throw 'Creating certificate SignCert in vault $vaultName failed with error $($operation.ErrorMessage)'
        }

        if ($tries -gt 120) {
            throw 'Timed out waiting for creation of certificate SignCert in vault $vaultName'
        }
    } while ($operation.Status -ne 'completed')

    $password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | % { [char] $_ })

    # Start-Sleep -Seconds 20

    $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name SignCert

    # Start-Sleep -Seconds 20

    $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $cert.Name -AsPlainText
    $secretByte = [Convert]::FromBase64String($secret)
    $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($secretByte, "", "Exportable,PersistKeySet")
    $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
    $pfxFileByte = $x509Cert.Export($type, $password)
    $pfxBase64 = [System.Convert]::ToBase64String($pfxFileByte)


    $DeploymentScriptOutputs['cert'] = $cert
    $DeploymentScriptOutputs['x509Cert'] = $x509Cert

    $DeploymentScriptOutputs['thumbprint'] = $cert.Thumbprint
    $DeploymentScriptOutputs['password'] = $password
    $DeploymentScriptOutputs['base64'] = $pfxBase64

    $cert | Out-String
}
