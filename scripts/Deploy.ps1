<#
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

.SYNOPSIS
Deploys the ARM template.
#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "The resource group to deploy the gateway.")]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = "The location gateway.")]
    [string] $Location,

    [Parameter(Mandatory = $true, HelpMessage = "The admin username for the gateway vms.")]
    [string] $Username,

    [Parameter(Mandatory = $true, HelpMessage = "The admin password for the gateway vms.")]
    [securestring] $Password,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the SSL certificate .pfx or .p12 file.")]
    [string] $SSLCertificate,

    [Parameter(Mandatory = $true, HelpMessage = "The SSL certificate password for installation.")]
    [securestring] $SSLCertificatePassword,

    [Parameter(Mandatory = $false, HelpMessage = "Path to the signing certificate .pfx or .p12 file.")]
    [string] $SignCertificate,

    [Parameter(Mandatory = $false, HelpMessage = "The signing certificate password for installation.")]
    [securestring] $SignCertificatePassword
)
