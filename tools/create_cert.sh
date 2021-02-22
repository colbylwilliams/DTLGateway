#!/bin/bash -e

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

echo "Starting script create_cert.."
echo ""

cdir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
tdir="$cdir/tmp"

if [ ! -d "$tdir" ]; then
    # echo "Creating temporary directory $tdir" >> $logFile
    echo "Creating temporary directory $tdir"
    mkdir "$tdir"
    # mkdir "$tdir/test"
fi

secretFile="$tdir/cert_in.pem"
# secretFile="$tdir/cert_in.p12"
exportFile="$tdir/cert_out.p12"

# create output file for local development
if [ ! -z "$AZ_SCRIPTS_OUTPUT_PATH" ]; then
    AZ_SCRIPTS_OUTPUT_PATH="$tdir/output.json"
fi

# create output file for local development
if [ ! -z "$AZ_SCRIPTS_PATH_OUTPUT_DIRECTORY" ]; then
    AZ_SCRIPTS_PATH_OUTPUT_DIRECTORY="$tdir"
fi

logFile="$AZ_SCRIPTS_PATH_OUTPUT_DIRECTORY/log.txt"

# echo "Starting script create_cert.." >> $logFile

certName="SignCert"

certPolicy='{
    "issuerParameters": {
        "name": "Self"
    },
    "keyProperties": {
        "exportable": true,
        "keySize": 2048,
        "keyType": "RSA",
        "reuseKey": false
    },
    "lifetimeActions": [
        {
            "action": { "actionType": "AutoRenew" },
            "trigger": { "daysBeforeExpiry": 60 }
        }
    ],
    "secretProperties": {
        "contentType": "application/x-pem-file"
    },
    "x509CertificateProperties": {
        "ekus": [ "1.3.6.1.5.5.7.3.2" ],
        "keyUsage": [ "digitalSignature" ],
        "subject": "CN=Azure DTL Gateway",
        "validityInMonths": 12
    }
}'

helpText=$(cat << endHelp

Signing Certificate Utility

Options:
  -h  View this help output text again.

  -v  KeyVault name.

  -n  Certificate name in KeyVault. Defaults to SignCert

Examples:

    $ create_cert.sh -v mykeyvault

endHelp
)

# show help text if called with no args
if (($# == 0)); then
    echo "$helpText" >&2; exit 0
fi

# get arg values
while getopts ":v:n:h:" opt; do
    case $opt in
        v)  vaultName=$OPTARG;;
        n)  certName=$OPTARG;;
        h)  echo "$helpText" >&2; exit 0;;
        \?) echo "    Invalid option -$OPTARG $helpText" >&2; exit 1;;
        :)  echo "    Option -$OPTARG requires an argument $helpText." >&2; exit 1;;
    esac
done

# check for the azure cli
if ! [ -x "$(command -v az)" ]; then
    # 'Error: az command is not installed.\n  The Azure CLI is required to run this deploy script.  Please install the Azure CLI, run az login, then try again.\n  Aborting.' >> $logFile
    echo 'Error: az command is not installed.\n  The Azure CLI is required to run this deploy script.  Please install the Azure CLI, run az login, then try again.\n  Aborting.' >&2
    exit 1
fi

# check for jq
if ! [ -x "$(command -v jq)" ]; then
    # echo 'Error: jq command is not installed.\n  jq is required to run this deploy script.  Please install jq from https://stedolan.github.io/jq/download/, then try again.\n  Aborting.' >> $logFile
    echo 'Error: jq command is not installed.\n  jq is required to run this deploy script.  Please install jq from https://stedolan.github.io/jq/download/, then try again.\n  Aborting.' >&2
    exit 1
fi


# echo "Generating certificate '$certName' in KeyVault '$vaultName'"

# remove e so az group show won't exit if an existing group isn't found
# set +e

# echo "Checking for existing certificate '$certName'" >> $logFile
# echo "Checking for existing certificate '$certName'"
# cert=$( az keyvault certificate show --vault-name $vaultName -n $certName )

# set -e

# if [ -z "$cert" ]; then

# echo "Creating new certificate '$certName'" >> $logFile
echo "Creating new certificate '$certName'"
# private key is added as a secret that can be retrieved in the Resource Manager template
az keyvault certificate create --vault-name $vaultName -n $certName -p "$certPolicy"

# echo "Getting certificate details" >> $logFile
echo "Getting certificate details"
# az keyvault certificate show --vault-name $vaultName -n $certName
cert=$( az keyvault certificate show --vault-name $vaultName -n $certName )

# az keyvault certificate download --vault-name $vaultName -n $certName -f "$tdir/test/cert.pem"

# fi

# echo "Getting secret for certificate '$certName'" >> $logFile
echo "Getting secret for certificate '$certName'"
sid=$( echo $cert | jq -r '.sid' )

# echo "Getting key for certificate '$certName'"
# kid=$( echo $cert | jq -r '.kid' )

# echo "Getting thumbprint for certificate '$certName'" >> $logFile
echo "Getting thumbprint for certificate '$certName'"
thumbprint=$( echo $cert | jq -r '.x509ThumbprintHex' )

# echo "Getting value for secret '$certName'" >> $logFile
# echo "Downloading certificate '$certName'"
# az keyvault secret show --id $sid
# secret=$( az keyvault secret show --id $sid --query value -o tsv )

az keyvault secret download --id $sid -f "$secretFile"

# echo ""
# echo "$secret"
# echo ""

# echo "Getting value for secret '$certName'" >> $logFile
# echo "Getting value for key '$certName'"
# az keyvault key show --id $kid
# key=$( az keyvault key show --id $kid --query value -o tsv )

# az keyvault key download --id $kid -f "$secretFile"

# echo ""
# echo "$key"
# echo ""

# echo "Generating random password for certificate export" >> $logFile
echo "Generating random password for certificate export"
password=$( openssl rand -base64 32 | tr -d /=+ | cut -c -16 )

echo "Exporting certificate file '$exportFile'"
openssl pkcs12 -export -in "$secretFile" -out "$exportFile" -password pass:$password -name "Azure DTL Gateway"

# echo "base64 encoding certificate file '$exportFile'" >> $logFile
# echo "base64 encoding certificate file '$exportFile'"
# certBase64=$( base64 "$exportFile" -w 0 )
certBase64=$( openssl base64 -A -in "$exportFile" )

# jq -n --arg thumbprint $thumbprint --arg password $password --arg certBase64 $certBase64 \
#       '{ "thumbprint": $thumbprint, "password": $password, "base64": $certBase64 }' > $AZ_SCRIPTS_OUTPUT_PATH

echo "{ \"thumbprint\": \"$thumbprint\", \"password\": \"$password\", \"base64\": \"$certBase64\" }" > $AZ_SCRIPTS_OUTPUT_PATH

# echo "Done." >> $logFile
echo "Done."
