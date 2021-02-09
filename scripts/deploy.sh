#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

cdir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

azureDeploy="$cdir/azuredeploy.json"
artifacts="$cdir/artifacts"

helpText=$(cat << endHelp

Remote Desktop Gateway Deploy Utility

Options:
  -h  View this help output text again.

  -g  Resource Group: The Name for the new Azure Resource Group to create.
        The value must be a string.  Resource Group names are case insensitive.
        Alphanumeric, underscore, parentheses, hyphen, period (except at the end) are valid.

  -l  Location. Values from: az account list-locations.
        You can configure the default location using az configure --defaults location=<location>.

  -s  Name or ID of subscription.
        You can configure the default subscription using az account set -s NAME_OR_ID.

  -u  The admin username for the gateway vms.

  -p  The admin password for the gateway vms.

  -c  Path to the SSL certificate .pfx or .p12 file.

  -k  The SSL certificate password for installation.

Examples:

    $ deploy.sh -g MyResoruceGroup -l eastus -u Admin -p SoSecure1 -c ./Cert.p12 -k 12345

endHelp
)

# show help text if called with no args
if (($# == 0)); then
    echo "$helpText" >&2; exit 0
fi

# get arg values
while getopts ":g:l:s:u:p:c:k:h:" opt; do
    case $opt in
        g)  resourceGroup=$OPTARG;;
        l)  region=$OPTARG;;
        s)  subscription=$OPTARG;;
        u)  adminUsername=$OPTARG;;
        p)  adminPassword=$OPTARG;;
        c)  sslCertificate=$OPTARG;;
        k)  sslCertificatePassword=$OPTARG;;
        h)  echo "$helpText" >&2; exit 0;;
        \?) echo "    Invalid option -$OPTARG $helpText" >&2; exit 1;;
        :)  echo "    Option -$OPTARG requires an argument $helpText." >&2; exit 1;;
    esac
done

if [ ! -f "$sslCertificate" ]; then
    echo "$sslCertificate not found.  Please check the path is correct and try again."
    exit 1
fi

# check for the azure cli
if ! [ -x "$(command -v az)" ]; then
    echo 'Error: az command is not installed.\n  The Azure CLI is required to run this deploy script.  Please install the Azure CLI, run az login, then try again.\n  Aborting.' >&2
    exit 1
fi

# check for jq
if ! [ -x "$(command -v jq)" ]; then
    echo 'Error: jq command is not installed.\n  jq is required to run this deploy script.  Please install jq from https://stedolan.github.io/jq/download/, then try again.\n  Aborting.' >&2
    exit 1
fi


# check if logged in to azure cli
az account show -s $subscription 1> /dev/null

if [ $? != 0 ];
then
    az login
fi


# remove e so az group show won't exit if an existing group isn't found
set +e


# check for an existing resource group
echo "\nChecking for existing resource group '$resourceGroup'"

az group show -g $resourceGroup --subscription $subscription 1> /dev/null


if [ $? != 0 ]; then
    echo "Creating resource group '$resourceGroup'"
    set -e
    (
        az group create -n $resourceGroup -l $region --subscription $subscription 1> /dev/null
    )
fi

echo "\nParsing SSL certificate\n"

sslCertificateBase64=$( base64 $sslCertificate )
sslCertificateThumbprint=$( openssl pkcs12 -in $sslCertificate -nodes -passin pass:$sslCertificatePassword | openssl x509 -noout -fingerprint | cut -d "=" -f 2 | sed 's/://g' )
sslCertificateCommonName=$( openssl pkcs12 -in $sslCertificate -nodes -passin pass:$sslCertificatePassword | openssl x509 -noout -subject | rev | cut -d "=" -f 1 | rev | sed 's/ //g' )

echo "\nDeploying arm template"

deploy=$(az deployment group create --subscription $subscription -g $resourceGroup \
         --template-file $azureDeploy \
         --parameters adminUsername=$adminUsername \
                      adminPassword=$adminPassword \
                      sslCertificate=$sslCertificateBase64 \
                      sslCertificatePassword=$sslCertificatePassword \
                      sslCertificateThumbprint=$sslCertificateThumbprint )

if [ -d "$artifacts" ]; then

  echo "\nSynchronizing artifacts"

  artifactsStorage=$( echo $deploy | jq -r '.properties.outputs.artifactsStorage.value' )
  artifactsContainer=$( echo $deploy | jq -r '.properties.outputs.artifactsContainer.value' )
  az storage blob sync --account-name $artifactsStorage -c $artifactsContainer -s "$artifacts" > /dev/null 2>&1 &
fi


gatewayIP=$( echo $deploy | jq -r '.properties.outputs.gatewayIP.value' )
gatewayFQDN=$( echo $deploy | jq -r '.properties.outputs.gatewayFQDN.value' )
gatewayScaleSet=$( echo $deploy | jq -r '.properties.outputs.gatewayScaleSet.value' )
gatewayFunction=$( echo $deploy | jq -r '.properties.outputs.gatewayFunction.value' )


echo "\nScaling gateway"

az vmss scale --subscription $subscription -g $resourceGroup -n $gatewayScaleSet --new-capacity 1 > /dev/null 2>&1 &


if [ "$gatewayFunction" != "null" ]; then

  echo "\nGetting gateway token"

  gatewayTokens=$(az functionapp function keys list --subscription $subscription -g $resourceGroup \
    -n $gatewayFunction \
    --function-name CreateToken )

  gatewayToken=$( echo $gatewayTokens | jq -r '.gateway' )

  if [ "$gatewayToken" == "null" ]; then

    echo "No gateway token found, creating"

    gatewayToken=$(az functionapp function keys set --subscription $subscription -g $resourceGroup \
      -n $gatewayFunction \
      --function-name CreateToken \
      --key-name gateway \
      --query value \
      -o tsv )
  fi
fi


GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [ ! -z "$sslCertificateCommonName" ]; then
  echo "\n\n${GREEN}Register Remote Desktop Gateway with your DNS using one of the following two options:${NC}\n"
  echo "${GREEN}  - Create an A-Record:     $sslCertificateCommonName -> $gatewayIP ${NC}"
  echo "${GREEN}  - Create an CNAME-Record: $sslCertificateCommonName -> $gatewayFQDN ${NC}"
  if [ ! -z "$gatewayToken" ]; then
    echo "\n\n${GREEN}Use the following to configure your labs to use the gateway:${NC}\n"
    echo "${GREEN}  - Gateway hostname:     $sslCertificateCommonName ${NC}"
    echo "${GREEN}  - Gateway token secret: $gatewayToken ${NC}"
  fi
fi


echo "\ndone.\n"
