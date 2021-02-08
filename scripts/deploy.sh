#!/bin/bash

DIR=$(dirname $0)

if [ $# -eq 0 ]; then
  echo "Usage:"
  echo "================================================================"
  exit 0
fi

while [ $# -gt 0 ]; do
  if [[ $1 == *"--"* ]]; then
    param="${1/--/}"
    declare PARAM_${param^^}="$2"
    # echo "PARAM_${param^^}=$2"
  fi
  shift
done

fail () {
    echo >&2 "$@"
    exit 1
}


readonly TEMPLATE="$( find $DIR -maxdepth 1 -iname "azuredeploy.json" )"
[ -f "$TEMPLATE" ] || fail "Missing deployment template 'azuredeploy.json' in $DIR"

[ -z "$PARAM_SUBSCRIPTION" ] && { PARAM_SUBSCRIPTION="$(az account show --query 'id' -o tsv)"; }
az account set -s "$PARAM_SUBSCRIPTION" || fail "Failed to set/identify subscription context"

[ -z "$PARAM_RESOURCEGROUP" ] && fail "ResourceGroup name must not be empty"
[ "$(az group exists -n $PARAM_RESOURCEGROUP)" == "true" ] || fail "ResourceGroup could not be found"

[ -z "$PARAM_RESET" ] && { PARAM_RESET="false"; }
[[ "TRUE|FALSE" == *"${PARAM_RESET^^}"* ]] || fail "Reset must be 'true' or 'false'"

PARAM_INSTANCECOUNT=$(echo "$PARAM_INSTANCECOUNT" | sed 's/[^0-9]*//g')
[ -z "$PARAM_INSTANCECOUNT" ] && { PARAM_INSTANCECOUNT=0; }

[ -z "$PARAM_ADMINUSERNAME" ] && fail "Admin username must not be empty"
[ -z "$PARAM_ADMINPASSWORD" ] && fail "Admin password must not be empty"

[ -f "$PARAM_SSLCERTIFICATE" ] ||	fail "SSL certificate could not be found"
[ -z "$PARAM_SSLCERTIFICATEPASSWORD" ] && fail "SSL certificate password must not be empty"

SSLCERTIFICATE_ENCODED=$( base64 $PARAM_SSLCERTIFICATE )
SSLCERTIFICATE_THUMBPRINT=$( openssl pkcs12 -in $PARAM_SSLCERTIFICATE -nodes -passin pass:$PARAM_SSLCERTIFICATEPASSWORD | openssl x509 -noout -fingerprint | cut -d "=" -f 2 | sed 's/://g' )
SSLCERTIFICATE_COMMONNAME=$( openssl pkcs12 -in $PARAM_SSLCERTIFICATE -nodes -passin pass:$PARAM_SSLCERTIFICATEPASSWORD | openssl x509 -noout -subject | rev | cut -d "=" -f 1 | rev | sed 's/ //g' )

[ -f "$PARAM_SIGNINGCERTIFICATE" ] ||	fail "Signing certificate could not be found"
[ -z "$PARAM_SIGNINGCERTIFICATEPASSWORD" ] && fail "Signing certificate password must not be empty"

SIGNINGCERTIFICATE_ENCODED=$( base64 $PARAM_SIGNINGCERTIFICATE )
SIGNINGCERTIFICATE_THUMBPRINT=$( openssl pkcs12 -in $PARAM_SIGNINGCERTIFICATE -nodes -passin pass:$PARAM_SIGNINGCERTIFICATEPASSWORD | openssl x509 -noout -fingerprint | cut -d "=" -f 2 | sed 's/://g' )

TEMPLATE_PARAMS+=( --parameters adminUsername="$PARAM_ADMINUSERNAME" )
TEMPLATE_PARAMS+=( --parameters adminPassword="$PARAM_ADMINPASSWORD" )

TEMPLATE_PARAMS+=( --parameters sslCertificate="$SSLCERTIFICATE_ENCODED" )
TEMPLATE_PARAMS+=( --parameters sslCertificatePassword="$PARAM_SSLCERTIFICATEPASSWORD" )
TEMPLATE_PARAMS+=( --parameters sslCertificateThumbprint="$SSLCERTIFICATE_THUMBPRINT" )

TEMPLATE_PARAMS+=( --parameters signCertificate="$SIGNINGCERTIFICATE_ENCODED" )
TEMPLATE_PARAMS+=( --parameters signCertificatePassword="$PARAM_SIGNINGCERTIFICATEPASSWORD" )
TEMPLATE_PARAMS+=( --parameters signCertificateThumbprint="$SIGNINGCERTIFICATE_THUMBPRINT" )

if [ "${PARAM_RESET^^}" == "TRUE" ]; then
  echo -e "\nDeleting resources ..."
  TEMPLATE_RESULT=$( az deployment group create \
    --subscription "$PARAM_SUBSCRIPTION" \
    --resource-group "$PARAM_RESOURCEGROUP" \
    --name "$( uuidgen )" \
    --no-prompt true --mode Complete \
    --template-uri "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/100-blank-template/azuredeploy.json" )
  echo -e "\nDeallocating resources ..."
  sleep 1m
fi

echo -e "\nDeploying resources ..."
TEMPLATE_RESULT=$( az deployment group create \
  --subscription "$PARAM_SUBSCRIPTION" \
  --resource-group "$PARAM_RESOURCEGROUP" \
  --name "$( uuidgen )" \
  --no-prompt true --mode Incremental \
  --template-file "$TEMPLATE" \
  "${TEMPLATE_PARAMS[@]}" )

if [ -d "$DIR/artifacts" ]; then
  echo -e "\nSynchronizing artifacts ..."
  ARTIFACTS_STORAGE=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.artifactsStorage.value' )
  ARTIFACTS_CONTAINER=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.artifactsContainer.value' )
  az storage blob sync --account-name $ARTIFACTS_STORAGE -c $ARTIFACTS_CONTAINER -s "$DIR/artifacts/" > /dev/null 2>&1 &
fi

GATEWAY_IP=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.gatewayIP.value' )
GATEWAY_FQDN=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.gatewayFQDN.value' )
GATEWAY_SCALESET=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.gatewayScaleSet.value' )
GATEWAY_FUNCTION=$( echo $TEMPLATE_RESULT | jq --raw-output '.properties.outputs.gatewayFunction.value' )

if [ $PARAM_INSTANCECOUNT -gt 0 ]; then
  echo -e "\nScaling gateway ..."
  az vmss scale --subscription "$PARAM_SUBSCRIPTION" --resource-group "$PARAM_RESOURCEGROUP" --name $GATEWAY_SCALESET --new-capacity $PARAM_INSTANCECOUNT > /dev/null 2>&1 &
fi

if [ ! -z "$GATEWAY_FUNCTION" ]; then
  echo -e "\nRenew gateway key ..."
  GATEWAY_KEY=$(az functionapp keys set \
    --subscription "$PARAM_SUBSCRIPTION" \
    --resource-group "$PARAM_RESOURCEGROUP" \
    --name "$GATEWAY_FUNCTION" \
    --key-name "gateway" \
    --key-type "functionKeys" \
    --query "value" \
    -o tsv)
fi

if [ ! -z "$SSLCERTIFICATE_COMMONNAME" ]; then
  echo -e "\nRegister Remote Desktop Gateway with your DNS using one of the following two options:"
  echo -e "- Create an A-Record:     $SSLCERTIFICATE_COMMONNAME -> $GATEWAY_IP"
  echo -e "- Create an CNAME-Record: $SSLCERTIFICATE_COMMONNAME -> $GATEWAY_FQDN"
  if [ ! -z "$GATEWAY_KEY" ]; then
    echo -e "\nGateway API endpoint:"
    echo -e "- Url:  https://$SSLCERTIFICATE_COMMONNAME/api/..."
    echo -e "- Code: $GATEWAY_KEY"
  fi
fi

echo -e "\ndone."
