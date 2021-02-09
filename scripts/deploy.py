import json
import base64
import argparse
import subprocess
from pathlib import Path
from datetime import date


# ----------------------
# args
# ----------------------

parser = argparse.ArgumentParser()

parser.add_argument('-n', '--name', required=True, help='The name of the gateway.')
parser.add_argument('-g', '--resource-group', required=True,
                    help='The resource group to deploy the gateway.')
parser.add_argument('-l', '--location', required=True, help='The location gateway.')
parser.add_argument('-s', '--subscription', required=True, help='The subscription id.')

parser.add_argument('-u', '--username', required=True,
                    help='The admin username for the gateway vms.')
parser.add_argument('-p', '--password', required=True,
                    help='The admin password for the gateway vms.')

parser.add_argument('--ssl-cert', required=True,
                    help='Path to the SSL certificate .pfx or .p12 file.')
parser.add_argument('--ssl-cert-thumbprint', required=True,
                    help='The SSL certificate thumbprint for identification in the local certificate store.')
parser.add_argument('--ssl-cert-password', required=True,
                    help='The SSL certificate password for installation.')

parser.add_argument('--sign-cert',
                    help='Path to the signing certificate .pfx or .p12 file.')
parser.add_argument('--sign-cert-thumbprint',
                    help='The signing certificate thumbprint for identification in the local certificate store.')
parser.add_argument('--sign-cert-password',
                    help='The signing certificate password for installation.')


args = parser.parse_args()

name = args.name
rg = args.resource_group
loc = args.location.lower()
sub = args.subscription

username = args.username
password = args.password


# ----------------------
# ssl cert
# ----------------------

ssl_cert = Path(args.ssl_cert)
ssl_cert_thumbprint = args.ssl_cert_thumbprint
ssl_cert_password = args.ssl_cert_password

if not ssl_cert.is_file():
    raise FileNotFoundError(ssl_cert)

with open(ssl_cert, 'rb') as f:
    ssl_cert_content = f.read()
    ssl_cert_base64 = str(base64.b64encode(ssl_cert_content), 'utf-8')

ssl_secret = base64.b64encode(json.dumps({
    'data': ssl_cert_base64,
    'dataType': 'pfx',
    'password': ssl_cert_password
}, ensure_ascii=True).encode('ascii'))


# ----------------------
# ssl & sign certs
# ----------------------

sign_cert_provided = args.sign_cert and args.sign_cert_thumbprint and args.sign_cert_password

if sign_cert_provided:

    sign_cert = Path(args.sign_cert)
    sign_cert_thumbprint = args.sign_cert_thumbprint
    sign_cert_password = args.sign_cert_password

    if not sign_cert.is_file():
        raise FileNotFoundError(sign_cert)

    with open(sign_cert, 'rb') as f:
        sign_cert_content = f.read()
        sign_cert_base64 = str(base64.b64encode(sign_cert_content), 'utf-8')

    sign_secret = base64.b64encode(json.dumps({
        'data': sign_cert_base64,
        'dataType': 'pfx',
        'password': sign_cert_password
    }, ensure_ascii=True).encode('ascii'))


# ----------------------
# azure account
# ----------------------

print('')
print('Getting Azure account information')

accountj = subprocess.run([
    'az', 'account', 'show'
], stdout=subprocess.PIPE, universal_newlines=True).stdout
try:
    account = json.loads(accountj)
except json.decoder.JSONDecodeError:
    raise EnvironmentError('Not logged in to az command line.  Please run az login then try again.')


# ----------------------
# resource group
# ----------------------

print('')
print("Checking for existing resource group '{}'".format(rg))

groupj = subprocess.run([
    'az', 'group', 'show', '-g', rg, '--subscription', sub
], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

try:
    group = json.loads(groupj)
except json.decoder.JSONDecodeError:
    print("Resource group '{}' not found, creating".format(rg))
    groupj = subprocess.run([
        'az', 'group', 'create', '-n', rg, '-l', loc, '--subscription', sub],
        stdout=subprocess.PIPE, universal_newlines=True).stdout
    group = json.loads(groupj)


# ----------------------
# deploy arm template
# ----------------------

arm_params_obj = {
    'adminUsername': {'value': username},
    'adminPassword': {'value': password},
    # 'tokenLifetime': { 'value': '' },
    'sslCertificate': {'value': ssl_cert_base64},
    'sslCertificatePassword': {'value': ssl_cert_password},
    'sslCertificateThumbprint': {'value': ssl_cert_thumbprint}
}

if sign_cert_provided:
    arm_params_obj['signCertificate'] = {'value': sign_cert_base64}
    arm_params_obj['signCertificatePassword'] = {'value': sign_cert_password}
    arm_params_obj['signCertificateThumbprint'] = {'value': sign_cert_thumbprint}


arm_params = json.dumps(arm_params_obj)

# print(arm_params)

print('\nDeploying arm template')

deployj = subprocess.run([
    'az', 'deployment', 'group', 'create', '-g', rg, '--subscription', sub,
    '-f', './azuredeploy.json',
    '-p', arm_params
], stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    deploy = json.loads(deployj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to deploy arm template: {}'.format(deployj))


# ----------------------
# upload artifacts
# ----------------------

print('\nSyncing artifacts')

syncj = subprocess.run([
    'az', 'storage', 'blob', 'sync', '--subscription', sub,
    '--account-name', deploy['properties']['outputs']['artifactsStorage']['value'],
    '--container', deploy['properties']['outputs']['artifactsContainer']['value'],
    '--source', './artifacts/'
], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout


# ----------------------
# scale gateway
# ----------------------

print('\nScaling gateway')

scalej = subprocess.run([
    'az', 'vmss', 'scale', '-g', rg, '--subscription', sub,
    '-n', deploy['properties']['outputs']['gatewayScaleSet']['value'],
    '--new-capacity', '1'
], stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    scale = json.loads(scalej)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to scale gateway: {}'.format(scalej))


print('\nDone.\n')
