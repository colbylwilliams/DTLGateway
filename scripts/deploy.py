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

parser.add_argument('--sign-cert', required=True,
                    help='Path to the signing certificate .fx or .p12 file.')
parser.add_argument('--sign-cert-thumbprint', required=True,
                    help='The signing certificate thumbprint for identification in the local certificate store.')
parser.add_argument('--sign-cert-password', required=True,
                    help='The signing certificate password for installation.')


args = parser.parse_args()

name = args.name
rg = args.resource_group
loc = args.location.lower()
sub = args.subscription

username = args.username
password = args.password


# ----------------------
# ssl & sign certs
# ----------------------

ssl_cert = Path(args.ssl_cert)
ssl_cert_thumbprint = args.ssl_cert_thumbprint
ssl_cert_password = args.ssl_cert_password

sign_cert = Path(args.sign_cert)
sign_cert_thumbprint = args.sign_cert_thumbprint
sign_cert_password = args.sign_cert_password

if not ssl_cert.is_file():
    raise FileNotFoundError(ssl_cert)

if not sign_cert.is_file():
    raise FileNotFoundError(sign_cert)


with open(ssl_cert, 'rb') as f:
    ssl_cert_content = f.read()
    ssl_cert_base64 = str(base64.b64encode(ssl_cert_content), 'utf-8')

with open(sign_cert, 'rb') as f:
    sign_cert_content = f.read()
    sign_cert_base64 = str(base64.b64encode(sign_cert_content), 'utf-8')


ssl_secret = base64.b64encode(json.dumps({
    'data': ssl_cert_base64,
    'dataType': 'pfx',
    'password': ssl_cert_password
}, ensure_ascii=True).encode('ascii'))

sign_secret = base64.b64encode(json.dumps({
    'data': sign_cert_base64,
    'dataType': 'pfx',
    'password': sign_cert_password
}, ensure_ascii=True).encode('ascii'))


# ----------------------
# clean name
# ----------------------

namel = ''
namelc = ''
for n in name.lower():
    if n.isalpha() or n.isdigit() or n == '-':
        namel += n
        if n != '-':
            namelc += n

storage_name = namelc
kv_name = namel + '-kv'
funcapp_name = '{}-fa'.format(namel)


# ----------------------
# azure account
# ----------------------

print('')
print('Getting Azure account information')

accountj = subprocess.run([
    'az', 'account', 'show'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout
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
    'az', 'group', 'show', '-g', rg, '--subscription', sub],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

try:
    group = json.loads(groupj)
except json.decoder.JSONDecodeError:
    print("Resource group '{}' not found, creating".format(rg))
    groupj = subprocess.run([
        'az', 'group', 'create', '-n', rg, '-l', loc, '--subscription', sub],
        stdout=subprocess.PIPE, universal_newlines=True).stdout
    group = json.loads(groupj)


# ----------------------
# key vault
# ----------------------

print('')
print('Creating key vault')

kvj = subprocess.run([
    'az', 'keyvault', 'create', '-n', kv_name, '-g', rg, '--subscription', sub,
    '--enabled-for-deployment'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    kv = json.loads(kvj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to create new KeyVault: {}'.format(kvj))


# ----------------------
# ssl & sign cert
# ----------------------

print('')
print('Adding SSL certificate to key vault')

kv_secret_sslj = subprocess.run([
    'az', 'keyvault', 'secret', 'set', '--subscription', sub,
    '--vault-name', kv_name,
    '-n', 'SSLCertificate',
    '--value', ssl_secret],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    kv_secret_ssl = json.loads(kv_secret_sslj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to add ssl certificate to KeyVault: {}'.format(kv_secret_sslj))

print('Adding signing certificate to key vault')

kv_secret_signj = subprocess.run([
    'az', 'keyvault', 'secret', 'set', '--subscription', sub,
    '--vault-name', kv_name,
    '-n', 'SignCertificate',
    '--value', sign_secret],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    kv_secret_sign = json.loads(kv_secret_signj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to add signing certificate to KeyVault: {}'.format(kv_secret_signj))


# ----------------------
# storage account
# ----------------------

print('')
print('Creating storage account')

storagej = subprocess.run([
    'az', 'storage', 'account', 'create', '-n', storage_name, '-g', rg, '--subscription', sub],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    storage = json.loads(storagej)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to create new storage account: {}'.format(storagej))


# ----------------------
# storage container
# ----------------------

print('')
print("Creating container 'deploy' in storage account")

container_deployj = subprocess.run([
    'az', 'storage', 'container', 'create', '--account-name', storage_name,
    '-n', 'deploy'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

try:
    container_deploy = json.loads(container_deployj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        "Failed to create container 'deploy' container in storage account: {}".format(container_deployj))


# ----------------------
# upload files
# ----------------------

print('')
print("Uploading file 'RDGatewayFedAuth.msi' to storage")

file_auth = subprocess.run([
    'az', 'storage', 'blob', 'upload', '--account-name', storage_name, '-c', 'deploy',
    '-n', 'RDGatewayFedAuth.msi',
    '-f' './deploy/RDGatewayFedAuth.msi'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

print("Uploading file 'azuredeploy-gateway.ps1' to storage")

file_deploy = subprocess.run([
    'az', 'storage', 'blob', 'upload', '--account-name', storage_name, '-c', 'deploy',
    '-n', 'azuredeploy-gateway.ps1',
    '-f' './deploy/azuredeploy-gateway.ps1'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout


# ----------------------
# sas tokens
# ----------------------

print('')
print("Getting SAS token for file 'RDGatewayFedAuth.msi'")

sas_expiry = date.fromisocalendar(2022, 1, 1)
sas_expiry = sas_expiry.strftime('%Y-%m-%dT%H:%MZ')

file_auth_sas = subprocess.run([
    'az', 'storage', 'blob', 'generate-sas', '--account-name', storage_name, '-c', 'deploy',
    '-n', 'RDGatewayFedAuth.msi',
    '--permissions', 'r',
    '--expiry', sas_expiry,
    '--full-uri'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

print("Getting SAS token for file 'azuredeploy-gateway.ps1'")

file_deploy_sas = subprocess.run([
    'az', 'storage', 'blob', 'generate-sas', '--account-name', storage_name, '-c', 'deploy',
    '-n', 'azuredeploy-gateway.ps1',
    '--permissions', 'r',
    '--expiry', sas_expiry,
    '--full-uri'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout


# ----------------------
# function app
# ----------------------

print('')
print('Creating function app plan')

funcapp_planj = subprocess.run([
    'az', 'functionapp', 'plan', 'create', '-g', rg, '--subscription', sub,
    '-n', funcapp_name,
    '-l', loc,
    '--sku', 'EP1'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

try:
    funcapp_plan = json.loads(funcapp_planj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to create new function app plan: {}'.format(funcapp_planj))

print('')
print('Creating function app')

funcappj = subprocess.run([
    'az', 'functionapp', 'create', '-g', rg, '--subscription', sub,
    '-n', funcapp_name,
    '-p', funcapp_plan['id'],
    '--storage-account', storage_name,
    '--assign-identity',
    '--scope', kv['id'],
    '--runtime', 'dotnet',
    '--functions-version', '3'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout

try:
    funcapp = json.loads(funcappj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to create new function app: {}'.format(funcappj))


# ----------------------
# key vault policy
# ----------------------

print('')
print('Creating key vault policy for function app')

kv_policyj = subprocess.run([
    'az', 'keyvault', 'set-policy', '-n', kv_name, '-g', rg, '--subscription', sub,
    '--secret-permissions', 'get',
    '--object-id', funcapp['identity']['principalId']],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    kv_policy = json.loads(kv_policyj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create keyvault policy for function app: {}'.format(kv_policyj))


# ----------------------
# function app settings
# ----------------------

print('')
print('Updating function app settings')

funcapp_settingsj = subprocess.run([
    'az', 'functionapp', 'config', 'appsettings', 'set', '-n', funcapp_name, '-g', rg, '--subscription', sub,
    '--settings',
    'SignCertificate=@Microsoft.KeyVault(SecretUri={})'.format(kv_secret_sign['id']),
    'SignCertificateUrl={}'.format(kv_secret_sign['id']),
    'TokenLifetime=00:01:00'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    funcapp_settings = json.loads(funcapp_settingsj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to update function app settings: {}'.format(funcapp_settingsj))


# ----------------------
# vm scale set
# ----------------------

print('')
print('Creating virtual machine scale set')

vmss_secrets = json.dumps([{
    'sourceVault': {'id': kv['id']},
    'vaultCertificates': [
        {'certificateUrl': kv_secret_ssl['id'], 'certificateStore': 'My'},
        {'certificateUrl': kv_secret_sign['id'], 'certificateStore': 'My'}
    ]
}])

vmssj = subprocess.run([
    'az', 'vmss', 'create', '-n', name, '-g', rg, '--subscription', sub,
    '--admin-username', username,
    '--admin-password', password,
    '--assign-identity',
    '--scope', kv['id'],
    '--backend-pool-name', '{}-bepool'.format(name),
    '--image', 'Win2019Datacenter',
    '--instance-count', '1',
    '--load-balancer', '{}-lb'.format(name),
    '--lb-nat-pool-name', '{}-nat'.format(name),
    '--public-ip-address', '{}-pip'.format(name),
    '--vnet-name', '{}-vnet'.format(name),
    '--subnet', 'default',
    '--secrets', vmss_secrets],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    vmss = json.loads(vmssj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to create new virtual machine scale set: {}'.format(vmssj))


# ----------------------
#  vmss extension
# ----------------------

print('')
print("Creating extension 'CustomScriptExtension' for virtual machine scale set")

vmss_ext_command = 'powershell.exe -ExecutionPolicy Unrestricted -Command & {{ $script = gci -Filter azuredeploy-gateway.ps1 -Recurse | sort -Descending -Property LastWriteTime | select -First 1 -ExpandProperty FullName; . $script -SslCertificateThumbprint {} -SignCertificateThumbprint {} -TokenFactoryHostname {} }}'.format(
    ssl_cert_thumbprint, sign_cert_thumbprint, funcapp['defaultHostName'])

vmss_ext_settings = json.dumps({
    'fileUrls': [
        file_auth_sas,
        file_deploy_sas
    ],
    'commandToExecute': vmss_ext_command
})

vmss_extj = subprocess.run([
    'az', 'vmss', 'extension', 'set', '-g', rg, '--subscription', sub,
    '-n', 'CustomScriptExtension',
    '--publisher', 'Microsoft.Compute',
    '--vmss-name', name,
    '--settings', vmss_ext_settings],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    vmss_ext = json.loads(vmss_extj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        "Failed to create extension 'CustomScriptExtension' for virtual machine scale set")


# ----------------------
# lb probes
# ----------------------

print('')
print("Creating probe 'HealthCheck' for load balancer")

lb_probe_health_checkj = subprocess.run([
    'az', 'network', 'lb', 'probe', 'create', '-g', rg, '--subscription', sub,
    '-n', 'HealthCheck',
    '--lb-name', '{}-lb'.format(name),
    '--port', '80',
    '--protocol', 'http',
    '--interval', '300',
    '--path', '/api/health',
    '--threshold', '2'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    lb_probe_health_check = json.loads(lb_probe_health_checkj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create new load balancer probe: {}'.format(lb_probe_health_checkj))

print("Creating probe 'Probe443' for load balancer")

lb_probe_443j = subprocess.run([
    'az', 'network', 'lb', 'probe', 'create', '-g', rg, '--subscription', sub,
    '-n', 'Probe443',
    '--lb-name', '{}-lb'.format(name),
    '--port', '443',
    '--protocol', 'tcp',
    '--interval', '5',
    '--threshold', '2'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    lb_probe_443 = json.loads(lb_probe_443j)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create new load balancer probe: {}'.format(lb_probe_443j))

print("Creating probe 'Probe3391' for load balancer")

lb_probe_3391j = subprocess.run([
    'az', 'network', 'lb', 'probe', 'create', '-g', rg, '--subscription', sub,
    '-n', 'Probe3391',
    '--lb-name', '{}-lb'.format(name),
    '--port', '3391',
    '--protocol', 'tcp',
    '--interval', '5',
    '--threshold', '2'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    lb_probe_3391 = json.loads(lb_probe_3391j)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create new load balancer probe: {}'.format(lb_probe_3391j))


# ----------------------
# lb rules
# ----------------------

print('')
print("Creating rule 'Balance443' for load balancer")

lb_rule_443j = subprocess.run([
    'az', 'network', 'lb', 'rule', 'create', '-g', rg, '--subscription', sub,
    '-n', 'Balance443',
    '--lb-name', '{}-lb'.format(name),
    '--frontend-port', '443',
    '--backend-port', '443',
    '--protocol', 'tcp',
    '--floating-ip', 'false',
    '--idle-timeout', '5',
    '--load-distribution', 'SourceIPProtocol',
    '--probe-name', 'Probe443'],  # TODO: Change to HealthCheck if function app is always on
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    lb_rule_443 = json.loads(lb_rule_443j)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create new load balancer rule: {}'.format(lb_rule_443j))

print("Creating rule 'Balance3391' for load balancer")

lb_rule_3391j = subprocess.run([
    'az', 'network', 'lb', 'rule', 'create', '-g', rg, '--subscription', sub,
    '-n', 'Balance3391',
    '--lb-name', '{}-lb'.format(name),
    '--frontend-port', '443',
    '--backend-port', '443',
    '--protocol', 'udp',
    '--floating-ip', 'false',
    '--idle-timeout', '5',
    '--load-distribution', 'SourceIPProtocol',
    '--probe-name', 'Probe3391'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    lb_rule_3391 = json.loads(lb_rule_3391j)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to create new load balancer rule: {}'.format(lb_rule_3391j))

# ----------------------
# public ip
# ----------------------

# print('')
# print('Updating public IP address domain record')

# ipj = subprocess.run([
#     'az', 'network', 'public-ip', 'update', '-g', rg, '--subscription', sub,
#     '-n', '{}-pip'.format(name),
#     '--dns-name', namel],
#     stdout=subprocess.PIPE, universal_newlines=True).stdout

# try:
#     ip = json.loads(ipj)
# except json.decoder.JSONDecodeError:
#     raise ChildProcessError('Failed to update public IP address domain record: {}'.format(ipj))


# ----------------------
# access restriction
# ----------------------

print('')
print('Restricting access to function app to vnet')

funcapp_accessj = subprocess.run([
    'az', 'functionapp', 'config', 'access-restriction', 'add', '-g', rg, '--subscription', sub,
    '-n', funcapp_name,
    '--priority', '1',
    '--rule-name', 'Allow VNet',
    '--description', 'Restrict incoming traffic to VNet',
    '--vnet-name', '{}-vnet'.format(name),
    '--subnet', 'default'],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    funcapp_access = json.loads(funcapp_accessj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError(
        'Failed to add restriction rule to function app: {}'.format(funcapp_accessj))


print('')
print('Getting public IP address')

ipj = subprocess.run([
    'az', 'network', 'public-ip', 'show', '-g', rg, '--subscription', sub,
    '-n', '{}-pip'.format(name)],
    stdout=subprocess.PIPE, universal_newlines=True).stdout

try:
    ip = json.loads(ipj)
except json.decoder.JSONDecodeError:
    raise ChildProcessError('Failed to get public IP address: {}'.format(ipj))


print('')
print('Done.')

print('')
print('The Gateways public IP address is: {}'.format(ip['ipAddress']))

print('')
