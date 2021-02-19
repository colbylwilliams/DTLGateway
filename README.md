# DTLGateway

Azure DevTest Labs allows you to configure labs to use a remote desktop gateway to ensure secure access to lab virtual machines (VMs) without exposing the RDP port. Once configured, DevTestLabs changes the behavior of the lab VMs Connect button to generate a machine-specific RDP with a temporary token from the gateway service.

This approach adds security by alleviating the need to have lab VMs RDP port exposed to the internet, instead tunneling RDP traffic over HTTPS. This article walks through an example on how to set up a lab that uses token authentication to connect to lab machines.

## Prerequisites

There are two prerequisites to deploy the remote desktop gateway service; an SSL certificate, and the pluggable token authentication module installer. Details for both are below.

### TLS/SSL Certificate

A TLS/SSL certificate must be installed on the gateway machines to handle HTTPS traffic. The certificate must match the fully qualified domain name (FQDN) that will be used for the gateway service. Wild-card TLS/SSL certificates don't work.

Specifically, you'll need:

- A SSL certificate matching the fully qualified domain name (FQDN) that will be used for the gateway service from a public certificate authority exported to a .pfx or .p12 (public/private) file
- The password used when exporting the SSL certificate
- A DNS record that points the FQDN to the Azure Public IP address resource used with the gateway service

### RDGatewayFedAuth.msi

Secondly, you'll need the RDGatewayFedAuth pluggable authentication module that supports token authentication for the remote desktop gateway. RDGatewayFedAuth comes with System Center Virtual Machine Manager (VMM) images.

- Download the latest System Center Virtual Machine Manager .iso archive [here](https://my.visualstudio.com/Downloads?q=System%20Center%20Virtual%20Machine%20Manager%202019&pgroup=)
- Extract the archive and find the retrieve the file from: System Center Virtual Machine Manager > amd64 > Setup > msi > RDGatewayFedAuth.msi

## Deploy Gateway

**_Note: The gateway solution is deployed using a bash script in conjunction with an Azure Resource Manager (ARM) template. Make sure to clone the repository in a directory that you can execute a bash script._**

The following section will walk through deploying a new remote desktop gateway service.

### Setup

1. To deploy the gateway service, you'll first need to clone this repository on your local machine.
2. Copy the RDGatewayFedAuth.msi file (from the section above) to the artifacts directory located at: [`<PathToClone>/arm/gateway/artifacts`](/arm/gateway/artifacts/)

### Run deploy.sh

Next, execute the script at: [`<PathToClone>/arm/gateway/deploy.sh`](/arm/gateway/deploy.sh) with the following arguments:

- `-g` The Name of the Azure Resource Group to deploy the gateway resources. It will be created if it doesn't exist.
- `-l` Location. Values from: `az account list-locations`.
- `-s` Name or ID of the subscription to deploy the gateway resources.
- `-u` The admin username to use for the gateway service VMs.
- `-p` The admin password for the gateway service VMs.
- `-c` Path to the SSL certificate .pfx or .p12 file.
- `-k` The password used to export the SSL certificate (for installation).

#### Example

```shell
/bin/sh deploy.sh -g MyResoruceGroup -l eastus -u Admin -p SoSecure1 -c ./Cert.p12 -k 12345
```

### Configure DNS

The deploy script will take several minutes to run. When it finishes, you should see output similar to this:

```ansi
Register Remote Desktop Gateway with your DNS using one of the following two options:

  - Create an A-Record:     gateway.example.com -> 80.121.8.170
  - Create an CNAME-Record: gateway.example.com -> rdg-h2q6vzjonvnhq.eastus.cloudapp.azure.com


Use the following to configure your labs to use the gateway:

  - Gateway hostname:     gateway.example.com
  - Gateway token secret: bb1fhnulQQufXoQRkCf1Lzy2vcg/zAVUhlAhUCHd0EajG0afA8RvBA==
```

```ansi
Register Remote Desktop Gateway with your DNS using one of the following two options:

  - Create an A-Record:     gateway.example.com -> 80.121.8.170
  - Create an CNAME-Record: gateway.example.com -> rdg-h2q6vzjonvnhq.eastus.cloudapp.azure.com


Use the following to configure your labs to use the gateway:

  - Gateway hostname:     gateway.example.com
  - Gateway token secret: bb1fhnulQQufXoQRkCf1Lzy2vcg/zAVUhlAhUCHd0EajG0afA8RvBA==
```

<style>#pregreen{color:green;}</style>
<pre id="pregreen">
Register Remote Desktop Gateway with your DNS using one of the following two options:

  - Create an A-Record:     gateway.example.com -> 80.121.8.170
  - Create an CNAME-Record: gateway.example.com -> rdg-h2q6vzjonvnhq.eastus.cloudapp.azure.com


Use the following to configure your labs to use the gateway:

  - Gateway hostname:     gateway.example.com
  - Gateway token secret: bb1fhnulQQufXoQRkCf1Lzy2vcg/zAVUhlAhUCHd0EajG0afA8RvBA==
</pre>

```diff
+Register Remote Desktop Gateway with your DNS using one of the following two options:

+  - Create an A-Record:     gateway.example.com -> 80.121.8.170
+  - Create an CNAME-Record: gateway.example.com -> rdg-h2q6vzjonvnhq.eastus.cloudapp.azure.com


+ Use the following to configure your labs to use the gateway:

+  - Gateway hostname:     gateway.example.com
+  - Gateway token secret: bb1fhnulQQufXoQRkCf1Lzy2vcg/zAVUhlAhUCHd0EajG0afA8RvBA==
```


## Remote Desktop Gateway Terms

By using this template, you agree to the [Remote Desktop Gateways Terms](https://www.microsoft.com/en-us/licensing/product-licensing/products).

For further information, refer to [Remote Gateway](https://aka.ms/rds) and [Deploy your Remote Desktop environment](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-deploy-infrastructure).
