# OpenFIPS201 v2.0.0 configuration tool

This is an all-in-one administrative configuration tool for the open-source OpenFIPS201 v2.0.0 PIV applet.

All commands are sent on the GlobalPlatform SCP03 secure channel, with command and response MAC and encryption.

## Features

| Feature                              | Implementation status |
|--------------------------------------|-----------------------|
| Create initial structure             | Done (1)              |
| Create key slot                      | Done                  |
| Load arbitrary config file           | Done                  |
| Set PIN and PUK                      | Done                  |
| Set admin key `9B`                   | Done                  |
| Generate asymmetric key pair         | Done                  |
| Import key                           | Done                  |
| Load certificate                     | Done                  |
| Generate certificate signing request | Done                  |
| Generate self-signed certificate     | Done                  |
| Secure the applet                    | Done                  |
| Secure messaging CS2/CS7 management  | Untested              |

1. ACLs, PIN lengths, PIN retries, etc. are personalizable by modifying the files in `config-files/`.  
   PIN length is by default 4 to 8 digits, PUK is 8 digits; 3 retries for PIN, 9 retries for PUK.
   See [custom config](docs/recipes/custom-config.md) for more details on customizing the initialization.

## Applet installation

Install a prebuilt applet .cap file from [prebuilt-applet/](prebuilt-applet/) or build the applet yourself,
changing `APPLICATION_LABEL` in `src-platform/jc305/org/openfips201/applet/Platform.java` if you are not building for a
P71D600 target (NXP J3R452).

Then install the applet with the `CardReset` privilege as required by the specification:

```sh
java -jar gp.jar --install OpenFIPS201-v2.0-jc3.0.5-jdk11.cap --privs CardReset
```

## Tool installation, usage and recipes

- [Installation and commands overview](docs/README.md)
- Recipes:
  - [Custom config](docs/recipes/custom-config.md): load arbitrary user-defined bulk configuration for specific scenarios
  - [Self-signed RSA signature certificate with imported key](docs/recipes/self-signed-rsa-signature-cert-with-imported-key.md):
    load a self-signed certificate with an imported key in order to back up the key
  - [Sign CSR and load certificate](docs/recipes/sign-csr-and-load-certificate.md): sign a CSR into a certificate using an external
    CA and load the certificate into the card
