# Documentation

Everything happens in the SCP-03 secure channel, using the administrative commands (with the exception of
generating key pairs, signing and loading certificate). All the administrative commands are disabled
once the applet is set to `SECURED` with the [secure-applet](secure-applet.md) command.

## Common arguments

The following are the common arguments, which must come before the subcommand.

- `-h, --help`: show the help message
- `-r, --reader READER`: PC/SC reader index to use (0-indexed, the list is printed if there's more than 1 reader available)
- `--aid AID`: OpenFIPS201 AID (default `A000000308000010000100`)
- `--key-mac KEY_MAC`: SCP-03 MAC key (default `404142434445464748494A4B4C4D4E4F`)
- `--key-enc KEY_ENC`: SCP-03 ENC key (default `404142434445464748494A4B4C4D4E4F`)

Example:
```sh
./openfips201.py \
  --key-mac 'B0FA4D0F8DC822AF43C6608BD559661A' \
  --key-enc '51B27C4CC83F6C3EB153B9C9A98F7B38' \
  set-pin 123456
```

## Installation

Make a Python virtual environment and install the packages:

### Linux installation

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### Windows installation (PowerShell)

```powershell
python -m venv .venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

You might have to run `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser` (possibly in an admin command prompt) if script execution
is disabled.

## Usage

Once the virtual environment is installed, activate each time before running the script.

### Linux

```sh
. .venv/bin/activate
```

### Windows (PowerShell)

The same warning about the execution policy as [for installation](#windows-installation-powershell) applies everytime you activate the virtual environment.

```powershell
.\venv\Scripts\Activate.ps1
```

## Commands

- [initialize](initialize.md): Initialize the PIN, admin key and data objects
- [set-config](set-config.md): Set the config from a user-provided YAML file
- [create-key](create-key.md): Create a key slot
- [set-admin-key](set-admin-key.md): Set the admin key 9B
- [set-pin](set-pin.md): Set a PIN or PUK code
- [keys](keys.md): Generate key pairs and certificates/certificate signing requests
- [secure-applet](secure-applet.md): Set the applet state to `SECURED` and prevent further admin commands

## Recipes

- [Custom config](recipes/custom-config.md): load arbitrary user-defined bulk configuration for specific scenarios
- [Self-signed RSA signature certificate with imported key](recipes/self-signed-rsa-signature-cert-with-imported-key.md):
  load a self-signed certificate with an imported key in order to back up the key
- [Sign CSR and load certificate](recipes/sign-csr-and-load-certificate.md): sign a CSR into a certificate using an external
  CA and load the certificate into the card
