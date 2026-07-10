# OpenFIPS201 v2.0.0 configuration tool

This is an all-in-one administrative configuration tool for the open-source OpenFIPS201 v2.0.0 PIV applet.

All commands are sent on the GlobalPlatform SCP03 secure channel, with command and response MAC and encryption.

## Features

| Feature                              | Implementation status |
| ------------------------------------ | --------------------- |
| Create initial structure             | Done (1)              |
| Create key slot                      | Done                  |
| Set PIN and PUK                      | Done (2)              |
| Set admin key `9B`                   | Done                  |
| Delete key slot                      | Not yet               |
| Generate asymmetric key pair         | Done                  |
| Import key                           | Not yet               |
| Load certificate                     | Done (3)              |
| Generate certificate signing request | Done (4)              |
| Generate self-signed certificate     | Not yet               |

1. ACLs and PIN length are personalizable by modifying `initial_setup.py`. The PIN length is currently limited to 8 digits maximum.
2. Global PIN is not supported yet.
3. Only uncompressed certificates for now.
4. The digest algorithm is fixed to SHA-256 for now.

## Applet installation

Build the applet, change `APPLICATION_LABEL` in `src-platform/jc305/org/openfips201/applet/Platform.java` if you are not building
for a P71D600 target (J3R452).

Then install the applet with the `CardReset` privilege as required by the specification:

```sh
java -jar gp.jar --install OpenFIPS201-v2.0-jc3.0.5-jdk11.cap --privs CardReset
```

## Tool installation

Make a Python virtual environment and install the packages:

### Linux installation

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### Windows installation (Powershell)

```powershell
python -m venv .venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

You might have to run `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser` (possibly in an admin command prompt) if script execution
is disabled.

## Usage

All throughout this section, it is assumed that only one card reader is connected and that the GlobalPlatform secure channel keys are the default ones.

Otherwise you need to replace `./openfips201.py` by `./openfips201.py -r READER_INDEX --key-mac KEY_MAC --key-enc KEY_ENC`.

See `./openfips201.py --help` for more details.

### Overview of subcommands

```
usage: openfips201.py [-h] [-r READER] [--aid AID] [--key-mac KEY_MAC] [--key-enc KEY_ENC] COMMAND ...

OpenFIPS201 v2.0.0 configuration tool

options:
  -h, --help           show this help message and exit
  -r, --reader READER  PC/SC reader index to use
  --aid AID            OpenFIPS201 AID (default A000000308000010000100)
  --key-mac KEY_MAC    SCP-03 MAC key (default 404142434445464748494A4B4C4D4E4F)
  --key-enc KEY_ENC    SCP-03 ENC key (default 404142434445464748494A4B4C4D4E4F)

command:
  COMMAND
    initialize         Initialize the PIN, admin key and data objects
    create-key         Create a key slot
    delete-key         Delete a key
    set-admin-key      Set the admin key 9B
    set-pin            Set a PIN or PUK code
    make-key           Generate key pairs and certificates/certificate signing requests

Call this program without a subcommand to print version and status information
```

### Initialize the card

```
usage: openfips201.py initialize [-h] [--admin-key-algo ALGO] [--admin-key ADMIN_KEY] [--pin PIN] [--puk PUK]

options:
  -h, --help            show this help message and exit
  --admin-key-algo ALGO
                        Admin key algorithm (one of tdea192, aes128, aes192, aes256; default aes128)
  --admin-key ADMIN_KEY
                        Initial admin key (default 404142434445464748494A4B4C4D4E4F)
  --pin PIN             Initial PIN (default 123456)
  --puk PUK             Initial PIN (default 12345678)

```

The admin key is the slot `9B`.

Example:
```sh
$ ./openfips201.py initialize --pin 132435 --puk 08978675 --admin-key '0102030405060708090A0B0C0D0E0F00'
```

Initialization only happens once. Deleting all the data objects is not supported yet. Delete and reinstall the applet if it's needed.

### Set PIN and PUK

```
usage: openfips201.py set-pin [-h] [--puk | --global-pin] PIN

positional arguments:
  PIN           New PIN value

options:
  -h, --help    show this help message and exit
  --puk         Set the PUK (81) instead of the PIN (80)
  --global-pin  Set the global PIN (??) instead of the PIN (80)
```

Example:
```sh
$ ./openfips201.py set-pin 123456
```

### Set admin key `9B`

```
usage: openfips201.py set-admin-key [-h] ALGO KEY

positional arguments:
  ALGO        Key algorithm (one of tdea192, aes128, aes192, aes256)
  KEY         Key data

options:
  -h, --help  show this help message and exit
```

Example:
```sh
$ ./openfips201.py set-admin-key '0102030405060708090A0B0C0D0E0F00'
```

### Delete key

**Note: not yet implemented**

```
usage: openfips201.py delete-key [-h] KEY-ID

positional arguments:
  KEY-ID      Key ID (9A, 9C, ...)

options:
  -h, --help  show this help message and exit
```

Example:
```sh
$ ./openfips201.py delete-key 9A
```

### Key and certificate generation

```
usage: openfips201.py make-key [-h] SUBCOMMAND ...

options:
  -h, --help           show this help message and exit

subcommand:
  SUBCOMMAND
    make-keypair-only  Make a keypair and save the public key
    make-self-signed   Make a self-signed certificate
    make-csr           Make a certificate signing request intended to be signed by an external CA
    load-cert          Load a certificate
```

#### Make a bare key pair

```
usage: openfips201.py make-key make-keypair-only [-h] [-a {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}] [-o FILE] KEY-ID

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)

options:
  -h, --help            show this help message and exit
  -a, --algo {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}
                        The public-key algorithm to use (default rsa2048)
  -o, --output FILE     Where to save the the public key (default card-{KEY_ID}.key)
```

This is useful if you want to make a certificate manually with OpenSSL, starting with a template certificate with a throwaway key
then replacing the certificate's key by the card's key; then importing the certificate into the card.

Example:
```sh
$ ./openfips201.py make-key make-keypair-only -a ecc256 9A
```

#### Make self-signed certificate

**Note: not yet implemented**

```
usage: openfips201.py make-key make-self-signed [-h] [--with-key PUBKEY] [-a {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}] [-o FILE] [--from-template FROM_TEMPLATE]
                                                [--common-name COMMON_NAME] [--email-address EMAIL_ADDRESS] [--organization ORGANIZATION] [--organizational-unit ORGANIZATIONAL_UNIT]
                                                [--locality LOCALITY] [--country COUNTRY] [--key-usage KEY_USAGE] [--extended-key-usage EXTENDED_KEY_USAGE]
                                                [--critical-extended-key-usage] [--validity VALIDITY] [--ca] [--last-ca-in-chain]
                                                KEY-ID

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)

options:
  -h, --help            show this help message and exit
  --with-key PUBKEY     Use the public key that was previously generated with make-keypair-only
  -a, --algo {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}
                        The public-key algorithm to use (default rsa2048)
  -o, --output FILE     Where to save the self-signed certificate (default card-{KEY_ID}.crt)
  --from-template FROM_TEMPLATE
                        Certificate to use as a template, ignoring the other certificate parameters (default: none)
  --common-name COMMON_NAME
                        CSR/Certificate common name (default "PIV certificate {KEY_ID}")
  --email-address EMAIL_ADDRESS
                        CSR/Certificate email address (default none)
  --organization ORGANIZATION
                        CSR/Certificate organization (default none)
  --organizational-unit ORGANIZATIONAL_UNIT
                        CSR/Certificate organizational unit (default none)
  --locality LOCALITY   CSR/Certificate locality name (default none)
  --country COUNTRY     CSR/Certificate country (default none)
  --key-usage KEY_USAGE
                        CSR/Certificate key usage, comma-separated (default digitalSignature, choices are none, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
                        keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly)
  --extended-key-usage EXTENDED_KEY_USAGE
                        CSR/Certificate extended key usage, comma-separated (default clientAuth, choices are none, any, serverAuth, clientAuth, codeSigning, emailProtection,
                        timeStamping, OCSPSigning, or arbitrary OIDs)
  --critical-extended-key-usage
                        Mark the extended key usage as critical
  --validity VALIDITY   Certificate validity in days (default 30 days)
  --ca                  Make a CA certificate
  --last-ca-in-chain    Mark the certificate as the last CA in the chain (the certificate will not be able to sign other CA certificates)
```

Example:
```sh
$ ./openfips201.py make-key make-self-signed -a ecc256 \
	--common-name 'PIV website authentication' \
	--key-usage digitalSignature \
	--extended-key-usage clientAuth \
	--email-address user@example.com \
	--organization 'Foobar Inc.' \
	--country US \
	9C
```

Example: import from a template:
```sh
$ ./openfips201.py make-key make-self-signed -a ecc256 --from-template dummy-cert.pem 9C
```

#### Make a certificate signing request

```
usage: openfips201.py make-key make-csr [-h] [--with-key PUBKEY] [-a {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}] [-o FILE] KEY-ID

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)

options:
  -h, --help            show this help message and exit
  --with-key PUBKEY     Use the public key that was previously generated with make-keypair-only
  -a, --algo {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}
                        The public-key algorithm to use (default rsa2048)
  -o, --output FILE     Where to save the certificate signing request (default card-{KEY_ID}.csr)
```

Example:
```sh
$ ./openfips201.py -a rsa3072 9A
```

#### Load a certificate

```
usage: openfips201.py make-key load-cert [-h] KEY-ID CERT

positional arguments:
  KEY-ID      Key ID (9A, 9C, ...)
  CERT        Certificate

options:
  -h, --help  show this help message and exit
```

Example:
```sh
$ ./openfips201.py 9A card-9A.pem
```
