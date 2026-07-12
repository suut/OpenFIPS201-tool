# OpenFIPS201 v2.0.0 configuration tool

This is an all-in-one administrative configuration tool for the open-source OpenFIPS201 v2.0.0 PIV applet.

All commands are sent on the GlobalPlatform SCP03 secure channel, with command and response MAC and encryption.

## Features

| Feature                              | Implementation status |
|--------------------------------------|-----------------------|
| Create initial structure             | Done (1)              |
| Create key slot                      | Done                  |
| Set PIN and PUK                      | Done (2)              |
| Set admin key `9B`                   | Done                  |
| Generate asymmetric key pair         | Done                  |
| Import key                           | Not yet               |
| Load certificate                     | Done (3)              |
| Generate certificate signing request | Done                  |
| Generate self-signed certificate     | Done                  |
| Secure the applet                    | Done                  |

1. ACLs and PIN length are personalizable by modifying `initial_setup.py`, default is 4 to 8 digits.
2. Global PIN is not supported yet.
3. Only uncompressed certificates for now.

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

### Windows installation (PowerShell)

```powershell
python -m venv .venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

You might have to run `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser` (possibly in an admin command prompt) if script execution
is disabled.

## Usage

All throughout this section, it is assumed that only one card reader is connected and that the GlobalPlatform secure channel keys are the default ones.

Otherwise, you need to replace `./openfips201.py` by `./openfips201.py -r READER_INDEX --key-mac KEY_MAC --key-enc KEY_ENC`.

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

Initialization only happens once. Deleting data objects or key slots (for instance to change the algo type)
is not supported by the applet. Delete and reinstall the applet if it's needed.

The data object creation can be customized in `initial_setup.py`.

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
$ ./openfips201.py set-admin-key aes128 '0102030405060708090A0B0C0D0E0F00'
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

```
usage: openfips201.py make-key make-self-signed [-h] [--with-key PUBKEY] [--no-load]
                                                [-a {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}] [-o FILE]
                                                [--common-name NAME] [--email EMAIL] [--organization ORG]
                                                [--organizational-unit ORG-UNIT] [--state-or-province STATE]
                                                [--locality LOCALITY] [--country COUNTRY] [--key-usage USAGE]
                                                [--extended-key-usage EKU] [--critical-extended-key-usage] [--validity DAYS]
                                                [--ca] [--last-ca-in-chain] [--sha1 | --sha224 | --sha256 | --sha384 | --sha512]
                                                KEY-ID

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)

options:
  -h, --help            show this help message and exit
  --with-key PUBKEY     Use the public key that was previously generated with make-keypair-only
  --no-load             Do not automatically load the certificate into the card
  -a, --algo {rsa1024,rsa2048,rsa3072,rsa4096,ecc256,ecc384}
                        The public-key algorithm to use (default rsa2048)
  -o, --output FILE     Where to save the self-signed certificate (default card-{KEY_ID}.crt)
  --common-name NAME    Certificate common name (default "PIV certificate {KEY_ID}")
  --email EMAIL         Email address, can be given multiple times
  --organization ORG    Certificate organization (default none)
  --organizational-unit ORG-UNIT
                        Certificate organizational unit (default none)
  --state-or-province STATE
                        Certificate state or province name (default none)
  --locality LOCALITY   Certificate locality name (default none)
  --country COUNTRY     Certificate country (default none)
  --key-usage USAGE     Certificate key usage, can be given multiple times (default digitalSignature, choices are none,
                        digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign,
                        encipherOnly, decipherOnly)
  --extended-key-usage EKU
                        Certificate extended key usage, can be given multiple times (default clientAuth, choices are none,
                        anyExtendedKeyUsage, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, or
                        arbitrary OIDs)
  --critical-extended-key-usage
                        Mark the extended key usage as critical
  --validity DAYS       Certificate validity in days (default 30 days)
  --ca                  Make a CA certificate
  --last-ca-in-chain    Mark the certificate as the last CA in the chain (the certificate will not be able to sign other CA
                        certificates)
  --sha1                Use SHA-1 digest for the signature
  --sha224              Use SHA-224 digest for the signature
  --sha256              Use SHA-256 digest for the signature (default)
  --sha384              Use SHA-384 digest for the signature
  --sha512              Use SHA-512 digest for the signature
```

Example:
```sh
$ ./openfips201.py make-key make-self-signed -a ecc384 \
    --sha384 \
    --validity 365 \
  --common-name 'PIV email signature' \
  --key-usage digitalSignature \
  --extended-key-usage emailProtection \
  --email user@example.com \
  --email secondary.email@example.com \
  --organization 'Foobar Inc.' \
  --country US \
  9C
```

Result:
```
$ pkcs11-tool -O -y cert -d 02
Using slot 2 with a present token (0x8)
Certificate Object; type = X.509 cert
  label:      Certificate for Digital Signature
  subject:    DN: CN=PIV email signature,O=Foobar Inc.,C=US
  serial:     69DA07518467F59008E1B4CBE48C9691550CBA94
  ID:         02
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=PIV%20email%20signature;id=%02;object=Certificate%20for%20Digital%20Signature;type=cert

$ openssl x509 -noout -text < card-9C.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:da:07:51:84:67:f5:90:08:e1:b4:cb:e4:8c:96:91:55:0c:ba:94
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C=US, O=Foobar Inc., CN=PIV email signature
        Validity
            Not Before: Jul 12 00:55:27 2026 GMT
            Not After : Jul 12 00:55:27 2027 GMT
        Subject: C=US, O=Foobar Inc., CN=PIV email signature
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:ae:6b:90:21:f7:cb:19:6d:5e:f9:2e:ba:b9:c8:
                    3c:15:7f:94:70:70:88:4a:09:ee:a9:12:38:5e:cf:
                    2f:a7:ef:83:b4:dd:c2:23:1e:5a:76:c3:a0:2e:b8:
                    6f:18:9a:20:95:df:98:3b:3b:0a:4b:18:e1:df:4c:
                    04:16:2f:3e:14:f9:9a:71:0c:d5:24:a5:03:f5:87:
                    fc:9a:9f:6a:a1:a3:c2:69:1b:37:ea:09:05:ac:4a:
                    f8:a1:dc:58:09:e4:91
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                7B:4A:4E:BC:EE:3D:6A:F0:4C:DC:CF:34:6D:43:25:F6:5E:89:EF:19
            X509v3 Authority Key Identifier:
                7B:4A:4E:BC:EE:3D:6A:F0:4C:DC:CF:34:6D:43:25:F6:5E:89:EF:19
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                E-mail Protection
            X509v3 Subject Alternative Name:
                email:user@example.com, email:secondary.email@example.com
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:31:00:83:ec:16:4f:1f:42:c7:40:cb:83:d6:91:5d:
        be:ba:4b:93:7f:01:42:33:fb:a7:67:6f:81:ec:b1:c4:76:75:
        a0:07:0d:07:75:1c:88:70:ab:0b:43:8f:0d:85:a0:c6:ca:02:
        30:5c:3a:94:a3:0a:22:60:2b:83:c4:f2:ee:03:ad:8f:58:e9:
        ff:a9:86:68:01:b2:55:92:78:5d:30:a2:2c:d7:08:b4:ac:3d:
        a6:56:0d:fe:69:87:75:56:c0:65:1a:af:7b
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

### Secure the card

This ends the administrative provisioning phase and disables the `PUT DATA ADMIN` commands which are used by this tool.

```
usage: openfips201.py secure-applet [-h]

options:
  -h, --help  show this help message and exit
```

Example:
```sh
$ ./openfips201.py secure-card
```
