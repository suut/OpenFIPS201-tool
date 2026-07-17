# `./openfips201.py keys make-keypair-only`

This command generates a key pair and outputs the public key to a file.

This could be useful for making a certificate using a template certificate in which the public key
gets replaced by the card public key, or for bespoke applications where a X.509 certificate is not necessary
(there is no discovery mechanism for public keys if an associated certificate is not loaded, so the public key
has to be transmitted out of band).

## Usage

```
usage: openfips201.py keys make-keypair-only [-h] [-o FILE] KEY-ID ALGO

positional arguments:
  KEY-ID             Key ID (9A, 9C, ...)
  ALGO               The public-key algorithm to use (choices rsa1024, rsa2048, rsa3072, rsa4096, ecc256, ecc384, cs2, cs7)

options:
  -h, --help         show this help message and exit
  -o, --output FILE  Where to save the the public key (default card-{KEY_ID}.key)
```

## Example

Generate a P-384 key pair and output it to the file `card-signature-pub.key`:

```sh
./openfips201.py keys make-keypair-only -o card-signature-pub.key 9C ecc384
```

Show the public key using OpenSSL:

```
# openssl pkey -in card-signature-pub.key -pubin -noout -text

Public-Key: (384 bit)
pub:
    04:58:d0:43:02:f2:24:25:c5:f9:f9:93:81:0e:10:
    4f:77:6c:ae:fc:c0:93:c0:3b:54:0a:f7:fd:3b:45:
    58:40:d3:4e:c1:a8:d8:8b:21:65:65:80:66:77:18:
    64:67:c6:b7:98:3c:64:bf:c9:56:9b:d0:89:61:11:
    7f:07:1b:35:d1:19:62:31:a4:d1:ff:ab:fa:dd:74:
    77:96:ec:c2:87:27:ce:d7:a8:f4:63:66:a8:70:f2:
    5a:96:b9:2b:3d:2a:8b
ASN1 OID: secp384r1
NIST CURVE: P-384
```
