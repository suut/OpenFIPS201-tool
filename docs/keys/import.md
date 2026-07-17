# `./openfips201.py keys import`

This command imports a private key from the following formats:
- Traditional OpenSSL DER format
- Encrypted PKCS#8 format
- Unencrypted PKCS#8 format
- OpenSSH format
- OpenPGP format
- Raw binary format (for symmetric keys)

If the key is encrypted the password will be prompted on the command-line.

For elliptic curve keys, only keys with named curves P-256 and P-384 are supported. 

The `--no-rsa-crt` option must be given if the key slot was created as a RSA key slot without the RSA CRT private key
format. 

## Usage

```
usage: openfips201.py keys import [-h] [--no-rsa-crt] KEY-ID ALGO KEY

positional arguments:
  KEY-ID        Key ID (9A, 9C, ...)
  ALGO          The key algorithm (choices are tdea192, rsa1024, rsa2048, rsa3072, rsa4096, aes128, aes192, aes256, ecc256, ecc384, cs2, cs7)
  KEY           The file from which to read the key

options:
  -h, --help    show this help message and exit
  --no-rsa-crt  Do not use RSA CRT for RSA keys
```

## Example

```sh
# Generate an encrypted P-256 private key
openssl genpkey -out p256.key -aes256 -pkeyopt ec_paramgen_curve:P-256

# Import the key, the password will be prompted
./openfips201.py keys import 9C ecc256 p256.key
```

See the recipe [Self-signed RSA signature certificate with imported key](../recipes/self-signed-rsa-signature-cert-with-imported-key.md)
for more details.
