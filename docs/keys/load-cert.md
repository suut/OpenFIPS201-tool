# `./openfips201.py keys load-cert`

This command loads a certificate corresponding to a given key slot.

Certificates are supported in PEM format and DER format. 

## Usage

```
usage: openfips201.py keys load-cert [-h] [--no-compression] KEY-ID CERT

positional arguments:
  KEY-ID            Key ID (9A, 9C, ...)
  CERT              Certificate

options:
  -h, --help        show this help message and exit
  --no-compression  Do not use GZIP compression
```

## Example

Load the certificate `card-9C.crt` into key slot `9C` with GZip compression:

```sh
./openfips201.py keys load-cert 9C card-9C.crt
```

See the recipe [Sign CSR and load certificate](../recipes/sign-csr-and-load-certificate.md) for more details.
