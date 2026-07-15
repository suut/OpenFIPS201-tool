# `./openfips201.py create-key`

This command creates the key slot, which is necessary before generating or importing a key.

Multiple algos can be created for the same key slot, but it is not possible to recreate the same key slot with the
same algo and different parameters.

## Usage

```
usage: openfips201.py create-key [-h] [--no-rsa-crt] [--permit-external] [--permit-mutual] [--importable] [--admin-key KEY] [--mode-contact MODE] [--mode-contactless MODE]
                                 KEY-ID ALGO ROLE

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)
  ALGO                  Key algo (one of tdea192, rsa1024, rsa2048, rsa3072, rsa4096, aes128, aes192, aes256, ecc256, ecc384, cs2, cs7)
  ROLE                  Key role (one of undefined, authenticate, keyEstablish, sign)

options:
  -h, --help            show this help message and exit
  --no-rsa-crt          Do not use RSA CRT for RSA keys
  --permit-external     Permit external authenticate
  --permit-mutual       Permit mutual authenticate
  --importable          Key is importable
  --admin-key KEY       Admin key (default 9B)
  --mode-contact MODE   Contact ACL (one of never, pin, pinAlways, always, sm, vci, userAdmin; default always)
  --mode-contactless MODE
                        Contactless ACL (one of never, pin, pinAlways, always, sm, vci, userAdmin; default always)
```

- For an asymmetric key slot, only `keyEstablish` and `sign` are allowed.
- For a symmetric key slot, only `authenticate` is allowed.
- For a secure message key slot, only `keyEstablish` is allowed.

Symmetric and secure messaging types must be importable.

If the installation process was customized to remove the automatic creation of the `9B` key slot, take note that it must
be created with `--permit-mutual` in order to be used as an admin key.

## Example

Create key slot `9C` for digital signature, using RSA 2048 with a private key in CRT form for better performance:

```sh
./openfips201.py create-key 9C rsa2048 sign
```

See the recipe [Self-signed RSA signature certificate with imported key](recipes/self-signed-rsa-signature-cert-with-imported-key.md)
for a more detailed example.
