# `./openfips201.py keys clear`

This command clear the key in a key slot. This operation is necessary to import a new key into
a slot if it was created with `--allow-import` and a key was previously imported.

Clearing a key only clears the key for that particular algorithm, as a key slot can have any number
of algorithm present in the slot.

## Usage

```
usage: openfips201.py keys clear [-h] KEY-ID ALGO

positional arguments:
  KEY-ID      Key ID (9A, 9C, ...)
  ALGO        The key algorithm (choices are tdea192, rsa1024, rsa2048, rsa3072, rsa4096, aes128, aes192, aes256, ecc256, ecc384, cs2, cs7)

options:
  -h, --help  show this help message and exit
```

## Example

Clear the RSA 2048 signature key:

```sh
./openfips201.py keys clear 9C rsa2048
```
