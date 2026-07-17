# `./openfips201.py set-admin-key`

This command sets the administrator key in the `9B` slot.

## Usage

```
usage: openfips201.py set-admin-key [-h] ALGO KEY

positional arguments:
  ALGO        Key algorithm (one of tdea192, aes128, aes192, aes256)
  KEY         Key data

options:
  -h, --help  show this help message and exit
```

## Example

Set the AES-128 admin key to `000102030405060708090A0B0C0D0E0F`:

```sh
./openfips201.py set-admin-key aes128 '000102030405060708090A0B0C0D0E0F'
```
