# `./openfips201.py initialize`

This command initializes the data objects, the PIN and PUK, and the admin key.
The PIN and PUK are then set to initial values.

## Usage

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

## Example

Initialize with default values:
- Admin key `9B` of type AES-128 with key `404142434445464748494A4B4C4D4E4F`
- PIN set to 123456
- PUK set to 12345678

```sh
./openfips201.py initialize
```

## Customization

The YAML files in the `config-files/` top-level directory can be modified to fine-tune the permissions
of the created objects.

See [Custom config](recipes/custom-config.md) for the details on the YAML config files.
