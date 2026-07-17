# `./openfips201.py set-pin`

This command sets the PIN or PUK.

## Usage

```
usage: openfips201.py set-pin [-h] [--puk] PIN

positional arguments:
  PIN         New PIN value

options:
  -h, --help  show this help message and exit
  --puk       Set the PUK (81) instead of the PIN (80)
```

## Example

Set the PIN to 123456:

```sh
./openfips201.py set-pin 123456
```

Set the PUK to 12345678:

```sh
./openfips201.py set-pin --puk 12345678
```
