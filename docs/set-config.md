# `./openfips201.py set-config`

Load a custom YAML configuration file, either with one request or a list of requests.

For a lit of requests, the total APDU size is limited (to typically 256 bytes including the secure channel overhead).
Split the requests into several files if you get an error when loading your configuration.

See the [Custom config](recipes/custom-config.md) recipe for more details.

## Usage

```
usage: openfips201.py set-config [-h] [--bulk] FILE

positional arguments:
  FILE        The YAML file to load

options:
  -h, --help  show this help message and exit
  --bulk      Make a bulk request using a file that contains an array of requests
```

## Example

Load a YAML config file containing a single `PutDataRequest` map:

```sh
./openfips201.py set-config my-config.yaml
```

Load a YAML config file containing a list of `PutDataRequest` maps:

```sh
./openfips201.py set-config --bulk my-configs.ymal
```
