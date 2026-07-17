# Custom configuration

A YAML file containing a `PutDataRequest` map can be loaded using `./openfips201.py set-config`.

If `--bulk` is given on the command-line, a list of `PutDataRequest` is loaded instead. As command chaining is not
possible with `PUT DATA ADMIN`, you must limit the number of requests for a given bulk file.

When running `./openfips201.py initialize`, the files `initial_setup_1.yaml`, `initial_setup_2.yaml` and
`initial_setup_3.yaml` will be loaded as configuration.

Several YAML tags are defined:

- `!x`: hexadecimal value, for example `!x "DEADBEEF"`
- `!var`: user-supplied variable on the command-line, the only variable defined is `admin_key_algo`
          when loading the configuration with `./openfips201.py initialize`
- `!keyAttribute`: a combination of elements from the `KeyAttribute` enumeration
- `!accessMode`: a combination of elements from the `AccessMode` enumeration
- `!keyRole`: a combination of elements from the `KeyRole` enumeration

The enumerations `KeyMechanism` or `PinCharSet` do not need a special tag, just specify the value as string.

See the ASN.1 schema for [PUT DATA ADMIN](../../asn1-v2/OpenFIPS201-PUT-DATA.asn) for the details of `PutDataRequest`.

## Examples

### Create a signature key in slot `9C`

```yaml
createKeyRequest:
  id: !x "9C"
  modeContact: !accessMode "always"
  modeContactless: !accessMode "never"
  keyRole: !keyRole "sign"
  keyMechanism: "rsa2048"
  keyAdmin: !x "9B"
  keyAttribute: !keyAttribute "rsaCRT"
```

### Create key slots `9A` and `9C`

```yaml
- createKeyRequest:
    id: !x "9A"
    modeContact: !accessMode "always"
    modeContactless: !accessMode "never"
    keyRole: !keyRole "sign"
    keyMechanism: "ecc256"
    keyAdmin: !x "9B"
    keyAttribute: !keyAttribute "none"
- createKeyRequest:
    id: !x "9C"
    modeContact: !accessMode "always"
    modeContactless: !accessMode "never"
    keyRole: !keyRole "sign"
    keyMechanism: "rsa2048"
    keyAdmin: !x "9B"
    keyAttribute: !keyAttribute "rsaCRT"
```

### Create the data object for the X.509 certificate for PIV authentication

```yaml
createObjectRequest:
  id: !x "5FC105"
  modeContact: !accessMode "always"
  modeContactless: !accessMode "always"
  adminKey: !x "9B"
```

## Enumerations

### `KeyAttribute`

| Attribute        | Description                                         |
|------------------|-----------------------------------------------------|
| `none`           | no special attributes are defined                   |
| `permitExternal` | permit EXTERNAL authentication (symmetric key only) |
| `permitMutual`   | permit MUTUAL authentication (symmetric key only)   |
| `importable`     | importable (must be set for symmetric keys)         |
| `rsaCRT`         | use the performance-optimized CRT form for RSA keys |

### `AccessMode`

| Attribute   | Description                                                                       |
|-------------|-----------------------------------------------------------------------------------|
| `never`     | the object may never be accessed                                                  |
| `pin`       | PIN verification can be used to access this object                                |
| `pinAlways` | PIN verification must immediately precede every access to this object             |
| `always`    | this object may be accessed without any verification                              |
| `sm`        | the object requires secure messaging to be true                                   |
| `vci`       | the object requires secure messaging AND the VCI condition to be true             |
| `userAdmin` | the object may be managed by a cardholder who has satisfied the access conditions |

### `KeyRole`

| Attribute      | Description                                   |
|----------------|-----------------------------------------------|
| `undefined`    |                                               |
| `authenticate` | authentication, only for symmetric keys       |
| `keyEstablish` | key exchange, only for asymmetric keys and SM |
| `sign`         | signature, only for asymmetric keys           |

### `KeyMechanism`

| Mechanism   | Description                           |
|-------------|---------------------------------------|
| `undefined` | Same as `tdea192`                     |
| `tdea192`   | 3-key 3DES                            |
| `rsa1024`   | RSA 1024                              |
| `rsa2048`   | RSA 2048                              |
| `rsa3072`   | RSA 3072                              |
| `rsa4096`   | RSA 4096                              |
| `aes128`    | AES-128                               |
| `aes256`    | AES-256                               |
| `ecc256`    | NIST P-256                            |
| `ecc384`    | NIST P-384                            |
| `cs2`       | PIV SM with AES-128 and P-256 SHA-256 |
| `cs7`       | PIV SM with AES-256 and P-384 SHA-384 |

### `PinCharSet`

| Charset              | Description                                                       |
|----------------------|-------------------------------------------------------------------|
| `numeric`            | only numeric digits permitted                                     |
| `alphaCaseVariant`   | all printable alphanumeric characters permitted, case sensitive   |
| `alphaCaseInvariant` | all printable alphanumeric characters permitted, case insensitive |
| `raw`                | all binary values permitted                                       |
