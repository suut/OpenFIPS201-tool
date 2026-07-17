# `./openfips201.py keys make-csr`

This commands emits a certificate signing request using the key in a key slot.
Optionally a key previously generated with [make-keypair-only](make-keypair-only.md) can be used.

## Usage

```
usage: openfips201.py keys make-csr [-h] [--with-key PUBKEY] [-o FILE] KEY-ID ALGO

positional arguments:
  KEY-ID             Key ID (9A, 9C, ...)
  ALGO               The public-key algorithm to use (choices rsa1024, rsa2048, rsa3072, rsa4096, ecc256, ecc384, cs2, cs7)

options:
  -h, --help         show this help message and exit
  --with-key PUBKEY  Use the public key that was previously generated with make-keypair-only
  -o, --output FILE  Where to save the certificate signing request (default card-{KEY_ID}.csr)
```

## Example

Emit a certificate signing request using a new key pair, and save it into `card-signature.csr`:
```sh
./openfips201.py keys make-csr -o card-signature.csr 9C rsa2048
```

Generate a key pair manually and use that key to emit a certificate signing request, and save it into `card-signature.csr`:
```sh
./openfips201.py keys make-keypair-only -o card-signature-pub.key 9C rsa2048

./openfips201.py keys make-csr --with-key card-signature-pub.key -o card-signature.csr 9C rsa2048 
```

Print out the generated certificate signing request:
```
# openssl req -in card-signature.csr -noout -text

Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:8c:c1:9c:55:2d:e3:bd:b2:e8:83:25:69:6a:e8:
                    f0:79:5d:f6:8c:4f:75:bf:59:1f:c6:62:90:e3:70:
                    b9:f7:fe:c0:1b:ac:d6:c3:30:b8:62:96:7c:3c:2d:
                    86:c5:05:74:7c:d0:7b:2c:14:36:cb:e7:a2:92:c9:
                    76:23:59:19:24:78:68:bc:b9:cf:e0:66:f5:14:16:
                    d1:a5:5d:70:a6:d0:c8:1c:51:1a:44:8c:bf:b0:15:
                    6f:63:9d:1d:1f:59:fd:5e:ba:b6:5a:12:80:7e:8a:
                    f7:b3:bc:3b:bf:ad:e0:3c:86:1f:d9:6e:43:25:14:
                    c9:e1:aa:0a:4c:65:95:f3:4b:3a:e7:44:cc:58:84:
                    b5:23:80:55:18:b2:da:01:9d:fe:84:b9:c8:1e:43:
                    3e:27:9d:1b:f7:18:ca:38:83:05:a7:32:1a:27:e5:
                    d7:ee:9c:92:b6:2b:08:8d:e4:cd:84:11:e6:76:5d:
                    ee:b5:c1:e9:00:0e:1f:64:5e:bd:9b:85:70:a3:d7:
                    d8:e4:13:aa:d7:1a:f4:c7:27:8c:0c:ce:a3:f6:a3:
                    40:36:2e:7e:dd:62:5f:27:c6:6f:56:33:d5:2a:b0:
                    69:1d:87:00:aa:7b:42:a4:1c:fc:01:24:ca:00:f5:
                    4c:9b:e6:02:8c:19:75:a4:2b:a2:c0:23:f2:f4:be:
                    70:91
                Exponent: 65537 (0x10001)
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        4b:12:7e:51:4f:ea:75:aa:36:06:16:25:a2:60:da:70:6d:35:
        0a:8e:82:87:e5:7a:0e:87:7d:a4:69:b7:c4:a6:70:31:e9:4f:
        f2:0c:97:41:2f:21:17:8a:ac:de:84:74:d0:86:19:64:e9:06:
        97:f9:ad:98:f0:ec:f3:c1:27:23:60:70:88:a0:32:dd:a5:31:
        71:cd:c1:74:07:6f:4e:be:d4:ea:c0:f6:e5:03:c1:b3:f5:a0:
        e4:89:ab:1e:ac:72:85:ff:a3:71:4e:f9:32:55:71:8a:13:b0:
        61:f9:58:6c:68:bc:fc:6e:5b:47:4d:a3:2a:66:e9:33:c9:8f:
        b9:d6:7e:14:cb:6b:25:f9:e9:0c:37:b7:35:f8:a6:cc:f0:46:
        b8:29:a0:f4:d0:1b:46:50:ee:01:98:e9:8f:cb:1b:89:90:5f:
        1a:94:39:64:6a:14:9c:4d:40:d9:71:ae:67:8a:37:4e:ce:f0:
        7e:87:d1:47:b3:03:80:3c:d4:c2:20:ba:0c:d1:c9:d7:bb:13:
        a6:c3:12:97:bb:cc:06:7e:0b:fa:ea:bb:fb:c3:bf:9b:73:b3:
        d4:69:34:74:81:45:12:ea:88:29:7b:61:57:99:46:16:a5:96:
        e9:28:e5:c8:46:2d:ee:2a:c9:c9:49:31:b8:18:ff:b6:79:d3:
        2d:54:c2:5e
```

See the recipe [Sign CSR and load certificate](../recipes/sign-csr-and-load-certificate.md) for more details.
