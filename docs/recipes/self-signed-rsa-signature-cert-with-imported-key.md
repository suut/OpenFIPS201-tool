# Self-signed RSA signature certificate with imported key

In this recipe we use OpenSSL to configure a self-signed certificate with particular 

It's assumed that `./openfips201.py initialize` was already run before.

### Step 1: generate the key

This generates a RSA 2048 key and saves it in encrypted PKCS#8 format. The command will prompt you for a password to
encrypt the key with.

```sh
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out rsa-priv.key -outpubkey rsa-pub.key \
  -aes256
```

### Step 2: create the key slot and import the key

We create the `9C` key slot:

```sh
./openfips201.py create-key --importable 9C rsa2048 sign
```

And we import the key, using RSA CRT private key format for better performances:

```sh
./openfips201.py keys import 9C rsa2048 rsa-priv.key 
```

The command will prompt for the private key password.

### Step 3: make the certificate

You will be prompted for the private key password, as well as for the name fields.

```sh
openssl req -new -x509 \
  -key rsa-priv.key \
  -sha256 \
  -addext basicConstraints=critical,CA:FALSE \
  -addext keyUsage=critical,digitalSignature \
  -out my-certificate.pem
```

Inspect the certificate:
```
# openssl x509 -in my-certificate.pem -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            77:bd:d3:a4:ad:f9:ef:0e:b5:e5:c0:d5:2c:79:48:d8:a4:bd:99:7a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=My certificate
        Validity
            Not Before: Jul 17 12:17:09 2026 GMT
            Not After : Aug 16 12:17:09 2026 GMT
        Subject: CN=My certificate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                D0:C5:87:47:B5:34:7D:4F:08:93:27:C8:B4:CD:E2:DC:A4:6F:6A:E9
            X509v3 Authority Key Identifier: 
                D0:C5:87:47:B5:34:7D:4F:08:93:27:C8:B4:CD:E2:DC:A4:6F:6A:E9
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ...
```

### Step 4: import the certificate

This will load the certificate with GZip compression:

```sh
./openfips201.py keys load-cert 9C my-certificate.pem 
```

### Step 5: verify that the PKCS#11 provider exposes the new certificate and public key

```
# pkcs11-tool -O -y cert

Using slot 2 with a present token (0x8)
Certificate Object; type = X.509 cert
  label:      Certificate for Digital Signature
  subject:    DN: CN=My certificate
  serial:     77BDD3A4ADF9EF0EB5E5C0D52C7948D8A4BD997A
  ID:         02
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=My%20certificate;id=%02;object=Certificate%20for%20Digital%20Signature;type=cert
```

```
# pkcs11-tool -O -y pubkey

Using slot 2 with a present token (0x8)
Public Key Object; RSA 2048 bits
  label:      SIGN pubkey
  ID:         02
  Usage:      verify, verifyRecover
  Access:     none
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=My%20certificate;id=%02;object=SIGN%20pubkey;type=public
```
