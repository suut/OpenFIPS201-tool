# Sign CSR and load certificate

In this recipe we generate a keypair on the card and emit a certificate signing request that we will
sign with a CA certificate using OpenSSL, then load the signed certificate into the card.

It's assumed that `./openfips201.py initialize` was already run before.

### Step 1: Create the key slot

We create the P-384 key slot `9C` for digital signature:

```sh
./openfips201.py create-key 9C ecc384 sign
```

### Step 2: Generate the key and CSR

Generate the keypair and emit the CSR at the same time:

```sh
./openfips201.py keys make-csr -o card.csr 9C ecc384
```

Inspect the CSR:
```
# openssl req -in card.csr -noout -text

Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    ...
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        ...
```

### Optional: Step 2.5: make a CA certificate and key

Make a CA certificate and the associated key pair:
```sh
openssl req -new -x509 \
  -newkey EC \
  -pkeyopt ec_paramgen_curve:P-521 \
  -keyout ca.key \
  -sha512 \
  -days +3650 \
  -subj '/CN=Test root CA' \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -out ca.pem
```

The command will prompt you for an encryption password for the private key.

Remove the `-subj '/CN=My test CA'` option in order to be prompted for the various name fields.

The certificate is created with:
- Validity: 10 years
- Public key algorithm: P-521
- Signature algorithm: ECDSA with SHA-512
- Key usage: certificate signing, CRL signing

### Step 3: Make a certificate signed by a CA

In this example the CA private key is taken from the file `ca.key`, but in practice it will be on a smartcard
or another PKCS#11 provider such as a HSM or CloudHSM. For that add the relevant `-provider` options and replace
`-CAkey ca.key` by `-CAkey pkcs11:...` with the relevant PKCS#11 URI.

The CA certificate is in `ca.pem`.

Create the file `req.cnf` and copy the following inside:
```ini
[ default ]
oid_section = oids
x509_extensions = ext

[ oids ]
mailboxValidatedStrict = 2.23.140.1.5.1.3

[ ext ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyAgreement, nonRepudiation
extendedKeyUsage = emailProtection
certificatePolicies = mailboxValidatedStrict
```

Then issue the certificate:
```sh
openssl req \
  -x509 \
  -in card.csr \
  -out card.pem \
  -CA ca.pem \
  -CAkey ca.key \
  -copy_extensions none \
  -config req.cnf \
  -addext subjectAltName=email:test@roflmao.fr \
  -subj '/CN=test@roflmao.fr' \
  -sha384
```

Inspect the certificate:
```
# openssl x509 -in card.pem -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:eb:d2:e1:73:ea:a1:a4:43:4e:25:f2:6b:e2:f3:ab:2f:e0:ae:54
        Signature Algorithm: ecdsa-with-SHA512
        Issuer: CN=Test root CA
        Validity
            Not Before: Jul 17 13:45:24 2026 GMT
            Not After : Aug 16 13:45:24 2026 GMT
        Subject: CN=test@roflmao.fr
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    ...
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Agreement
            X509v3 Extended Key Usage: 
                E-mail Protection
            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.5.1.3
            X509v3 Subject Alternative Name: 
                email:test@roflmao.fr
            X509v3 Subject Key Identifier: 
                51:A6:F9:0A:64:60:F5:4C:44:CC:A2:8D:39:B4:9E:40:93:E9:18:0E
            X509v3 Authority Key Identifier: 
                F1:6E:B4:E6:8C:9A:80:70:43:EE:4D:14:D7:87:E2:D2:EE:DE:44:E8
    Signature Algorithm: ecdsa-with-SHA512
    Signature Value:
        ...
```

### Step 4: load the certificate into the card

```sh
./openfips201.py keys load-cert 9C card.pem
```

### Step 5: verify that the PKCS#11 provider exposes the new certificate and public key

```
# pkcs11-tool -O -y cert

Using slot 2 with a present token (0x8)
Certificate Object; type = X.509 cert
  label:      Certificate for Digital Signature
  subject:    DN: CN=test@roflmao.fr
  serial:     69EBD2E173EAA1A4434E25F26BE2F3AB2FE0AE54
  ID:         02
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=test%40roflmao.fr;id=%02;object=Certificate%20for%20Digital%20Signature;type=cert
```

```
# pkcs11-tool -O -y pubkey

Using slot 2 with a present token (0x8)
Public Key Object; EC  EC_POINT 384 bits
  EC_POINT:   04610428a4e4bdc3e0d009eae04d3dc9b85590c23e472aeaf4bad70c1b774bd01fe8ad9d79e2de025be2821db3c2af6f45275d74256f3b7e44df92662388a6cbe547de62cee76e2319417ab79708ff2eb0a0b73999d670179308f2356cee05e0ff823d
  EC_PARAMS:  06052b81040022 ("secp384r1" OID:"1.3.132.0.34")
  label:      SIGN pubkey
  ID:         02
  Usage:      verify, derive
  Access:     none
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=test%40roflmao.fr;id=%02;object=SIGN%20pubkey;type=public
```