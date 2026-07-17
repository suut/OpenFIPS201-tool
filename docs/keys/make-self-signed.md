# `./openfips201.py keys make-self-signed`

This command makes a self-signed certificate using the key from a slot.
Unless the existing public key is given as a file (which must match the key actually in the slot!) is given, a new key
pair is generated.

**Warning**: `ecc256` needs to be used with the SHA-256 digest, and `ecc384` with the SHA-384 digest.

## Usage

```
usage: openfips201.py keys make-self-signed [-h] [--with-key PUBKEY] [--no-load] [-o FILE] [--common-name NAME] [--email EMAIL]
                                            [--organization ORG] [--organizational-unit ORG-UNIT] [--state-or-province STATE]
                                            [--locality LOCALITY] [--country COUNTRY] [--key-usage USAGE]
                                            [--extended-key-usage EKU] [--critical-extended-key-usage] [--validity DAYS] [--ca]
                                            [--last-ca-in-chain] [--sha1 | --sha224 | --sha256 | --sha384 | --sha512]
                                            KEY-ID ALGO

positional arguments:
  KEY-ID                Key ID (9A, 9C, ...)
  ALGO                  The public-key algorithm to use (choices rsa1024, rsa2048, rsa3072, rsa4096, ecc256, ecc384)

options:
  -h, --help            show this help message and exit
  --with-key PUBKEY     Use the public key that was previously imported or generated with make-keypair-only
  --no-load             Do not automatically load the certificate into the card
  -o, --output FILE     Where to save the self-signed certificate (default card-{KEY_ID}.crt)
  --common-name NAME    Certificate common name (default "PIV certificate {KEY_ID}")
  --email EMAIL         Email address, can be given multiple times
  --organization ORG    Certificate organization (default none)
  --organizational-unit ORG-UNIT
                        Certificate organizational unit (default none)
  --state-or-province STATE
                        Certificate state or province name (default none)
  --locality LOCALITY   Certificate locality name (default none)
  --country COUNTRY     Certificate country (default none)
  --key-usage USAGE     Certificate key usage, can be given multiple times (default digitalSignature, choices are none,
                        digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign,
                        encipherOnly, decipherOnly)
  --extended-key-usage EKU
                        Certificate extended key usage, can be given multiple times (default clientAuth, choices are none,
                        anyExtendedKeyUsage, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, or
                        arbitrary OIDs)
  --critical-extended-key-usage
                        Mark the extended key usage as critical
  --validity DAYS       Certificate validity in days (default 30 days)
  --ca                  Make a CA certificate
  --last-ca-in-chain    Mark the certificate as the last CA in the chain (the certificate will not be able to sign other CA
                        certificates)
  --sha1                Use SHA-1 digest for the signature
  --sha224              Use SHA-224 digest for the signature
  --sha256              Use SHA-256 digest for the signature (default)
  --sha384              Use SHA-384 digest for the signature
  --sha512              Use SHA-512 digest for the signature
```

## Example

### TLS client authentication

Generate a TLS client authentication certificate (default value for the key usage and extended key usage) using P-256
with SHA-256 digest, valid for 1 year:

```sh
./openfips201.py keys make-self-signed \
  --country 'US' \
  --organization 'My organization' \
  --common-name 'My self-signed certificate' \
  --validity 365 \
  -o my-client-auth-certificate.crt \
  9C \
  ecc256
```

Inspect the certificate:
```
# openssl x509 -in my-client-auth-certificate.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2a:78:a5:6e:61:ab:73:63:5e:ec:d5:51:ed:15:16:65:95:31:c6:65
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=PIV certificate 9C
        Validity
            Not Before: Jul 17 11:24:36 2026 GMT
            Not After : Aug 16 11:24:36 2026 GMT
        Subject: CN=PIV certificate 9C
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                A3:AC:3E:C6:04:F8:D1:10:1D:31:D7:ED:51:8E:7E:7B:BD:54:D5:AA
            X509v3 Authority Key Identifier: 
                A3:AC:3E:C6:04:F8:D1:10:1D:31:D7:ED:51:8E:7E:7B:BD:54:D5:AA
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        ...
```

### E-mail protection

Generate an e-mail protection certificate for S/MIME, using RSA 2048 with SHA-256, valid for 10 years:

```sh
./openfips201.py keys make-self-signed \
  --common-name 'test@roflmao.com' \
  --email 'test@roflmao.com' \
  --key-usage 'digitalSignature' \
  --extended-key-usage 'emailProtection' \
  --validity 3650 \
  -o email-signing-certificate.crt \
  9C \
  rsa2048
```

Inspect the certificate:
```
# openssl x509 -in email-signing-certificate.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            27:71:f4:97:cb:65:ad:55:98:b6:51:11:0a:c0:e7:18:6f:79:2f:c8
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=test@roflmao.com
        Validity
            Not Before: Jul 17 11:34:29 2026 GMT
            Not After : Jul 14 11:34:29 2036 GMT
        Subject: CN=test@roflmao.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                B7:FA:6E:6B:B5:48:68:EF:BB:01:0F:9E:75:61:46:78:4D:50:90:E7
            X509v3 Authority Key Identifier: 
                B7:FA:6E:6B:B5:48:68:EF:BB:01:0F:9E:75:61:46:78:4D:50:90:E7
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                E-mail Protection
            X509v3 Subject Alternative Name: 
                email:test@roflmao.com
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ...
```

## Make a CA certificate which can only issue client certificates for TLS authentication

Generate a CA certificate with the path length set to 0 in order to forbid it from signing new CA certificates,
valid for 1 year.

```sh
./openfips201.py keys make-self-signed \
  --country 'US' \
  --organization 'My infrastructure' \
  --common-name 'TLS client authentication CA' \
  --key-usage 'keyCertSign' \
  --key-usage 'cRLSign' \
  --extended-key-usage 'clientAuth' \
  --ca \
  --last-ca-in-chain \
  --validity 365 \
  -o tls-client-auth-ca.crt \
  9C \
  rsa2048
```

Inspect the certificate:
```
# openssl x509 -in tls-client-auth-ca.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            18:a9:e4:20:17:90:81:cf:a6:a0:fa:65:fb:e8:0b:cb:96:a4:3b:5c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=My infrastructure, CN=TLS client authentication CA
        Validity
            Not Before: Jul 17 12:01:53 2026 GMT
            Not After : Jul 17 12:01:53 2027 GMT
        Subject: C=US, O=My infrastructure, CN=TLS client authentication CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                83:DD:D1:BB:60:8B:C3:F8:04:BE:92:17:2F:36:5F:DE:0A:52:EE:EA
            X509v3 Authority Key Identifier: 
                83:DD:D1:BB:60:8B:C3:F8:04:BE:92:17:2F:36:5F:DE:0A:52:EE:EA
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ...
```
