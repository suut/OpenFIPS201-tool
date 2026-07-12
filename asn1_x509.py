#!/usr/bin/env python3

import datetime

from pyasn1.type.univ import *
from pyasn1.type.char import *
from pyasn1.type.useful import *
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der import encoder as der_encoder

from asn1_utils import components, values, tagApp, tagCtx, tagSetApp, Optional, tagCtxExplicit

class DirectoryString(Choice):
    componentType = components({
        'teletexString': TeletexString(),
        'printableString': PrintableString(),
        'universalString': UniversalString(),
        'utf8String': UTF8String(),
        'bmpString': BMPString(),
        'ia5String': IA5String()
    })

class OtherName(Sequence):
    componentType = components({
        'type-id': ObjectIdentifier(),
        'value': tagCtxExplicit(Any(), 0)
    })

class EDIPartyName(Sequence):
    componentType = components({
        'nameAssigned': Optional(tagCtx(DirectoryString(), 0, True)),
        'partyName': tagCtx(DirectoryString(), 1)
    })

class AttributeTypeAndValue(Sequence):
    componentType = components({
        'type': ObjectIdentifier(),
        'value': DirectoryString()
    })

class RelativeDistinguishedName(SetOf):
    componentType = AttributeTypeAndValue()

class Name(SequenceOf):
    componentType = RelativeDistinguishedName()

class GeneralName(Choice):
    componentType = components({
        'otherName': tagCtx(OtherName(), 0),
        'rfc822Name': tagCtx(IA5String(), 1),
        'dNSName': tagCtx(IA5String(), 2),
        'x400Address': tagCtx(Sequence(), 3, True),
        'directoryName': tagCtx(Name(), 4, True),
        'ediPartyName': tagCtx(EDIPartyName(), 5, True),
        'uniformResourceIdentifier': tagCtx(IA5String(), 6),
        'iPAddress': tagCtx(OctetString(), 7),
        'registeredID': tagCtx(ObjectIdentifier(), 8)
    })

class GeneralNames(SequenceOf):
    componentType = GeneralName()

class AlgorithmIdentifier(Sequence):
    componentType = components({
        'algorithm': ObjectIdentifier(),
        'parameters': Optional(Any())
    })

class Time(Choice):
    componentType = components({
        'utcTime': UTCTime(),
        'generalTime': GeneralizedTime(),
    })

class Validity(Sequence):
    componentType = components({
        'notBefore': Time(),
        'notAfter': Time()
    })

class SubjectPublicKeyInfo(Sequence):
    componentType = components({
        'algorithm': AlgorithmIdentifier(),
        'subjectPublicKey': BitString()
    })

class Attribute(Sequence):
    componentType = components({
        'type': ObjectIdentifier(),
        'values': SetOf(Any())
    })

class Attributes(SetOf):
    componentType = Attribute()

class Extension(Sequence):
    componentType = components({
        'extnID': ObjectIdentifier(),
        'critical': Optional(Boolean()),
        'extnValue': OctetString()
    })

class Extensions(SequenceOf):
    componentType = Extension()

class AKID(Sequence):
    componentType = components({
        'identifier': tagCtx(OctetString(), 0)
    })

class SKID(Choice):
    componentType = components({
        'identifier': OctetString()
    })

class BasicConstraints(Sequence):
    componentType = components({
        'cA': Boolean(),
        'pathLenConstraint': Optional(Integer())
    })

class KeyUsage(BitString):
    namedValues = values({
        'digitalSignature': 0,
        'nonRepudiation': 1,
        'keyEncipherment': 2,
        'dataEncipherment': 3,
        'keyAgreement': 4,
        'keyCertSign': 5,
        'cRLSign': 6,
        'encipherOnly': 7,
        'decipherOnly': 8
    })

class ExtKeyUsage(SequenceOf):
    componentType = ObjectIdentifier()

class TBSCertificate(Sequence):
    componentType = components({
        'version': tagCtxExplicit(Integer(), 0),
        'serialNumber': Integer(),
        'signature': AlgorithmIdentifier(),
        'issuer': Name(),
        'validity': Validity(),
        'subject': Name(),
        'subjectPublicKeyInfo': SubjectPublicKeyInfo(),
        'issuerUniqueID': Optional(tagCtx(BitString(), 1)),
        'subjectUniqueID': Optional(tagCtx(BitString(), 2)),
        'extensions': Optional(tagCtxExplicit(Extensions(), 3))
    })

class Certificate(Sequence):
    componentType = components({
        'tbsCertificate': TBSCertificate(),
        'signatureAlgorithm': AlgorithmIdentifier(),
        'signatureValue': BitString()
    })

class CertificationRequestInfo(Sequence):
    componentType = components({
        'version': Integer(),
        'subject': Name(),
        'subjectPKInfo': SubjectPublicKeyInfo(),
        'attributes': tagCtx(Attributes(), 0, True)
    })

class CertificationRequest(Sequence):
    componentType = components({
        'certificationRequestInfo': CertificationRequestInfo(),
        'signatureAlgorithm': AlgorithmIdentifier(),
        'signature': BitString()
    })

class RSAPublicKey(Sequence):
    componentType = components({
        'modulus': Integer(),
        'publicExponent': Integer()
    })


def encode_authority_key_identifier(key_hash: bytes) -> bytes:
    return der_encoder.encode(AKID().setComponentByName('identifier', key_hash))


def encode_subject_key_identifier(key_hash: bytes) -> bytes:
    return der_encoder.encode(SKID().setComponentByName('identifier', key_hash))


def encode_basic_constraints(ca: bool, path_len: int|None = None) -> bytes:
    constraints = BasicConstraints()
    constraints['cA'] = ca
    if path_len is not None:
        constraints['pathLen'] = path_len
    return der_encoder.encode(constraints)


def encode_key_usage(usages: list[str]) -> bytes:
    bitfield = 0
    for usage in usages:
        bitfield |= (1 << KeyUsage.namedValues[usage])
    return der_encoder.encode(KeyUsage(bitfield))


def encode_ext_key_usage(usages: list[str]) -> bytes:
    ext_key_usage = ExtKeyUsage()
    for usage in usages:
        if usage == 'anyExtendedKeyUsage':
            ext_key_usage.append(oids['anyExtendedKeyUsage'])
        else:
            ext_key_usage.append(oids[f'id-kp-{usage}'])
    return der_encoder.encode(ext_key_usage)


def encode_subject_alt_name_emails(emails, **fmt):
    names = GeneralNames()
    for email in emails:
        name = GeneralName()
        name['rfc822Name'] = email.format(**fmt)
        names.append(name)
    return der_encoder.encode(names)


def make_utctime(time: datetime.datetime, yeardigits=2) -> UTCTime:
    if yeardigits == 2:
        fmt = '%y%m%d%H%M%SZ'
    elif yeardigits == 4:
        fmt = '%Y%m%d%H%M%SZ'
    else:
        raise ValueError('Either 2 or 4 digits for the year')
    return UTCTime(time.astimezone(datetime.timezone.utc).strftime(fmt))


oids = {
    'sha1-with-rsa-signature': ObjectIdentifier('1.2.840.113549.1.1.5'),
    'sha224WithRSAEncryption': ObjectIdentifier('1.2.840.113549.1.1.14'),
    'sha256WithRSAEncryption': ObjectIdentifier('1.2.840.113549.1.1.11'),
    'sha384WithRSAEncryption': ObjectIdentifier('1.2.840.113549.1.1.12'),
    'sha512WithRSAEncryption': ObjectIdentifier('1.2.840.113549.1.1.13'),
    'ecdsa-with-SHA1': ObjectIdentifier('1.2.840.10045.4.1'),
    'ecdsa-with-SHA224': ObjectIdentifier('1.2.840.10045.4.3.1'),
    'ecdsa-with-SHA256': ObjectIdentifier('1.2.840.10045.4.3.2'),
    'ecdsa-with-SHA384': ObjectIdentifier('1.2.840.10045.4.3.3'),
    'ecdsa-with-SHA512': ObjectIdentifier('1.2.840.10045.4.3.4'),
    'rsaEncryption': ObjectIdentifier('1.2.840.113549.1.1.1'),
    'commonName': ObjectIdentifier('2.5.4.3'),
    'serialNumber': ObjectIdentifier('2.5.4.5'),
    'countryName': ObjectIdentifier('2.5.4.6'),
    'localityName': ObjectIdentifier('2.5.4.7'),
    'stateOrProvinceName': ObjectIdentifier('2.5.4.8'),
    'streetAddress': ObjectIdentifier('2.5.4.9'),
    'organizationName': ObjectIdentifier('2.5.4.10'),
    'organizationalUnitName': ObjectIdentifier('2.5.4.11'),
    'emailAddress': ObjectIdentifier('1.2.840.113549.1.9.1'),
    'ecPublicKey': ObjectIdentifier('1.2.840.10045.2.1'),
    'prime256v1': ObjectIdentifier('1.2.840.10045.3.1.7'),
    'ansip384r1': ObjectIdentifier('1.3.132.0.34'),
    'authorityKeyIdentifier': ObjectIdentifier('2.5.29.35'),
    'subjectKeyIdentifier': ObjectIdentifier('2.5.29.14'),
    'keyUsage': ObjectIdentifier('2.5.29.15'),
    'extKeyUsage': ObjectIdentifier('2.5.29.37'),
    'subjectAltName': ObjectIdentifier('2.5.29.17'),
    'basicConstraints': ObjectIdentifier('2.5.29.19'),
    'anyExtendedKeyUsage': ObjectIdentifier('2.5.29.37.0'),
    'id-kp-serverAuth': ObjectIdentifier('1.3.6.1.5.5.7.3.1'),
    'id-kp-clientAuth': ObjectIdentifier('1.3.6.1.5.5.7.3.2'),
    'id-kp-codeSigning': ObjectIdentifier('1.3.6.1.5.5.7.3.3'),
    'id-kp-emailProtection': ObjectIdentifier('1.3.6.1.5.5.7.3.4'),
    'id-kp-timeStamping': ObjectIdentifier('1.3.6.1.5.5.7.3.8'),
    'id-kp-OCSPSigning': ObjectIdentifier('1.3.6.1.5.5.7.3.9'),
}

rsa_signature_oids_by_digest = {
    'sha1': oids['sha1-with-rsa-signature'],
    'sha224': oids['sha224WithRSAEncryption'],
    'sha256': oids['sha256WithRSAEncryption'],
    'sha384': oids['sha384WithRSAEncryption'],
    'sha512': oids['sha512WithRSAEncryption']
}

ecdsa_signature_oids_by_digest = {
    'sha1': oids['ecdsa-with-SHA1'],
    'sha224': oids['ecdsa-with-SHA224'],
    'sha256': oids['ecdsa-with-SHA256'],
    'sha384': oids['ecdsa-with-SHA384'],
    'sha512': oids['ecdsa-with-SHA512']
}
