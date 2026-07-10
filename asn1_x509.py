#!/usr/bin/env python3
from pyasn1.type.univ import *
from pyasn1.type.char import *
from pyasn1.type.univ import ObjectIdentifier

from asn1_utils import components, values, tagApp, tagCtx, tagSetApp, Optional

class DirectoryString(Choice):
    componentType = components({
        'teletexString': TeletexString(),
        'printableString': PrintableString(),
        'universalString': UniversalString(),
        'utf8String': UTF8String(),
        'bmpString': BMPString()
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

class AlgorithmIdentifier(Sequence):
    componentType = components({
        'algorithm': ObjectIdentifier(),
        'parameters': Optional(Any())
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

oids = {
    'sha256WithRSAEncryption': ObjectIdentifier('1.2.840.113549.1.1.11'),
    'ecdsaWithSHA256': ObjectIdentifier('1.2.840.10045.4.3.2'),
    'rsaEncryption': ObjectIdentifier('1.2.840.113549.1.1.1'),
    'commonName': ObjectIdentifier('2.5.4.3'),
    'serialNumber': ObjectIdentifier('2.5.4.5'),
    'countryName': ObjectIdentifier('2.5.4.6'),
    'localityName': ObjectIdentifier('2.5.4.7'),
    'stateOrProvinceName': ObjectIdentifier('2.5.4.8'),
    'streetAddress': ObjectIdentifier('2.5.4.9'),
    'organizationName': ObjectIdentifier('2.5.4.10'),
    'organizationalUnitName': ObjectIdentifier('2.5.4.11'),
    'ecPublicKey': ObjectIdentifier('1.2.840.10045.2.1'),
    'prime256v1': ObjectIdentifier('1.2.840.10045.3.1.7'),
    'ansip384r1': ObjectIdentifier('1.3.132.0.34')
}
