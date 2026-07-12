#!/usr/bin/env python3

from pyasn1.type.univ import *

from asn1_utils import components, values, tagApp, tagCtx, tagSetApp, Optional


class AccessMode(Enumerated):  # OK
    namedValues = values({
        'never': 0,
    	'pin': 1,
    	'pinAlways': 2,
        'always': 31,
        'sm': 64,
    	'vci': 96,
    	'userAdmin': -128
    })

class KeyRole(Enumerated):  # OK
    namedValues = values({
        'undefined': 0,
        'authenticate': 1,
        'keyEstablish': 2,
        'sign': 4
    })

class KeyAttribute(BitString):  # OK
    namedValues = values({
        'none': 0,
        'permitExternal': 4,
        'permitMutual': 8,
        'importable': 16,
        'rsaCRT': 32
    })

class KeyMechanism(Enumerated):  # OK
    namedValues = values({
        'undefined': 0,
        'tdea192': 3,
        'rsa1024': 6,
        'rsa2048': 7,
        'rsa3072': 5,
        'rsa4096': 22,
        'aes128': 8,
        'aes192': 10,
        'aes256': 12,
        'ecc256': 17,
        'ecc384': 20,
        'cs2': 39,
        'cs7': 46
    })

class PinCharSet(Enumerated):  # OK
    namedValues = values({
        'numeric': 0,
        'alphaCaseVariant': 1,
        'alphaCaseInvariant': 2,
        'raw': 3
    })

class PutDataCreateObjectRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'adminKey': Optional(tagCtx(OctetString(), 17))
    })


class PutDataDeleteObjectRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11)
    })

class PutDataCreateKeyRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'keyAdmin': Optional(tagCtx(OctetString(), 17)),
        'keyMechanism': tagCtx(KeyMechanism(), 14),
        'keyRole': tagCtx(KeyRole(), 15),
        'keyAttribute': tagCtx(OctetString(), 16)
    })

class PutDataDeleteKeyRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'keyMechanism': Optional(tagCtx(KeyMechanism(), 14))
    })

class PutDataUpdateConfigRequest(Sequence):  # OK
    componentType = components({
        'restrictContactlessGlobal': Optional(tagCtx(Boolean(), 0)),
        'restrictContactlessAdmin': Optional(tagCtx(Boolean(), 1)),
        'restrictEnumeration': Optional(tagCtx(Boolean(), 2)),
        'restrictRandom': Optional(tagCtx(Boolean(), 3)),
        'vciCompatibilityMode': Optional(tagCtx(Boolean(), 4))
    })

class PutDataCreateVerifierRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'minLength': tagCtx(Integer(), 14),
        'maxLength': tagCtx(Integer(), 15),
        'retriesContact': tagCtx(Integer(), 16),
        'retriesContactless': tagCtx(Integer(), 17),
        'ruleCharset': Optional(tagCtx(PinCharSet(), 18)),
        'ruleHistory': Optional(tagCtx(Integer(), 19)),
        'ruleSequence': Optional(tagCtx(Integer(), 20)),
        'ruleRepeat': Optional(tagCtx(Integer(), 21)),
        'restrictUpdate': Optional(tagCtx(Boolean(), 22)),
    })


class PutDataDeletePinRequest(Sequence):  # OK
    componentType = components({
        'id': tagCtx(OctetString(), 11)
    })

class PutDataRequest(Choice):  # OK
    componentType = components({
        'createObjectRequest': tagApp(PutDataCreateObjectRequest(), 4, True),
        'createVerifierRequest': tagApp(PutDataCreateVerifierRequest(), 5, True),
        'createKeyRequest': tagApp(PutDataCreateKeyRequest(), 6, True),
        'updateConfigRequest': tagApp(PutDataUpdateConfigRequest(), 8, True),
        'deleteObjectRequest': tagApp(PutDataDeleteObjectRequest(), 9, True),
        'deletePinRequest': tagApp(PutDataDeletePinRequest(), 10, True),
        'deleteKeyRequest': tagApp(PutDataDeleteKeyRequest(), 11, True),
        'secureRequest': tagApp(Null(), 31, False)
    })

class PutDataBulkRequest(SequenceOf):  # OK
    componentType = PutDataRequest()
    tagSet = tagSetApp(SequenceOf(), 10, True)
