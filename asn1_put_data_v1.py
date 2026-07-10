#!/usr/bin/env python3

from pyasn1.type.univ import *

from asn1_utils import components, values, tagApp, tagCtx, tagSetApp, Optional


class LegacyOperation(Enumerated):
    namedValues = values({
        'undefined': 0,
        'dataObject': 1,
        'key': 2
    })

class AccessMode(Enumerated):
    namedValues = values({
        'never': 0,
    	'pin': 1,
    	'pinAlways': 2,
        'occ': 4,
    	'userAdmin': 16,
    	'always': 127
    })

class KeyRole(Enumerated):
    namedValues = values({
        'authenticate': 1,
        'keyEstablish': 2,
        'sign': 4,
        'verify': 8,
        'encrypt': 16,
        'decrypt': 32
    })

class KeyAttribute(Enumerated):
    namedValues = values({
        'none': 0,
        'permitInternal': 2,
        'permitExternal': 4,
        'permitMutual': 8,
        'importable': 16
    })

class KeyMechanism(Enumerated):
    namedValues = values({
        'undefined': 0,
        'tdea192': 3,
        'rsa1024': 6,
        'rsa2048': 7,
        'aes128': 8,
        'aes192': 10,
        'aes256': 12,
        'ecc256': 17,
        'ecc384': 20,
        'cs2': 39,
        'cs7': 46
    })

class PinCharSet(Enumerated):
    namedValues = values({
        'numeric': 0,
        'alphaCaseVariant': 1,
        'alphaCaseInvariant': 2,
        'raw': 3
    })

class VciMode(Enumerated):
    namedValues = values({
        'disabled': 0,
        'enabled': 1,
        'requirePairing': 2
    })

class OccMode(Enumerated):
    namedValues = values({
        'disabled': 0,
        'enabled': 1
    })

class PutDataLegacyRequest(Sequence):
    componentType = components({
        'operation': tagCtx(LegacyOperation(), 10),
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'keyMechanism': Optional(tagCtx(KeyMechanism(), 14)),
        'keyRole': Optional(tagCtx(KeyRole(), 15)),
        'keyAttribute': Optional(tagCtx(KeyAttribute(), 16))
    })

class PinPolicyParameter(Sequence):
    componentType = components({
        'enableLocal': Optional(tagCtx(Boolean(), 0)),
        'enableGlobal': Optional(tagCtx(Boolean(), 1)),
        'preferGlobal': Optional(tagCtx(Boolean(), 2)),
        'permitContactless': Optional(tagCtx(Boolean(), 3)),
        'minLength': Optional(tagCtx(Integer(), 4)),
        'maxLength': Optional(tagCtx(Integer(), 5)),
        'maxRetriesContact': Optional(tagCtx(Integer(), 6)),
        'maxRetriesContactless': Optional(tagCtx(Integer(), 7)),
        'charset': Optional(tagCtx(PinCharSet(), 8)),
        'history': Optional(tagCtx(Integer(), 9)),
        'ruleSequence': Optional(tagCtx(Integer(), 10)),
        'ruleDistinct': Optional(tagCtx(Integer(), 11))
    })

class PukPolicyParameter(Sequence):
    componentType = components({
        'enabled': Optional(tagCtx(Boolean(), 0)),
        'permitContactless': Optional(tagCtx(Boolean(), 1)),
        'length': Optional(tagCtx(Integer(), 2)),
        'retriesContact': Optional(tagCtx(Integer(), 3)),
        'retriesContactless': Optional(tagCtx(Integer(), 4)),
        'restrictUpdate': Optional(tagCtx(Boolean(), 5))
    })

class VciPolicyParameter(Sequence):
    componentType = components({
        'mode': Optional(tagCtx(VciMode(), 0))
    })

class OccPolicyParameter(Sequence):
    componentType = components({
        'mode': Optional(tagCtx(OccMode(), 0))
    })

class OptionsParameter(Sequence):
    componentType = components({
        'restrictContactlessGlobal': Optional(tagCtx(Boolean(), 0)),
        'restrictContactlessAdmin': Optional(tagCtx(Boolean(), 1)),
        'restrictEnumeration': Optional(tagCtx(Boolean(), 2)),
        'restrictSingleKey': Optional(tagCtx(Boolean(), 3)),
        'ignoreContactlessAcl': Optional(tagCtx(Boolean(), 4)),
        'readEmptyDataObject': Optional(tagCtx(Boolean(), 5)),
        'useRSACRT': Optional(tagCtx(Boolean(), 6))
    })

class PutDataCreateObjectRequest(Sequence):
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'adminKey': Optional(tagCtx(Integer(), 17))
    })

class PutDataDeleteObjectRequest(Sequence):
    componentType = components({
        'id': tagCtx(OctetString(), 11)
    })

class PutDataCreateKeyRequest(Sequence):
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'modeContact': tagCtx(AccessMode(), 12),
        'modeContactless': tagCtx(AccessMode(), 13),
        'adminKey': Optional(tagCtx(Integer(), 17)),
        'keyMechanism': tagCtx(KeyMechanism(), 14),
        'keyRole': tagCtx(KeyRole(), 15),
        'keyAttribute': tagCtx(KeyAttribute(), 16)
    })

class PutDataDeleteKeyRequest(Sequence):
    componentType = components({
        'id': tagCtx(OctetString(), 11),
        'keyMechanism': tagCtx(KeyMechanism(), 14)
    })

class PutDataUpdateConfigRequest(Sequence):
    componentType = components({
        'pinPolicy': Optional(tagCtx(PinPolicyParameter(), 0, True)),
        'pukPolicy': Optional(tagCtx(PukPolicyParameter(), 1, True)),
        'vciPolicy': Optional(tagCtx(VciPolicyParameter(), 2, True)),
        'occPolicy': Optional(tagCtx(OccPolicyParameter(), 3, True)),
        'options': Optional(tagCtx(OptionsParameter(), 4, True))
    })

class PutDataRequest(Choice):
    componentType = components({
        'legacyRequest': PutDataLegacyRequest(),
        'createObjectRequest': tagApp(PutDataCreateObjectRequest(), 4, True),
        'deleteObjectRequest': tagApp(PutDataDeleteObjectRequest(), 5, True),
        'createKeyRequest': tagApp(PutDataCreateKeyRequest(), 6, True),
        'deleteKeyRequest': tagApp(PutDataDeleteKeyRequest(), 7, True),
        'configRequest': tagApp(PutDataUpdateConfigRequest(), 8, True)
    })

class PutDataBulkRequest(SequenceOf):
    componentType = PutDataRequest()
    tagSet = tagSetApp(SequenceOf(), 10, True)
