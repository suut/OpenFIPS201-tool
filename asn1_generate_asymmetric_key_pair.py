#!/usr/bin/env python3

from pyasn1.type.univ import *
from pyasn1.type.tag import *

from asn1_utils import components, tagCtx, tagSetApp, tagSetCtx, Optional
from asn1_put_data_v2 import KeyMechanism

class PubkeyRSAResponse(Sequence):
    tagSet = tagSetApp(Sequence(), 73, True)

    componentType = components({
        'rsaModulus': tagCtx(OctetString(), 1),
        'rsaExponent': tagCtx(OctetString(), 2)
    })


class PubkeyECCResponse(Sequence):
    tagSet = tagSetApp(Sequence(), 73, True)

    componentType = components({
        'point': tagCtx(OctetString(), 6)
    })


class KeyRequest(Sequence):
    tagSet = tagSetCtx(Sequence(), 12, True)

    componentType = components({
        'mechanism': tagCtx(KeyMechanism(), 0),
        'parameter': Optional(tagCtx(OctetString(), 1)),
    })
