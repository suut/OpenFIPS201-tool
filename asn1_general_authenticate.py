#!/usr/bin/env python3

from pyasn1.type.univ import *
from pyasn1.type.tag import *

from asn1_utils import components, tagCtx


class SigningRequest(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 28))
    componentType = components({
        'response': tagCtx(OctetString(), 2),
        'challenge': tagCtx(OctetString(), 1)
    })

class SigningResponse(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 28))
    componentType = components({
        'response': tagCtx(OctetString(), 2),
    })
