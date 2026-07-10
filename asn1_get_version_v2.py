#!/usr/bin/env python3

from pyasn1.type.univ import *
from pyasn1.type.char import *

from asn1_utils import components, tagCtx, tagSetApp


class GetVersionResponse(Sequence):
    tagSet = tagSetApp(Sequence(), 19, True)
    componentType = components({
        'application': tagCtx(UTF8String(), 0),
        'major': tagCtx(Integer(), 1),
        'minor': tagCtx(Integer(), 2),
        'revision': tagCtx(Integer(), 3),
        'debug': tagCtx(Boolean(), 4),
    })
