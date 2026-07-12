#!/usr/bin/env python3

from pyasn1.type.univ import *

from asn1_utils import components, values, tagCtx, tagSetApp


class AppletState(Enumerated):
    namedValues = values({
        'installed': 3,
        'selectable': 7,
        'secured': 15
    })


class OperatorRole(Enumerated):
    namedValues = values({
        'public': 0,
        'user': 1,
        'securityOfficer': 2,
        'keyHolder': 3,
        'admin': 4
    })


class GetStatusResponse(Sequence):
    tagSet = tagSetApp(Sequence(), 19, True)
    componentType = components({
        'appletState': tagCtx(AppletState(), 0),
        'operatorRole': tagCtx(OperatorRole(), 1),
        'operatorId': tagCtx(Integer(), 2),
        'pinAlways': tagCtx(Boolean(), 3),
        'smState': tagCtx(Boolean(), 4),
        'vciState': tagCtx(Boolean(), 5),
        'contactlessAcl': tagCtx(Boolean(), 6),
        'fipsMode': tagCtx(Boolean(), 7),
    })
