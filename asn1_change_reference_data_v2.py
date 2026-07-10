#!/usr/bin/env python3

from pyasn1.type.univ import *

from asn1_utils import components, tagCtx


class ChangeReferenceDataKeyRequest(Choice):
    componentType = components({
		'key': tagCtx(OctetString(), 0),

		'rsaN': tagCtx(OctetString(), 1),
		'rsaE': tagCtx(OctetString(), 2),
		'rsaD': tagCtx(OctetString(), 3),

		'eccW': tagCtx(OctetString(), 6),
		'eccS': tagCtx(OctetString(), 7),
		'smCVC': tagCtx(OctetString(), 8),

		'rsaP': tagCtx(OctetString(), 16),
		'rsaQ': tagCtx(OctetString(), 17),
		'rsaDP': tagCtx(OctetString(), 18),
		'rsaDQ': tagCtx(OctetString(), 19),
		'rsaPQ': tagCtx(OctetString(), 20),

		'clear': tagCtx(Null(), 31)
	})
