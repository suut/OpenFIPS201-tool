#!/usr/bin/env python3

from dataclasses import dataclass

from pyasn1.type.univ import *
from pyasn1.type.opentype import *
from pyasn1.type.tag import *
from pyasn1.type.namedtype import *
from pyasn1.type.base import *
from pyasn1.type.namedval import *


@dataclass
class DefinedBy:
    defined_by: str
    mapping: dict


@dataclass
class Optional:
    t: Asn1Type|DefinedBy


def tagCtx(t, n, constructed=False):
    return t.subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed if constructed else tagFormatSimple, n))

def tagCtxExplicit(t, n):
    return t.subtype(explicitTag=Tag(tagClassContext, tagFormatConstructed, n))

def tagApp(t, n, constructed=False):
    return t.subtype(implicitTag=Tag(tagClassApplication, tagFormatConstructed if constructed else tagFormatSimple, n))

def tagSetCtx(t, n, constructed=False):
    return t.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed if constructed else tagFormatSimple, n))

def tagSetApp(t, n, constructed=False):
    return t.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed if constructed else tagFormatSimple, n))

def components(d):
    items = []
    for k, v in d.items():
        kw = {}
        if isinstance(v, Optional):
            v = v.t
            T = OptionalNamedType
        else:
            T = NamedType
        if isinstance(v, DefinedBy):
            kw['openType'] = OpenType(v.defined_by, v.mapping)
            v = Any()
        items.append(T(k, v, **kw))

    return NamedTypes(*items)

def values(d):
    return NamedValues(*d.items(),)

def encode_unstructured(tag, data):
    if len(data) < 128:
        ll = b''
        l = len(data).to_bytes(length=1)
    elif len(data) < 256:
        ll = b'\x81'
        l = len(data).to_bytes(length=1)
    elif len(data) < 65536:
        ll = b'\x82'
        l = len(data).to_bytes(length=2)
    else:
        raise ValueError('data too large')
    if not isinstance(tag, bytes):
        tag = bytes((tag,))
    return tag + ll + l + data
