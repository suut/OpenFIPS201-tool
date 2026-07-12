#!/usr/bin/env python3

import sys
import argparse
from functools import partial
from pathlib import Path
import hashlib
import base64
import random
from datetime import datetime, timedelta
from typing import Callable, Any

import yaml

from smartcard.System import readers as readers
from smartcard.reader.Reader import Reader

from pyasn1.codec.native import decoder as native_decoder
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.univ import BitString, Integer, ObjectIdentifier, Null

import pkcs1
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA, SECP256R1, SECP384R1
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.exceptions import InvalidSignature

import asn1_utils
import scp03
import asn1_get_status_v2
import asn1_get_version_v2
import asn1_put_data_v2
import asn1_change_reference_data_v2
import asn1_general_authenticate
import asn1_generate_asymmetric_key_pair
import asn1_x509


def select_reader(selected=None):
    readers_list = readers()
    reader: Reader|None = None
    match len(readers_list):
        case 0:
            sys.exit('No reader found')
        case 1:
            reader = readers_list[0]
            print('Using reader', reader, file=sys.stderr)
        case _:
            if selected is not None:
                reader = readers_list[selected]
            else:
                print(f'Select one of the following readers with {sys.argv[0]} --reader=N')
                for i, r in enumerate(readers_list):
                    print(f'[{i}] {r}')
                sys.exit(1)
    return reader


def x(s):
    return bytes.fromhex(s)


def is_numeric(s):
    return all(c in '1234567890' for c in s)


def is_hex(s):
    return all(c in '1234567890abcdef ' for c in s.lower())


def set_pin_puk(scp, pin_id, pin, width=8):
    scp.transmit(x('0024FF') + bytes((pin_id,)), pin.ljust(width, b'\xFF'))


def set_admin_key(scp, admin_key, algo):
    put_key_req = asn1_change_reference_data_v2.ChangeReferenceDataKeyRequest()
    put_key_req['key'] = admin_key
    print(put_key_req)
    scp.transmit([0x00, 0x24, asn1_put_data_v2.KeyMechanism.namedValues[algo], 0x9B],
                 ber_encoder.encode(put_key_req, defMode=True))


cert_by_key = {
    x('9A'): x('5FC105'),
    x('9C'): x('5FC10A'),
    x('9D'): x('5FC10B'),
    x('9E'): x('5FC101'),
    x('82'): x('5FC10D'),
    x('83'): x('5FC10E'),
    x('84'): x('5FC10F'),
    x('85'): x('5FC110'),
    x('86'): x('5FC111'),
    x('87'): x('5FC112'),
    x('88'): x('5FC113'),
    x('89'): x('5FC114'),
    x('8A'): x('5FC115'),
    x('8B'): x('5FC116'),
    x('8C'): x('5FC117'),
    x('8D'): x('5FC118'),
    x('8E'): x('5FC119'),
    x('8F'): x('5FC11A'),
    x('90'): x('5FC11B'),
    x('91'): x('5FC11C'),
    x('92'): x('5FC11D'),
    x('93'): x('5FC11E'),
    x('94'): x('5FC11F'),
    x('95'): x('5FC120'),
}

def load_pem_der(data):
    if data.startswith(b'-----BEGIN'):  # we have PEM
        end_of_start_label = data.index(b'-----', 10) + 5
        start_of_end_label = data.index(b'-----END', end_of_start_label)
        b64data = data[end_of_start_label:start_of_end_label].replace(b'\r', b'').replace(b'\n', b'')
        data = base64.b64decode(b64data)
    return data


def load_cert(scp: scp03.SCP03, key_id: bytes, data: bytes):
    if key_id not in cert_by_key:
        sys.exit('Invalid key ID')

    cert_data = bytearray()
    cert_data += asn1_utils.encode_unstructured(0x70, data)
    cert_data += asn1_utils.encode_unstructured(0x71, b'\x00')  # CertInfo: not compressed
    cert_data += asn1_utils.encode_unstructured(0xFE, b'')      # LRC

    tag_list_field = asn1_utils.encode_unstructured(0x5C, cert_by_key[key_id])
    data_field = asn1_utils.encode_unstructured(0x53, cert_data)

    payload = tag_list_field + data_field

    apdus = []
    total_blocks = (len(payload) + 223) // 224

    for i in range(total_blocks):
        if i < total_blocks - 1:
            cla = 0x10
        else:
            cla = 0x00  # last block

        header = bytes([cla, 0xDB, 0x3F, 0xFF])
        apdus.append((header, payload[224 * i:224 * (i + 1)]))

    for header, apdu in apdus:
        scp.transmit(header, apdu)

    print('Success')


def get_cryptography_hash(hash_function: Callable[[...], Any]) -> HashAlgorithm:
    if hash_function is hashlib.sha1:
        return SHA1()
    elif hash_function is hashlib.sha224:
        return SHA224()
    elif hash_function is hashlib.sha256:
        return SHA256()
    elif hash_function is hashlib.sha384:
        return SHA384()
    elif hash_function is hashlib.sha512:
        return SHA512()
    else:
        raise ValueError(f'Unknown hash {hash_function!r}')


def verify_signature(pubkey: asn1_x509.SubjectPublicKeyInfo, data: bytes, signature: bytes, hash_function=hashlib.sha256) -> bool:
    """
    Verify a signature, with RSASSA-PKCS#1v1.5 for RSA keys and ECDSA for ECC keys
    :param pubkey: The public key
    :param data: The signed data
    :param signature: The signature
    :param hash_function: The hash function to use
    :return: Whether the signature verification was successful
    """
    algo: ObjectIdentifier = pubkey['algorithm']['algorithm']

    if algo == asn1_x509.oids['rsaEncryption']:
        pubkey_data: asn1_x509.RSAPublicKey = der_decoder.decode(pubkey['subjectPublicKey'].asOctets(), asn1Spec=asn1_x509.RSAPublicKey())
        pubkey_rsa = pkcs1.keys.RsaPublicKey(int(pubkey_data['modulus']), int(pubkey_data['publicExponent']))
        return pkcs1.rsassa_pkcs1_v15.verify(pubkey_rsa, data, signature, hash_class=hash_function)

    elif algo == asn1_x509.oids['ecPublicKey']:
        pubkey_data: bytes = pubkey['subjectPublicKey'].asOctets()
        if pubkey['algorithm']['parameters'] == asn1_x509.oids['prime256v1']:
            curve = SECP256R1()
        elif pubkey['algorithm']['parameters'] == asn1_x509.oids['ansip384r1']:
            curve = SECP384R1()
        else:
            raise ValueError('invalid curve')
        pubkey_ec = EllipticCurvePublicKey.from_encoded_point(curve, pubkey_data)
        try:
            pubkey_ec.verify(signature, data, ECDSA(get_cryptography_hash(hash_function)))
        except InvalidSignature:
            return False
        else:
            return True

    else:
        raise ValueError('unknown algo')


def raw_sign(scp: scp03.SCP03, key_id: bytes, algo: str, data: bytes) -> bytes:
    """
    Sign already hashed and padded data
    :param scp: Secure channel
    :param key_id: Key ID (9A, 9C, ...)
    :param algo: Algorithm to use
    :param data: Data to sign
    :return: Signature
    """
    if len(key_id) != 1:
        sys.exit('KEY-ID must be 1 byte')
    if algo not in ('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'):
        sys.exit('Invalid algo')
    algo_id = asn1_put_data_v2.KeyMechanism.namedValues[algo]

    # Each APDU must have a payload of 224 bytes maximum
    signing_request = asn1_general_authenticate.SigningRequest()
    signing_request['response'] = b''
    signing_request['challenge'] = data

    signing_request_encoded = ber_encoder.encode(signing_request, defMode=True)

    apdus = []
    total_blocks = (len(signing_request_encoded) + 223) // 224

    for i in range(total_blocks):
        if i < total_blocks - 1:
            cla = 0x10
        else:
            cla = 0x00  # last block

        header = bytes([cla, 0x87, algo_id, *key_id])
        apdus.append((header, signing_request_encoded[224 * i:224 * (i + 1)]))

    resp = b''
    for header, data in apdus:
        resp = scp.transmit(header, data)

    signing_response, _ = ber_decoder.decode(resp, asn1Spec=asn1_general_authenticate.SigningResponse())

    return signing_response['response'].asOctets()


def sign(scp: scp03.SCP03, key_id: bytes, algo: str, data: bytes, hash_function=hashlib.sha256):
    if len(key_id) != 1:
        sys.exit('KEY-ID must be 1 byte')
    if algo not in ('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'):
        sys.exit('Invalid algo')

    if algo.startswith('rsa'):
        mlen = int(algo[3:]) // 8
        to_sign_hashed = pkcs1.rsassa_pkcs1_v15.emsa_pkcs1_v15.encode(data, mlen, hash_class=hash_function)
    elif algo.startswith('ec'):
        to_sign_hashed = hash_function(data).digest()
    else:
        raise ValueError()

    return raw_sign(scp, key_id, algo, to_sign_hashed)


def make_self_signed(scp: scp03.SCP03, key_id: bytes, algo: str, args: argparse.Namespace, existing_pubkey=None):
    # parse key usages
    if args.key_usage is None:
        key_usage = ['digitalSignature']
    elif 'none' in args.key_usage:
        assert args.key_usage == ['none'], 'none must be the only element'
        key_usage = []
    else:
        key_usage = args.key_usage
    if args.extended_key_usage is None:
        extended_key_usage = ['clientAuth']
    elif 'none' in args.extended_key_usage:
        assert args.extended_key_usage == ['none'], 'none must be the only element'
        extended_key_usage = []
    else:
        extended_key_usage = args.extended_key_usage
    if args.email is None:
        emails = []
    elif 'none' in args.email:
        assert args.email == ['none'], 'none must be the only element'
        emails = []
    else:
        emails = args.email

    # parse digest
    if args.digest is None:
        digest = 'sha256'
        digest_func = hashlib.sha256
    else:
        digest = args.digest
        digest_func = getattr(hashlib, args.digest)

    if args.algo.startswith('rsa'):
        sig_algo = asn1_x509.rsa_signature_oids_by_digest[digest]
    elif args.algo.startswith('ecc'):
        sig_algo = asn1_x509.ecdsa_signature_oids_by_digest[digest]
    else:
        raise ValueError('Invalid algo')

    # Make or get the public key
    if existing_pubkey is not None:
        pubkey_x509, _ = der_decoder.decode(existing_pubkey, asn1Spec=asn1_x509.SubjectPublicKeyInfo())
        if algo.startswith('rsa'):
            assert pubkey_x509['algorithm'] == asn1_x509.oids['rsaEncryption']
            assert pubkey_x509['parameters'] == Null()
        elif algo.startswith('ecc'):
            assert pubkey_x509['algorithm'] == asn1_x509.oids['ecPublicKey']
            if algo == 'ecc256':
                assert pubkey_x509['parameters'] == asn1_x509.oids['prime256v1']
            else:
                assert pubkey_x509['parameters'] == asn1_x509.oids['ansip384r1']
    else:
        pubkey_x509 = create_keypair(scp, key_id, algo)

    # Make the certificate:
    inner_cert = asn1_x509.TBSCertificate()

    # Version
    inner_cert['version'] = 2

    # Serial number
    inner_cert['serialNumber'] = random.SystemRandom().getrandbits(159) # positive 20-bytes number

    # Signature algo
    inner_cert['signature']['algorithm'] = sig_algo
    if algo.startswith('rsa'):
        inner_cert['signature']['parameters'] = Null()

    # Issuer
    if args.country and args.country != 'none':
        country = asn1_x509.RelativeDistinguishedName()
        country[0]['type'] = asn1_x509.oids['countryName']
        country[0]['value']['printableString'] = args.country.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(country)
    if args.state_or_province and args.state_or_province != 'none':
        state_or_province = asn1_x509.RelativeDistinguishedName()
        state_or_province[0]['type'] = asn1_x509.oids['stateOrProvinceName']
        state_or_province[0]['value']['utf8String'] = args.state_or_province.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(state_or_province)
    if args.locality and args.locality != 'none':
        locality = asn1_x509.RelativeDistinguishedName()
        locality[0]['type'] = asn1_x509.oids['localityName']
        locality[0]['value']['utf8String'] = args.locality.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(locality)
    if args.organization and args.organization != 'none':
        organization = asn1_x509.RelativeDistinguishedName()
        organization[0]['type'] = asn1_x509.oids['organizationName']
        organization[0]['value']['utf8String'] = args.organization.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(organization)
    if args.organizational_unit and args.organizational_unit != 'none':
        organizational_unit = asn1_x509.RelativeDistinguishedName()
        organizational_unit[0]['type'] = asn1_x509.oids['organizationalUnitName']
        organizational_unit[0]['value']['utf8String'] = args.organizational_unit.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(organizational_unit)
    if args.common_name and args.common_name != 'none':
        common_name = asn1_x509.RelativeDistinguishedName()
        common_name[0]['type'] = asn1_x509.oids['commonName']
        common_name[0]['value']['utf8String'] = args.common_name.format(KEY_ID=key_id.hex().upper())
        inner_cert['issuer'].append(common_name)

    # Validity
    not_before = datetime.now()
    not_after = not_before + timedelta(days=args.validity)
    inner_cert['validity']['notBefore']['utcTime'] = asn1_x509.make_utctime(not_before)
    inner_cert['validity']['notAfter']['utcTime'] = asn1_x509.make_utctime(not_after)

    # Subject
    inner_cert['subject'] = inner_cert['issuer']

    # Public key
    inner_cert['subjectPublicKeyInfo'] = pubkey_x509

    # Extensions:

    # Subject key identifier
    akid = asn1_x509.Extension()
    akid['extnID'] = asn1_x509.oids['subjectKeyIdentifier']
    akid['extnValue'] = asn1_x509.encode_subject_key_identifier(hashlib.sha1(der_encoder.encode(pubkey_x509)).digest())
    inner_cert['extensions'].append(akid)

    # Authority key identifier
    skid = asn1_x509.Extension()
    skid['extnID'] = asn1_x509.oids['authorityKeyIdentifier']
    skid['extnValue'] = asn1_x509.encode_authority_key_identifier(hashlib.sha1(der_encoder.encode(pubkey_x509)).digest())
    inner_cert['extensions'].append(skid)

    # Basic constraints
    basic_constraints = asn1_x509.Extension()
    basic_constraints['extnID'] = asn1_x509.oids['basicConstraints']
    basic_constraints['critical'] = True
    basic_constraints['extnValue'] = asn1_x509.encode_basic_constraints(args.ca, 0 if args.ca and args.last_ca_in_chain else None)
    inner_cert['extensions'].append(basic_constraints)

    # Key usage
    key_usage_ext = asn1_x509.Extension()
    key_usage_ext['extnID'] = asn1_x509.oids['keyUsage']
    key_usage_ext['critical'] = True
    key_usage_ext['extnValue'] = asn1_x509.encode_key_usage(key_usage)
    inner_cert['extensions'].append(key_usage_ext)

    # Extended key usage
    if extended_key_usage:
        ext_key_usage_ext = asn1_x509.Extension()
        ext_key_usage_ext['extnID'] = asn1_x509.oids['extKeyUsage']
        if args.critical_extended_key_usage:
            ext_key_usage_ext['critical'] = True
        ext_key_usage_ext['extnValue'] = asn1_x509.encode_ext_key_usage(extended_key_usage)
        inner_cert['extensions'].append(ext_key_usage_ext)

    # Subject alt name
    if emails:
        subject_alt_name = asn1_x509.Extension()
        subject_alt_name['extnID'] = asn1_x509.oids['subjectAltName']
        subject_alt_name['extnValue'] = asn1_x509.encode_subject_alt_name_emails(emails, KEY_ID=key_id.hex().upper())
        inner_cert['extensions'].append(subject_alt_name)

    to_sign = der_encoder.encode(inner_cert)

    signature = sign(scp, key_id, algo, to_sign, digest_func)
    sig_ok = verify_signature(pubkey_x509, to_sign, signature, digest_func)
    assert sig_ok, 'Signature must be valid'
    print('Signature OK:', sig_ok)

    cert = asn1_x509.Certificate()
    cert['tbsCertificate'] = inner_cert
    cert['signatureAlgorithm'] = inner_cert['signature']
    cert['signatureValue'] = BitString.fromOctetString(signature)

    return der_encoder.encode(cert)


def make_csr(scp: scp03.SCP03, key_id: bytes, algo: str, existing_pubkey=None) -> asn1_x509.CertificationRequest:
    if not algo.startswith('rsa') and not algo.startswith('ecc'):
        sys.exit('Invalid algo')
    if key_id not in cert_by_key:
        sys.exit('Invalid key ID')
    if algo.startswith('ecc') and not algo in ('ecc256', 'ecc384'):
        sys.exit('Invalid ECC algorithm')

    if existing_pubkey:
        pubkey_x509, _ = der_decoder.decode(existing_pubkey, asn1Spec=asn1_x509.SubjectPublicKeyInfo())
        if algo.startswith('rsa'):
            assert pubkey_x509['algorithm'] == asn1_x509.oids['rsaEncryption']
            assert pubkey_x509['parameters'] == Null()
        elif algo.startswith('ecc'):
            assert pubkey_x509['algorithm'] == asn1_x509.oids['ecPublicKey']
            if algo == 'ecc256':
                assert pubkey_x509['parameters'] == asn1_x509.oids['prime256v1']
            else:
                assert pubkey_x509['parameters'] == asn1_x509.oids['ansip384r1']
    else:
        # Generate key pair
        pubkey_x509 = create_keypair(scp, key_id, algo)

    # Construct the CSR
    csr = asn1_x509.CertificationRequest()
    csr['certificationRequestInfo']['version'] = 0
    csr['certificationRequestInfo']['subjectPKInfo'] = pubkey_x509

    to_sign = der_encoder.encode(csr['certificationRequestInfo'])

    signed_csr = sign(scp, key_id, algo, to_sign)
    sig_ok = verify_signature(pubkey_x509, to_sign, signed_csr)
    assert sig_ok, 'Signature must be valid (was the correct key used?)' if existing_pubkey else 'Signature must be valid'
    print('Signature OK')

    if algo.startswith('rsa'):
        csr['signatureAlgorithm']['algorithm'] = asn1_x509.oids['sha256WithRSAEncryption']

    elif algo.startswith('ecc'):
        csr['signatureAlgorithm']['algorithm'] = asn1_x509.oids['ecdsa-with-SHA256']

    csr['signature'] = BitString.fromOctetString(signed_csr)

    print('Create CSR success')

    return csr


def create_keypair(scp: scp03.SCP03, key_id: bytes, algo: str) -> asn1_x509.SubjectPublicKeyInfo:
    if not algo.startswith('rsa') and not algo.startswith('ecc'):
        sys.exit('Invalid algo')
    if key_id not in cert_by_key:
        sys.exit('Invalid key ID')
    if algo.startswith('ecc') and not algo in ('ecc256', 'ecc384'):
        sys.exit('Invalid ECC algorithm')

    # Generate key pair
    req = asn1_generate_asymmetric_key_pair.KeyRequest()
    req['mechanism'] = algo
    encoded_req = ber_encoder.encode(req, defMode=True)

    pubkey_raw = scp.transmit(x('004700') + key_id, encoded_req)

    pubkey_x509 = asn1_x509.SubjectPublicKeyInfo()

    if algo.startswith('rsa'):
        pubkey, _ = ber_decoder.decode(pubkey_raw, asn1Spec=asn1_generate_asymmetric_key_pair.PubkeyRSAResponse())
        pubkey_rsa = asn1_x509.RSAPublicKey()
        pubkey_rsa['modulus'] = Integer(BitString.fromOctetString(pubkey['rsaModulus']).asInteger())
        pubkey_rsa['publicExponent'] = Integer(BitString.fromOctetString(pubkey['rsaExponent']).asInteger())
        pubkey_x509['subjectPublicKey'] = BitString.fromOctetString(der_encoder.encode(pubkey_rsa))
        pubkey_x509['algorithm']['algorithm'] = asn1_x509.oids['rsaEncryption']
        pubkey_x509['algorithm']['parameters'] = Null()

    elif algo.startswith('ecc'):
        pubkey, _ = ber_decoder.decode(pubkey_raw, asn1Spec=asn1_generate_asymmetric_key_pair.PubkeyECCResponse())
        pubkey_x509['subjectPublicKey'] = BitString.fromOctetString(pubkey['point'])
        pubkey_x509['algorithm']['algorithm'] = asn1_x509.oids['ecPublicKey']
        if algo == 'ecc256':
            pubkey_x509['algorithm']['parameters'] = asn1_x509.oids['prime256v1']
        elif algo == 'ecc384':
            pubkey_x509['algorithm']['parameters'] = asn1_x509.oids['ansip384r1']

    print('Create key pair success')
    return pubkey_x509


def yaml_x_parser(loader: yaml.CLoader, value: yaml.ScalarNode):
    return bytes.fromhex(value.value)


yaml.CLoader.add_constructor('tag:yaml.org,2002:x', yaml_x_parser)


parser = argparse.ArgumentParser(description='OpenFIPS201 v2.0.0 configuration tool', epilog='Call this program without a subcommand to print version and status information')
parser.add_argument('-r', '--reader', default=None, help='PC/SC reader index to use')
parser.add_argument('--aid', default='A000000308000010000100', help='OpenFIPS201 AID (default %(default)s)')
parser.add_argument('--key-mac', default=scp03.GP_DEFAULT_KEY.hex().upper(), help='SCP-03 MAC key (default %(default)s)')
parser.add_argument('--key-enc', default=scp03.GP_DEFAULT_KEY.hex().upper(), help='SCP-03 ENC key (default %(default)s)')

subparsers = parser.add_subparsers(title='command', dest='command', metavar='COMMAND')

initialize_parser = subparsers.add_parser('initialize', help='Initialize the PIN, admin key and data objects')
initialize_parser.add_argument('--admin-key-algo', default='aes128', choices=['tdea192', 'aes128', 'aes192', 'aes256'], help='Admin key algorithm (one of %(choices)s; default %(default)s)', metavar='ALGO')
initialize_parser.add_argument('--admin-key', default=scp03.GP_DEFAULT_KEY.hex().upper(), help='Initial admin key (default %(default)s)', metavar='ADMIN_KEY')
initialize_parser.add_argument('--pin', default='123456', help='Initial PIN (default %(default)s)', metavar='PIN')
initialize_parser.add_argument('--puk', default='12345678', help='Initial PIN (default %(default)s)', metavar='PUK')

create_key_parser = subparsers.add_parser('create-key', help='Create a key slot')
create_key_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
create_key_parser.add_argument('algo', help='Key algo (one of %(choices)s)', choices=('tdea192', 'rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'aes128', 'aes192', 'aes256', 'ecc256', 'ecc384', 'cs2', 'cs7'), metavar='ALGO')
create_key_parser.add_argument('role', help='Key role (one of %(choices)s)', choices=[*asn1_put_data_v2.KeyRole.namedValues.keys()], metavar='ROLE')
create_key_parser.add_argument('--no-rsa-crt', action='store_true', help='Do not use RSA CRT for RSA keys')
create_key_parser.add_argument('--permit-external', action='store_true', help='Permit external authenticate')
create_key_parser.add_argument('--permit-mutual', action='store_true', help='Permit mutual authenticate')
create_key_parser.add_argument('--importable', action='store_true', help='Key is importable')
create_key_parser.add_argument('--admin-key', default='9B', help='Admin key (default %(default)s)', metavar='KEY')
create_key_parser.add_argument('--mode-contact', default='always', choices=[*asn1_put_data_v2.AccessMode.namedValues.keys()], help='Contact ACL (one of %(choices)s; default %(default)s)', metavar='MODE')
create_key_parser.add_argument('--mode-contactless', default='always', choices=[*asn1_put_data_v2.AccessMode.namedValues.keys()], help='Contactless ACL (one of %(choices)s; default %(default)s)', metavar='MODE')

set_admin_key_parser = subparsers.add_parser('set-admin-key', help='Set the admin key 9B')
set_admin_key_parser.add_argument('algo', choices=['tdea192', 'aes128', 'aes192', 'aes256'], metavar='ALGO', help='Key algorithm (one of %(choices)s)')
set_admin_key_parser.add_argument('key', help='Key data', metavar='KEY')

set_pin_parser = subparsers.add_parser('set-pin', help='Set a PIN or PUK code')
set_pin_parser.add_argument('pin', help='New PIN value', metavar='PIN')
pin_group = set_pin_parser.add_mutually_exclusive_group()
pin_group.add_argument('--puk', action='store_true', help='Set the PUK (81) instead of the PIN (80)')
pin_group.add_argument('--global-pin', action='store_true', help='Set the global PIN (??) instead of the PIN (80)')

generate_key_parser = subparsers.add_parser('make-key', help='Generate key pairs and certificates/certificate signing requests')
generate_key_subparsers = generate_key_parser.add_subparsers(title='subcommand', dest='manage_certs_subcommand', metavar='SUBCOMMAND', required=True)

make_keypair_parser = generate_key_subparsers.add_parser('make-keypair-only', help='Make a keypair and save the public key')
make_keypair_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
make_keypair_parser.add_argument('-a', '--algo', choices=('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'), default='rsa2048', help='The public-key algorithm to use (default %(default)s)')
make_keypair_parser.add_argument('-o', '--output', default='card-{KEY_ID}.key', help='Where to save the the public key (default %(default)s)', metavar='FILE')

make_self_signed_parser = generate_key_subparsers.add_parser('make-self-signed', help='Make a self-signed certificate')
make_self_signed_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
make_self_signed_parser.add_argument('--with-key', help='Use the public key that was previously generated with make-keypair-only', metavar='PUBKEY')
make_self_signed_parser.add_argument('--no-load', action='store_true', help='Do not automatically load the certificate into the card')
make_self_signed_parser.add_argument('-a', '--algo', choices=('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'), default='rsa2048', help='The public-key algorithm to use (default %(default)s)')
make_self_signed_parser.add_argument('-o', '--output', default='card-{KEY_ID}.crt', help='Where to save the self-signed certificate (default %(default)s)', metavar='FILE')
make_self_signed_parser.add_argument('--common-name', default='PIV certificate {KEY_ID}', help='Certificate common name (default "%(default)s")', metavar='NAME')
make_self_signed_parser.add_argument('--email', action='append', help='Email address, can be given multiple times', metavar='EMAIL')
make_self_signed_parser.add_argument('--organization', help='Certificate organization (default none)', metavar='ORG')
make_self_signed_parser.add_argument('--organizational-unit', help='Certificate organizational unit (default none)', metavar='ORG-UNIT')
make_self_signed_parser.add_argument('--state-or-province', help='Certificate state or province name (default none)', metavar='STATE')
make_self_signed_parser.add_argument('--locality', help='Certificate locality name (default none)')
make_self_signed_parser.add_argument('--country', help='Certificate country (default none)')
make_self_signed_parser.add_argument('--key-usage', action='append', help='Certificate key usage, can be given multiple times (default digitalSignature, choices are none, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly)', metavar='USAGE')
make_self_signed_parser.add_argument('--extended-key-usage', action='append', help='Certificate extended key usage, can be given multiple times (default clientAuth, choices are none, anyExtendedKeyUsage, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, or arbitrary OIDs)', metavar='EKU')
make_self_signed_parser.add_argument('--critical-extended-key-usage', action='store_true', help='Mark the extended key usage as critical')
make_self_signed_parser.add_argument('--validity', default=30, type=int, help='Certificate validity in days (default %(default)s days)', metavar='DAYS')
make_self_signed_parser.add_argument('--ca', action='store_true', help='Make a CA certificate')
make_self_signed_parser.add_argument('--last-ca-in-chain', action='store_true', help='Mark the certificate as the last CA in the chain (the certificate will not be able to sign other CA certificates)')
digest_group = make_self_signed_parser.add_mutually_exclusive_group()
digest_group.add_argument('--sha1', dest='digest', action='store_const', const='sha1', help='Use SHA-1 digest for the signature')
digest_group.add_argument('--sha224', dest='digest', action='store_const', const='sha224', help='Use SHA-224 digest for the signature')
digest_group.add_argument('--sha256', dest='digest', action='store_const', const='sha256', help='Use SHA-256 digest for the signature (default)')
digest_group.add_argument('--sha384', dest='digest', action='store_const', const='sha384', help='Use SHA-384 digest for the signature')
digest_group.add_argument('--sha512', dest='digest', action='store_const', const='sha512', help='Use SHA-512 digest for the signature')

make_csr_parser = generate_key_subparsers.add_parser('make-csr', help='Make a certificate signing request intended to be signed by an external CA')
make_csr_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
make_csr_parser.add_argument('--with-key', help='Use the public key that was previously generated with make-keypair-only', metavar='PUBKEY')
make_csr_parser.add_argument('-a', '--algo', choices=('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'), default='rsa2048', help='The public-key algorithm to use (default %(default)s)')
make_csr_parser.add_argument('-o', '--output', default='card-{KEY_ID}.csr', help='Where to save the certificate signing request (default %(default)s)', metavar='FILE')

load_cert_parser = generate_key_subparsers.add_parser('load-cert', help='Load a certificate')
load_cert_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
load_cert_parser.add_argument('cert', help='Certificate', metavar='CERT')

secure_applet_parser = subparsers.add_parser('secure-applet', help='Set the applet state to SECURED and prevent further admin commands')

args = parser.parse_args()

AID = x(args.aid)
KEY_ENC = x(args.key_enc)
KEY_MAC = x(args.key_mac)

reader = select_reader(int(args.reader) if args.reader is not None else None)

scp = scp03.SCP03(reader, AID, KEY_ENC, KEY_MAC, scp03.GP_DEFAULT_KEY, chaining_quirk=True)  # DEK is unused
scp.connect()
scp.initialize()

match args.command:
    case 'initialize':
        if not is_numeric(args.pin) or not is_numeric(args.puk):
            sys.exit('PIN and PUK must be numeric')

        if len(args.pin) > 8 or len(args.puk) > 8:
            sys.exit('Maximum 8 characters')

        if not is_hex(args.admin_key):
            sys.exit('Admin key must be hexadecimal')

        admin_key: bytes = x(args.admin_key)
        pin: bytes = args.pin.encode('ascii')
        puk: bytes = args.puk.encode('ascii')

        with open(Path(__file__).parent / 'initial_setup.yaml') as f:
            setup = yaml.load(f, yaml.CLoader)

        setup_reqs: list[asn1_put_data_v2.PutDataBulkRequest] = [
            *map(partial(native_decoder.decode, asn1Spec=asn1_put_data_v2.PutDataBulkRequest()), setup)]

        admin_key_request = asn1_put_data_v2.PutDataRequest()
        admin_key_request['createKeyRequest']['id'] = x('9B')
        admin_key_request['createKeyRequest']['modeContact'] = 'always'
        admin_key_request['createKeyRequest']['modeContactless'] = 'always'
        admin_key_request['createKeyRequest']['keyMechanism'] = args.admin_key_algo
        admin_key_request['createKeyRequest']['keyRole'] = 'authenticate'
        admin_key_request['createKeyRequest']['keyAttribute'] = x('18')  # importable, permitMutual

        setup_reqs[0].append(admin_key_request)

        for req in setup_reqs:
            print('Sending bulk configuration request:')
            print(req)
            encoded_req = ber_encoder.encode(req, defMode=True)
            scp.transmit(x('00DB3F00'), encoded_req)
            print('Success')

        # Set PIN
        print('Setting PIN to', args.pin)
        set_pin_puk(scp, 0x80, pin)
        print('Success')

        # Set PUK
        print('Setting PUK to', args.puk)
        set_pin_puk(scp, 0x81, puk)
        print('Success')

        print(f'Setting key 9B with mechanism {args.admin_key_algo} to', admin_key.hex().upper())
        set_admin_key(scp, admin_key, args.admin_key_algo)
        print('Success')

    case 'create-key':
        if not is_hex(args.key_id):
            sys.exit('Key ID is not hexadecimal')
        key_id = x(args.key_id)
        if len(key_id) != 1:
            sys.exit('Key ID must be 1 byte')
        if not is_hex(args.admin_key):
            sys.exit('Admin key is not hexadecimal')
        admin_key = x(args.admin_key)
        if len(admin_key) != 1:
            sys.exit('Admin key must be 1 byte')
        req = asn1_put_data_v2.PutDataRequest()
        req['createKeyRequest']['id'] = key_id
        req['createKeyRequest']['modeContact'] = args.mode_contact
        req['createKeyRequest']['modeContactless'] = args.mode_contactless
        req['createKeyRequest']['keyRole'] = args.role
        req['createKeyRequest']['keyMechanism'] = args.algo
        req['createKeyRequest']['keyAdmin'] = admin_key

        attr = 0
        if args.algo.startswith('rsa') and not args.no_rsa_crt:
            attr |= asn1_put_data_v2.KeyAttribute.namedValues['rsaCRT']
        if args.permit_external:
            attr |= asn1_put_data_v2.KeyAttribute.namedValues['permitExternal']
        if args.permit_mutual:
            attr |= asn1_put_data_v2.KeyAttribute.namedValues['permitMutual']
        if args.importable:
            attr |= asn1_put_data_v2.KeyAttribute.namedValues['importable']

        req['createKeyRequest']['keyAttribute'] = attr.to_bytes(length=1)

        print(req)
        encoded_req = ber_encoder.encode(req, defMode=True)

        try:
            scp.transmit(x('00DB3F00'), encoded_req)
        except scp03.APDUException as e:
            if e.sw == 0x6E27:
                sys.exit('Object already exists!')
            else:
                raise e from None

        print('Success')

    case 'set-admin-key':
        if not is_hex(args.key):
            sys.exit('Admin key must be hexadecimal')

        admin_key: bytes = x(args.key)
        print(f'Setting key 9B with mechanism {args.algo} to', admin_key.hex().upper())
        set_admin_key(scp, admin_key, args.algo)
        print('Success')

    case 'secure-applet':
        req = asn1_utils.encode_unstructured(0x5F, b'')
        scp.transmit(x('00DB3F00'), req)
        print('Success')

    case 'set-pin':
        if args.puk:
            what = 'PUK'
            pin_id = 0x81
        elif args.global_pin:
            raise NotImplementedError()
        else:
            what = 'PIN'
            pin_id = 0x80

        if not is_numeric(args.pin):
            sys.exit('PIN must be numeric')

        pin = args.pin.encode('ascii')

        # Set PIN
        print('Setting', what, 'to', args.pin)
        set_pin_puk(scp, pin_id, pin)
        print('Success')

    case 'make-key':
        if not is_hex(args.key_id):
            sys.exit('key-id must be hexadecimal')
        key_id = x(args.key_id)
        if len(key_id) != 1:
            sys.exit('key-id must be one byte')

        match args.manage_certs_subcommand:
            case 'make-keypair-only':
                output = Path(args.output.format(KEY_ID=key_id.hex().upper()))
                if not output.parent.exists():
                    sys.exit(f'Directory {output.parent} does not exist')
                pubkey_x509 = create_keypair(scp, key_id, args.algo)
                Path(output).write_bytes(der_encoder.encode(pubkey_x509))
                print('Success')

            case 'make-self-signed':
                output = Path(args.output.format(KEY_ID=key_id.hex().upper()))
                if not output.parent.exists():
                    sys.exit(f'Directory {output.parent} does not exist')
                existing_pubkey = None
                if args.with_key is not None:
                    existing_pubkey = load_pem_der(Path(args.with_key).read_bytes())
                cert = make_self_signed(scp, key_id, args.algo, args, existing_pubkey)
                output.write_bytes(cert)
                if not args.no_load:
                    load_cert(scp, key_id, cert)
                print('Success')

            case 'make-csr':
                output = Path(args.output.format(KEY_ID=key_id.hex().upper()))
                if not output.parent.exists():
                    sys.exit(f'Directory {output.parent} does not exist')
                existing_pubkey = None
                if args.with_key is not None:
                    existing_pubkey = load_pem_der(Path(args.with_key).read_bytes())
                csr = make_csr(scp, key_id, args.algo, existing_pubkey)
                Path(output).write_bytes(der_encoder.encode(csr))
                print('Success')

            case 'load-cert':
                cert = Path(args.cert)
                if not cert.exists():
                    sys.exit('Certificate file does not exist')
                load_cert(scp, key_id, load_pem_der(Path(args.cert).read_bytes()))

    case _:
        status_raw = bytearray(scp.transmit(x('00CB3F00'), x('5C032F4753')))
        status_raw[0] |= 0x20
        status, _ = ber_decoder.decode(bytes(status_raw), asn1Spec=asn1_get_status_v2.GetStatusResponse())
        print(status)

        version_raw = bytearray(scp.transmit(x('00CB3F00'), x('5C032F4756')))
        version_raw[0] |= 0x20
        version, _ = ber_decoder.decode(bytes(version_raw), asn1Spec=asn1_get_version_v2.GetVersionResponse())
        print(version)
