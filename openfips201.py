#!/usr/bin/env python3

import sys
import argparse
from functools import partial
from pathlib import Path
import hashlib
import base64

from smartcard.System import readers as readers
from smartcard.reader.Reader import Reader

from pyasn1.codec.native import decoder as native_decoder
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.univ import BitString, Integer

import pkcs1
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization.base import load_der_public_key

import asn1_utils
import scp03
import asn1_get_status_v2
import asn1_get_version_v2
import asn1_put_data_v2
import asn1_change_reference_data_v2
import asn1_general_authenticate
import asn1_generate_asymmetric_key_pair
import asn1_x509
import initial_setup


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


def make_csr(scp: scp03.SCP03, key_id: bytes, algo: str, existing_pubkey=None) -> asn1_x509.CertificationRequest:
    if not algo.startswith('rsa') and not algo.startswith('ecc'):
        sys.exit('Invalid algo')
    if key_id not in cert_by_key:
        sys.exit('Invalid key ID')
    if algo.startswith('ecc') and not algo in ('ecc256', 'ecc384'):
        sys.exit('Invalid ECC algorithm')

    algo_id = asn1_put_data_v2.KeyMechanism.namedValues[algo]

    if existing_pubkey:
        pubkey_x509, _ = der_decoder.decode(existing_pubkey, asn1Spec=asn1_x509.SubjectPublicKeyInfo())
    else:
        # Generate key pair
        pubkey_x509 = create_keypair(scp, key_id, algo)

    # Construct the CSR
    csr = asn1_x509.CertificationRequest()
    csr['certificationRequestInfo']['version'] = 0
    csr['certificationRequestInfo']['subjectPKInfo'] = pubkey_x509

    to_sign = der_encoder.encode(csr['certificationRequestInfo'])

    if algo.startswith('rsa'):
        data_len = int(algo[3:]) // 8
        to_sign_padded = pkcs1.rsassa_pkcs1_v15.emsa_pkcs1_v15.encode(to_sign, data_len, hash_class=hashlib.sha256)
    else:  # algo.startswith('ecc')
        to_sign_padded = hashlib.sha256(to_sign).digest()

    # Sign the CSR, each APDU must have a payload of 224 bytes maximum
    signing_request = asn1_general_authenticate.SigningRequest()
    signing_request['response'] = b''
    signing_request['challenge'] = to_sign_padded

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

    signed_csr = signing_response['response'].asOctets()

    if algo.startswith('rsa'):
        pubkey_rsa, _ = der_decoder.decode(pubkey_x509['subjectPublicKey'].asOctets(), asn1Spec=asn1_x509.RSAPublicKey())
        pkcs1_pubkey = pkcs1.keys.RsaPublicKey(int(pubkey_rsa['modulus']), int(pubkey_rsa['publicExponent']))
        sig_ok = pkcs1.rsassa_pkcs1_v15.verify(pkcs1_pubkey, to_sign, signed_csr, hashlib.sha256)
        assert sig_ok, 'Signature must be valid'
        print('Signature OK')

        csr['signatureAlgorithm']['algorithm'] = asn1_x509.oids['sha256WithRSAEncryption']

    elif algo.startswith('ecc'):
        pubkey_ecc: EllipticCurvePublicKey = load_der_public_key(der_encoder.encode(pubkey_x509))
        pubkey_ecc.verify(signed_csr, to_sign_padded, ECDSA(Prehashed(SHA256())))
        print('Signature OK')

        csr['signatureAlgorithm']['algorithm'] = asn1_x509.oids['ecdsaWithSHA256']

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
create_key_parser.add_argument('algo', help='Key algo (one of %(choices)s)', choices=[*asn1_put_data_v2.KeyMechanism.namedValues.keys()], metavar='ALGO')
create_key_parser.add_argument('role', help='Key role (one of %(choices)s)', choices=[*asn1_put_data_v2.KeyRole.namedValues.keys()], metavar='ROLE')
create_key_parser.add_argument('--no-rsa-crt', action='store_true', help='Do not use RSA CRT for RSA keys')
create_key_parser.add_argument('--permit-external', action='store_true', help='Permit external authenticate')
create_key_parser.add_argument('--permit-mutual', action='store_true', help='Permit mutual authenticate')
create_key_parser.add_argument('--importable', action='store_true', help='Key is importable')
create_key_parser.add_argument('--admin-key', default='9B', help='Admin key (default %(default)s)', metavar='KEY')
create_key_parser.add_argument('--mode-contact', default='always', choices=[*asn1_put_data_v2.AccessMode.namedValues.keys()], help='Contact ACL (one of %(choices)s; default %(default)s)', metavar='MODE')
create_key_parser.add_argument('--mode-contactless', default='always', choices=[*asn1_put_data_v2.AccessMode.namedValues.keys()], help='Contactless ACL (one of %(choices)s; default %(default)s)', metavar='MODE')

delete_key_parser = subparsers.add_parser('delete-key', help='Delete a key')
delete_key_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')

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
make_self_signed_parser.add_argument('-a', '--algo', choices=('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'), default='rsa2048', help='The public-key algorithm to use (default %(default)s)')
make_self_signed_parser.add_argument('-o', '--output', default='card-{KEY_ID}.crt', help='Where to save the self-signed certificate (default %(default)s)', metavar='FILE')
make_self_signed_parser.add_argument('--from-template', help='Certificate to use as a template, ignoring the other certificate parameters (default: none)')
make_self_signed_parser.add_argument('--common-name', default='PIV certificate {KEY_ID}', help='CSR/Certificate common name (default "%(default)s")')
make_self_signed_parser.add_argument('--email-address', help='CSR/Certificate email address (default none)')
make_self_signed_parser.add_argument('--organization', help='CSR/Certificate organization (default none)')
make_self_signed_parser.add_argument('--organizational-unit', help='CSR/Certificate organizational unit (default none)')
make_self_signed_parser.add_argument('--locality', help='CSR/Certificate locality name (default none)')
make_self_signed_parser.add_argument('--country', help='CSR/Certificate country (default none)')
make_self_signed_parser.add_argument('--key-usage', default='digitalSignature', help='CSR/Certificate key usage, comma-separated (default %(default)s, choices are none, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly)')
make_self_signed_parser.add_argument('--extended-key-usage', default='clientAuth', help='CSR/Certificate extended key usage, comma-separated (default %(default)s, choices are none, any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, or arbitrary OIDs)')
make_self_signed_parser.add_argument('--critical-extended-key-usage', action='store_true', help='Mark the extended key usage as critical')
make_self_signed_parser.add_argument('--validity', default=30, type=int, help='Certificate validity in days (default %(default)s days)')
make_self_signed_parser.add_argument('--ca', action='store_true', help='Make a CA certificate')
make_self_signed_parser.add_argument('--last-ca-in-chain', action='store_true', help='Mark the certificate as the last CA in the chain (the certificate will not be able to sign other CA certificates)')

make_csr_parser = generate_key_subparsers.add_parser('make-csr', help='Make a certificate signing request intended to be signed by an external CA')
make_csr_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
make_csr_parser.add_argument('--with-key', help='Use the public key that was previously generated with make-keypair-only', metavar='PUBKEY')
make_csr_parser.add_argument('-a', '--algo', choices=('rsa1024', 'rsa2048', 'rsa3072', 'rsa4096', 'ecc256', 'ecc384'), default='rsa2048', help='The public-key algorithm to use (default %(default)s)')
make_csr_parser.add_argument('-o', '--output', default='card-{KEY_ID}.csr', help='Where to save the certificate signing request (default %(default)s)', metavar='FILE')

load_cert_parser = generate_key_subparsers.add_parser('load-cert', help='Load a certificate')
load_cert_parser.add_argument('key_id', help='Key ID (9A, 9C, ...)', metavar='KEY-ID')
load_cert_parser.add_argument('cert', help='Certificate', metavar='CERT')

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

        setup_reqs: list[asn1_put_data_v2.PutDataBulkRequest] = [
            *map(partial(native_decoder.decode, asn1Spec=asn1_put_data_v2.PutDataBulkRequest()), initial_setup.reqs)]

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

    case 'delete-key':
        raise NotImplementedError()

    case 'set-admin-key':
        if not is_hex(args.key):
            sys.exit('Admin key must be hexadecimal')

        admin_key: bytes = x(args.key)
        print(f'Setting key 9B with mechanism {args.algo} to', admin_key.hex().upper())
        set_admin_key(scp, admin_key, args.algo)
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
                raise NotImplementedError()  # TODO

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
