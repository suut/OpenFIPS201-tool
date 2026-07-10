#!/usr/bin/env python
# coding: utf-8

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from enum import IntEnum
import struct
from smartcard.reader.Reader import Reader
from smartcard.CardConnection import CardConnection
import os


class StatusWord:
    DESC = {}

    def __init__(self, sw, desc=None):
        self.sw = sw
        self.desc = desc

        if desc is not None:
            type(self).DESC[sw] = desc
        elif sw in type(self).DESC:
            self.desc = type(self).DESC[sw]

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.sw == other.sw
        else:
            return self.sw == other

    def __int__(self):
        return self.sw

    def __ne__(self, other):
        return not self == other

    def __and__(self, other):
        return self.sw & other

    def __lshift__(self, other):
        return self.sw << other

    def __rshift__(self, other):
        return self.sw >> other

    def __or__(self, other):
        return self.sw | other

    def __str__(self):
        if self.desc is not None:
            return self.desc
        else:
            return f'0x{self.sw:04X}'

    def __repr__(self):
        if self.desc is not None:
            return f'{self.__class__.__qualname__}(0x{self.sw:04X}, {self.desc})'

        else:
            return f'{self.__class__.__qualname__}(0x{self.sw:04X})'


SW_APPLET_SELECT_FAILED = StatusWord(0x6999, 'SW_APPLET_SELECT_FAILED')
SW_BYTES_REMAINING_00 = StatusWord(0x6100, 'SW_BYTES_REMAINING_00')
SW_CLA_NOT_SUPPORTED = StatusWord(0x6E00, 'SW_CLA_NOT_SUPPORTED')
SW_COMMAND_CHAINING_NOT_SUPPORTED = StatusWord(0x6984, 'SW_COMMAND_CHAINING_NOT_SUPPORTED')
SW_COMMAND_NOT_ALLOWED = StatusWord(0x6986, 'SW_COMMAND_NOT_ALLOWED')
SW_CONDITIONS_NOT_SATISFIED = StatusWord(0x6985, 'SW_CONDITIONS_NOT_SATISFIED')
SW_CORRECT_LENGTH_00 = StatusWord(0x6C00, 'SW_CORRECT_LENGTH_00')
SW_DATA_INVALID = StatusWord(0x6984, 'SW_DATA_INVALID')
SW_FILE_FULL = StatusWord(0x6A84, 'SW_FILE_FULL')
SW_FILE_INVALID = StatusWord(0x6A83, 'SW_FILE_INVALID')
SW_FILE_NOT_FOUND = StatusWord(0x6A82, 'SW_FILE_NOT_FOUND')
SW_FUNC_NOT_SUPPORTED = StatusWord(0x6A81, 'SW_FUNC_NOT_SUPPORTED')
SW_INCORRECT_P1P2 = StatusWord(0x6A86, 'SW_INCORRECT_P1P2')
SW_INS_NOT_SUPPORTED = StatusWord(0x6D00, 'SW_INS_NOT_SUPPORTED')
SW_LAST_COMMAND_EXPECTED = StatusWord(0x6883, 'SW_LAST_COMMAND_EXPECTED')
SW_LOGICAL_CHANNEL_NOT_SUPPORTED = StatusWord(0x6881, 'SW_LOGICAL_CHANNEL_NOT_SUPPORTED')
SW_NO_ERROR = StatusWord(0x9000, 'SW_NO_ERROR')
SW_RECORD_NOT_FOUND = StatusWord(0x6A83, 'SW_RECORD_NOT_FOUND')
SW_SECURE_MESSAGING_NOT_SUPPORTED = StatusWord(0x6882, 'SW_SECURE_MESSAGING_NOT_SUPPORTED')
SW_SECURITY_STATUS_NOT_SATISFIED = StatusWord(0x6982, 'SW_SECURITY_STATUS_NOT_SATISFIED')
SW_UNKNOWN = StatusWord(0x6F00, 'SW_UNKNOWN')
SW_WARNING_STATE_UNCHANGED = StatusWord(0x6200, 'SW_WARNING_STATE_UNCHANGED')
SW_WRONG_DATA = StatusWord(0x6A80, 'SW_WRONG_DATA')
SW_WRONG_LENGTH = StatusWord(0x6700, 'SW_WRONG_LENGTH')
SW_WRONG_P1P2 = StatusWord(0x6B00, 'SW_WRONG_P1P2')
SW_REFERENCED_DATA_NOT_FOUND = StatusWord(0x6A88, 'SW_REFERENCED_DATA_NOT_FOUND')


class APDUException(Exception):
    def __init__(self, data, sw):
        self.data = bytes(data)
        self.sw: StatusWord = StatusWord(sw)

    def __str__(self):
        return f'{str(self.sw)}' + ' ' + self.data.hex()


def fromhex(s: str) -> bytes:
    return bytes.fromhex(s)


def encode_apdu(header: bytes, data: bytes|None, le: int|None, force_extended_length=False):
    if data is None:
        data = b''

    if le is not None and le >= 65536:
        force_extended_length = True
        le = 0

    extended_length = force_extended_length or len(data) > 255 or (le is not None and le > 255)

    le_length = (2 if data is not None and len(data) != 0 else 3)  if extended_length else 1
    lc_length = 3 if extended_length else 1

    if data is None or len(data) == 0:
        if le is None:
            return header  # case 1
        else:
            return header + le.to_bytes(length=le_length)  # case 2
    else:
        if le is None:
            return header + len(data).to_bytes(length=lc_length) + data  # case 3
        else:
            return header + len(data).to_bytes(length=lc_length) + data + le.to_bytes(length=le_length)  # case 4


def apdu(c, header, data, le, force_extended_length=False):
    out_total = []
    to_transmit = [*encode_apdu(header, data, le, force_extended_length=force_extended_length)]
    # print('>>>', bytes(to_transmit).hex())
    out, sw1, sw2 = c.transmit(to_transmit)
    if sw1 == 0x6C:
        # print('retrying')
        to_transmit = [*encode_apdu(header, data, sw2, force_extended_length=force_extended_length)]
        out, sw1, sw2 = c.transmit(to_transmit)

    # print('<<<', bytes(out).hex(), hex(sw1), hex(sw2))

    # out_total += bytes(out)
    out_total.append((bytes(out), sw1, sw2))
    while sw1 == 0x61:
        # print('getting all data with', sw2)
        to_transmit = [*encode_apdu(bytes([header[0], 0xC0, 0x00, 0x00]), None, sw2)]
        out, sw1, sw2 = c.transmit(to_transmit)
        # print('<<<', bytes(out).hex(), hex(sw1), hex(sw2))

        # out_total += bytes(out)
        out_total.append((bytes(out), sw1, sw2))

    # print('===', '; '.join(f'{out.hex()} {sw1:02X} {sw2:02X}' for out, sw1, sw2 in out_total))
    # if not (sw1 == 0x90 and sw2 == 0x00):
    #     raise APDUException(out_total, (sw1 << 8) | sw2)

    # return bytes(out_total)
    return out_total


def get_challenge(size=8):
    return os.urandom(size)


def do_ceil(x, y):
    return (x + y - 1) // y


def do_10n_padding(message: bytes|bytearray) -> bytes:
    if isinstance(message, list):
        message = bytes(message)
    return message + b'\x80' + (-(len(message) + 1) % 16) * b'\x00'


def remove_10n_padding(message: bytes|bytearray) -> bytes:
    m = bytearray(message)
    assert len(m) % 16 == 0
    while m[-1] == 0x00:
        m.pop()
    assert m.pop() == 0x80
    return bytes(m)


class CryptogramType(IntEnum):
    CARD = 0
    HOST = 1
    CARD_CHALLENGE = 2
    ENC = 4
    MAC = 6
    RMAC = 7


def label(key_type: CryptogramType, i: int, size: int) -> bytes:
    # size in bits
    return bytes((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, key_type.value, 0)) + struct.pack('>H', size) + bytes((i,))


def session_key(k: bytes, key_type: CryptogramType, challenge: bytes) -> bytes:
    if len(k) == 16:
        return cmac(label(key_type, 1, 128) + challenge, k)
    elif len(k) == 24:
        return cmac(label(key_type, 1, 192) + challenge, k) + cmac(label(key_type, 2, 192) + challenge, k)[:8]
    elif len(k) == 32:
        return cmac(label(key_type, 1, 256) + challenge, k) + cmac(label(key_type, 2, 256) + challenge, k)
    else:
        raise NotImplementedError()


def session_keys(enc: bytes, mac: bytes, challenge: bytes):
    s_enc = session_key(enc, CryptogramType.ENC, challenge)
    s_mac = session_key(mac, CryptogramType.MAC, challenge)
    s_rmac = session_key(mac, CryptogramType.RMAC, challenge)

    return s_enc, s_mac, s_rmac


def cryptogram(cryptogram_type, challenge, length_bits, key):
    assert length_bits % 8 == 0
    out = bytearray()
    for i in range((127 + length_bits) // 128):
        out += cmac(label(cryptogram_type, i+1, length_bits) + challenge, key)
    return out[:length_bits//8]


def cmac(message, key, last_mac=b''):
    return CMAC.new(key, last_mac + message, AES).digest()


def decrypt(seq, payload, key):
    s = b'\x80' + seq.to_bytes(length=15, byteorder='big')

    icv = AES.new(key, AES.MODE_CBC, iv=16*b'\x00').encrypt(s)
    return remove_10n_padding(AES.new(key, AES.MODE_CBC, iv=icv).decrypt(payload))


def encrypt(seq, payload, key):
    s = b'\x00' + seq.to_bytes(length=15, byteorder='big')

    icv = AES.new(key, AES.MODE_CBC, iv=16*b'\x00').encrypt(s)
    return bytearray(AES.new(key, AES.MODE_CBC, iv=icv).encrypt(do_10n_padding(payload)))


GP_DEFAULT_KEY = fromhex('404142434445464748494A4B4C4D4E4F')
ISD_AID = fromhex('A000000151000000')


class SCP03Error(Exception):
    pass


class NotConnectedError(SCP03Error):
    pass


class NotInitializedError(SCP03Error):
    pass


class SCP03:
    def __init__(self, reader, aid, key_enc, key_mac, key_dek, challenge_size=8, chaining_quirk=False):
        self.reader: Reader = reader
        self.conn: CardConnection = self.reader.createConnection()
        self.connected = False
        self.aid = aid
        self.key_enc = key_enc
        self.key_mac = key_mac
        self.key_dek = key_dek
        self.ssc: bytes|None = None
        self.card_challenge: bytes|None = None
        self.host_challenge: bytes|None = None
        self.challenge: bytes|None = None
        self.kdd: bytes|None = None
        self.key_info: bytes|None = None
        self.card_cryptogram: bytes|None = None
        self.host_cryptogram: bytes|None = None
        self.s_mac: bytes|None = None
        self.s_enc: bytes|None = None
        self.s_rmac: bytes|None = None
        self.kvn: int|None = None
        self.scp: int|None = None
        self.i: int|None = None
        self.seq: int = 1
        self.last_cmac: bytes|None = None
        self.secure_channel_initialized = False
        assert challenge_size in (8, 16)
        self.challenge_size = challenge_size
        self.chaining_quirk = chaining_quirk


    def connect(self):
        self.conn.connect()
        self.connected = True


    def clear_apdu(self, header, data, le=None, force_extended_length=False, split=False):
        out = apdu(self.conn, bytes(header), bytes(data) if data is not None else None, le, force_extended_length=force_extended_length)
        if split:
            return out
        else:
            out_total = bytearray()
            sw1 = 0x90
            sw2 = 0x00
            for data, sw1, sw2 in out:
                out_total += data
            if sw1 != 0x90 or sw2 != 0x00:
                raise APDUException(out_total, (sw1 << 8) | sw2)
            return out_total


    def apdu(self, cmd: bytes|list, encrypt=True):
        cmd = bytes(cmd)
        # find APDU case
        if len(cmd) == 4:  # case 1
            header = cmd[:4]
            payload = None
            le = None
            extended_length = False
        elif len(cmd) == 5:  # case 2S
            header = cmd[:4]
            payload = None
            le = cmd[4]
            extended_length = False
        elif cmd[4] != 0 and len(cmd) == 5 + cmd[4]:  # case 3S
            header = cmd[:4]
            payload = cmd[5:]
            le = None
            extended_length = False
        elif cmd[4] != 0 and len(cmd) == 6 + cmd[4]:  # case 4S
            header = cmd[:4]
            payload = cmd[5:-1]
            le = cmd[-1]
            extended_length = False
        elif cmd[4] == 0 and len(cmd) == 7:  # case 2E
            header = cmd[:4]
            payload = None
            le = int.from_bytes(cmd[5:])
            extended_length = True
        elif cmd[4] == 0:
            le_or_lc = int.from_bytes(cmd[5:7])
            if le_or_lc != 0 and cmd[4] == 0 and len(cmd) == 7 + int.from_bytes(cmd[5:7]):  # case 3E
                header = cmd[:4]
                payload = cmd[5:]
                le = None
                extended_length = True
            elif le_or_lc != 0 and cmd[4] == 0 and len(cmd) == 9 + int.from_bytes(cmd[5:7]):  # case 4E
                header = cmd[:4]
                payload = cmd[5:-2]
                le = int.from_bytes(cmd[-2:])
                extended_length = True
            else:
                raise ValueError(f'Invalid APDU: {cmd.hex()}')
        else:
            raise ValueError(f'Invalid APDU: {cmd.hex()}')

        if encrypt:
            if extended_length:
                raise NotImplementedError('no extended length for secure channel, chaining required')
            else:
                return self.transmit(header, payload, le)
        else:
            return self.clear_apdu(header, payload, le, force_extended_length=extended_length)


    def initialize(self, key_version=0x00):
        if not self.connected:
            raise NotConnectedError()

        self.host_challenge = get_challenge(self.challenge_size)

        self.clear_apdu([0x00, 0xA4, 0x04, 0x00], self.aid, 0)
        response = self.clear_apdu([0x80, 0x50, key_version, 0x00], self.host_challenge, 0)

        self.kdd = response[:10]
        self.key_info = response[10:13]
        if self.challenge_size == 8:
            self.card_challenge = response[13:21]
            self.card_cryptogram = response[21:29]
            self.ssc = response[29:32]
        else:
            self.card_challenge = response[13:29]
            self.card_cryptogram = response[29:45]
            self.ssc = response[45:48]

        self.kvn = self.key_info[0]
        self.scp = self.key_info[1]
        self.i = self.key_info[2]

        assert self.scp == 0x03

        self.challenge = self.host_challenge + self.card_challenge

        self.s_enc, self.s_mac, self.s_rmac = session_keys(self.key_enc, self.key_mac, self.challenge)

        assert cryptogram(CryptogramType.CARD, self.challenge, 8*self.challenge_size, self.s_mac) == self.card_cryptogram
        if self.ssc:
            assert cryptogram(CryptogramType.CARD_CHALLENGE, self.ssc + self.aid, 8*self.challenge_size, self.key_enc) == self.card_challenge
        self.host_cryptogram = cryptogram(CryptogramType.HOST, self.challenge, 8*self.challenge_size, self.s_mac)

        cmd = fromhex('8482330010') + self.host_cryptogram
        self.last_cmac = cmac(cmd, self.s_mac, 16*b'\x00')
        self.clear_apdu([0x84, 0x82, 0x33, 0x00], self.host_cryptogram + self.last_cmac[:self.challenge_size], 0)

        self.seq = 1
        self.secure_channel_initialized = True


    def transmit(self, header, payload, le=None):
        if not self.connected:
            raise NotConnectedError()

        if not self.secure_channel_initialized:
            raise NotInitializedError()

        header = bytearray(header)
        header[0] |= 0x04  # set secure messaging bit
        ciphertext = encrypt(self.seq, payload, self.s_enc) if payload else b''

        cmd = header + bytes((len(ciphertext) + self.challenge_size,)) + ciphertext

        self.last_cmac = cmac(cmd, self.s_mac, self.last_cmac)

        data = self.clear_apdu(header, ciphertext + self.last_cmac[:self.challenge_size], le, split=True)
        total = bytearray()
        sw1 = 0x90
        sw2 = 0x00

        if self.chaining_quirk:
            for resp, sw1, sw2 in data:
                rdf = resp[:-self.challenge_size]
                rmac = resp[-self.challenge_size:]
                response_full = bytes((*rdf, sw1, sw2))

                if resp:
                    rmac_expected = cmac(response_full, self.s_rmac, self.last_cmac)[:self.challenge_size]
                    assert rmac == rmac_expected
                    if rdf:
                        decrypted = decrypt(self.seq, rdf, self.s_enc)
                        total += decrypted
        else:
            resp = bytearray()
            for fragment, fragment_sw1, fragment_sw2 in data:
                resp += fragment
                sw1 = fragment_sw1
                sw2 = fragment_sw2

            rdf = resp[:-self.challenge_size]
            rmac = resp[-self.challenge_size:]
            response_full = bytes((*rdf, sw1, sw2))

            if resp:
                rmac_expected = cmac(response_full, self.s_rmac, self.last_cmac)[:self.challenge_size]
                assert rmac == rmac_expected
                if rdf:
                    decrypted = decrypt(self.seq, rdf, self.s_enc)
                    total += decrypted

        self.seq += 1

        if sw1 != 0x90 or sw2 != 0x00:
            raise APDUException(bytes(total), (sw1 << 8) | sw2)

        return bytes(total)


class PreparedSCP03:
    def __init__(self, aid, key_enc, key_mac, key_dek, kdd, ssc, challenge_size=8):
        self.aid = aid
        self.key_enc = key_enc
        self.key_mac = key_mac
        self.key_dek = key_dek
        self.ssc: bytes = ssc
        self.card_challenge: bytes|None = None
        self.host_challenge: bytes|None = None
        self.challenge: bytes|None = None
        self.kdd: bytes = kdd
        self.host_cryptogram: bytes|None = None
        self.s_mac: bytes|None = None
        self.s_enc: bytes|None = None
        self.s_rmac: bytes|None = None
        self.seq: int = 1
        self.last_cmac: bytes|None = None
        assert challenge_size in (8, 16)
        self.challenge_size = challenge_size
        self.prepared_apdus = []


    def initialize(self, challenge):
        self.host_challenge = challenge  # get_challenge(self.challenge_size)

        self.card_challenge = cryptogram(CryptogramType.CARD_CHALLENGE, self.ssc + self.aid, 64, self.key_enc)

        print('Computed card challenge:', self.card_challenge.hex())

        self.challenge = self.host_challenge + self.card_challenge

        self.s_enc, self.s_mac, self.s_rmac = session_keys(self.key_enc, self.key_mac, self.challenge)

        print('S-ENC:', self.s_enc.hex())
        print('S-MAC:', self.s_mac.hex())
        print('S-RMAC:', self.s_rmac.hex())

        self.host_cryptogram = cryptogram(CryptogramType.HOST, self.challenge, 64, self.s_mac)
        print('Host cryptogram:', self.host_cryptogram.hex())

        external_authenticate = fromhex('8482330010') + self.host_cryptogram  # C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC
        self.last_cmac = cmac(external_authenticate, self.s_mac, 16*b'\x00')
        self.seq = 1

        self.prepared_apdus.append(bytes((0x00, 0xA4, 0x04, 0x00, len(self.aid), *self.aid, 0)))
        self.prepared_apdus.append(fromhex('8050') + bytes((0x00, 0x00, self.challenge_size, *self.host_challenge, 0)))
        self.prepared_apdus.append(external_authenticate + self.last_cmac[:self.challenge_size] + b'\x00')


    def transmit(self, header, payload):
        header = bytearray(header)
        header[0] |= 0x04  # set secure messaging bit
        ciphertext = encrypt(self.seq, payload, self.s_enc)
        cmd = header + bytes((len(ciphertext) + self.challenge_size,)) + ciphertext

        self.last_cmac = cmac(cmd, self.s_mac, self.last_cmac)
        self.prepared_apdus.append(cmd + self.last_cmac[:self.challenge_size] + b'\x00')
        self.seq += 1


    def get_apdu_sequence(self):
        return self.prepared_apdus[:]
