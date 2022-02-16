# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# transport.py
#
# Implement the desktop to card connection for our cards, both TAPSIGNER and SATSCARD.
#
#
import sys, os, cbor2
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from .utils import *
from .constants import *
from .exceptions import CardRuntimeError
from pprint import pformat
from .compat import hash160, sha256s
from .proto import CKTapCard

# Change this to see traffic details
VERBOSE = False

def find_cards():
    #
    # Search all connected card readers, and find all cards that are present.
    #
    # - generator function.
    #
    from smartcard.System import readers as get_readers
    from smartcard.Exceptions import CardConnectionException, NoCardException

    # emulation running on a Unix socket
    sim = CKTapUnixTransport.find_simulator()
    if sim:
        yield CKTapCard(sim)

    readers = get_readers()
    if not readers:
        raise RuntimeError("No USB card readers found. Need at least one.")

    # search for our card
    for r in readers:
        try:
            conn = r.createConnection()
        except:
            continue
        
        try:
            conn.connect()
            atr = conn.getATR()
        except (CardConnectionException, NoCardException):
            #print(f"Empty reader: {r}")
            continue

        if atr == CARD_ATR:
            tr = CKTapNFCTransport(conn)
            yield CKTapCard(tr)
        else:
            print(f"Got ATR: {atr}")

def find_first():
    # operate on the first card we can find
    for c in find_cards():
        return c

    return None

class CKTapTransportABC:
    #
    # Abstract base class. Low level details about talking our protocol.
    #

    def _send_recv(self, msg):
        # take CBOR encoded request, and round-trip the request + response
        raise NotImplementedError

    def get_ATR(self):
        # ATR = Answer To Reset
        raise NotImplementedError

    def close(self):
        # release resources
        pass

    def send(self, cmd, **args):
        # Serialize command, send it as ADPU, get response and decode

        args = dict(args)
        args['cmd'] = cmd
        msg = cbor2.dumps(args)

        if VERBOSE:
            print(f">> {cmd} (%s)" % ', '.join(k+'='+(str(v) if len(str(v)) < 9 else '...')
                                            for k,v in args.items() if k != 'cmd'))

        # Send and wait for reply
        stat_word, resp = self._send_recv(msg)

        try:
            resp = cbor2.loads(resp) if resp else {}
        except:
            #print("Bad CBOR rx'd from card:\n{B2A(resp)}")
            raise RuntimeError('Bad CBOR from card')
            
        if VERBOSE:
            print("<< ", end='')
            if 'error' not in resp:
                print(', '.join(resp.keys()))
            else:
                print(pformat(resp))

        return stat_word, resp

class CKTapNFCTransport(CKTapTransportABC):
    #
    # For talking to a real card over USB to a reader.
    #

    def __init__(self, card_conn):
        # Check connection they gave us
        # - if you don't have that, use find_cards instead
        atr = card_conn.getATR()
        assert atr == CARD_ATR, "wrong ATR from card"

        self._conn = card_conn

        # Perform "ISO Select" to pick our app
        # - 00 a4 04 00 (APPID)
        # - probably optional
        sw, resp = self._apdu(0x00, 0xa4, APP_ID, p1=4)
        assert sw == SW_OKAY, "ISO app select failed"

    def close(self):
        # release resources
        self._conn.disconnect()
        del self._conn

    def get_ATR(self):
        return self._conn.getATR()

    def _apdu(self, cls, ins, data, p1=0, p2=0):
        # send APDU to card
        lst = [ cls, ins, p1, p2, len(data)] + list(data)
        resp, sw1, sw2 = self._conn.transmit(lst)
        resp = bytes(resp)
        return ((sw1 << 8) | sw2), resp

    def _send_recv(self, msg):
        # send raw bytes (already CBOR encoded) and get response back
        assert len(msg) <= 255, "msg too long"
        return self._apdu(CBOR_CLA, CBOR_INS, msg)

class CKTapUnixTransport(CKTapTransportABC):
    #
    # Emulation running over a Unix socket.
    #

    @classmethod
    def find_simulator(cls):
        import os
        FN = '/tmp/ecard-pipe'
        if os.path.exists(FN):
            return cls(FN)
        return None

    def __init__(self, pipename):
        import socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(pipename)
        self.first_look()
        self._certs_checked = True      # because it won't pass

    def get_ATR(self):
        return CARD_ATR

    def _send_recv(self, msg):
        # send and receive response back
        self.sock.sendall(msg)
        resp = self.sock.recv(4096)

        if not resp:
            # closed socket causes this
            raise RuntimeError("Emu crashed?")

        return 0x9000, resp


# EOF
