#!/usr/bin/env python3
# 
# (c) Copyright 2021 by Coinkite Inc. All rights reserved.
#
# Emulate an SATSCARD or TAPSIGNER card.
#
import os, sys, struct, pdb, click, random, traceback, subprocess
from collections import namedtuple
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from dataclasses import dataclass, field
from pprint import pprint, pformat
from hexdump import hexdump
import cbor2, bech32

# see <https://wally.readthedocs.io/en/release_0.8.3/crypto/>
from wallycore import ec_sig_verify, ec_public_key_verify, ec_sig_to_public_key
from wallycore import ec_public_key_from_private_key, ec_public_key_decompress
from wallycore import hash160                           # = ripemd160(sha256(x)) => 20 bytes
from wallycore import ec_sig_from_bytes as ec_sig_from_digest       # fix misnomer
from wallycore import ecdh as wally_ecdh                            # preference
from wallycore import EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE

# show bytes as hex in a string
B2A = lambda x: b2a_hex(x).decode('ascii')

# single-shot SHA256
sha256s = lambda msg: sha256(msg).digest()

# Print more?
DEBUG = True

# Operate on testnet? Affects address displays, but none of the math.
TESTNET = True

# Design parameters: might be subject to change.
NUM_SLOTS = 10
ADDR_TRIM = 12
CARD_NONCE_SIZE = 16
USER_NONCE_SIZE = 16
ROOT_PUBKEY = None              # expected pubkey of root certificate in chain
NDEF_URL = lambda ts: 'getsatscard.com/start#' if not ts else 'tapsigner.com/start#'
FIXED_AES_KEY = b'A'*16

# placeholder, but required param
REQUIRED = object()

# high bit set in LE32 indicating hardened BIP-32 path component
HARDENED = 0x8000_0000
HARD = lambda x: (x | 0x8000_0000)
all_hardened = lambda path: all(bool(i & HARDENED) for i in path)
none_hardened = lambda path: not any(bool(i & HARDENED) for i in path)
DEFAULT_TAPSIGNER_PATH = [ HARD(84), HARD(0), HARD(0) ]

def path2str(path):
    return '/'.join(['m'] + [ str(i & ~HARDENED)+('h' if i&HARDENED else '') for i in path])

# provides msg+code number
class CKErrorCode(RuntimeError):
    def __init__(self, msg, code):
        self.code = code
        super().__init__(msg)

def prandom(count):
    # make some bytes, randomly, but not: fully deterministic
    return bytes(random.randint(0, 255) for i in range(count))

def maybe_unlucky():
    if random.randint(0, 8) == 1:
        print("such bad luck")
        raise CKErrorCode("unlucky number", 205)

def xor_bytes(a, b):
    # XOR the bytes of A and B
    assert len(a) == len(b)
    return bytes(i^j for i,j in zip(a,b))

def pick_keypair():
    # Choose pub/private pair. Verify it's on curve. Fully random, except using PRNG
    for retry in range(3):
        priv = prandom(32)
        try:
            pub = ec_public_key_from_private_key(priv)
        except ValueError:
            print(f'bad luck: {B2A(priv)}')
            continue

        return priv, pub
    else:
        raise ValueError("stuck RNG")

def is_pubkey(p):
    # check it looks like a compressed public key
    return len(p) == 33 and (p[0] in { 2, 3})

def is_valid_pubkey(p):
    # check it 
    # - looks like a compressed public key
    # - is a pubkey on this curve: slow but important
    if not is_pubkey(p): return False
    try:
        ec_public_key_verify(p)
        return True
    except:
        return False

def render_address(pubkey, testnet):
    # make the text string used as a payment address
    HRP = 'bc' if not testnet else 'tb'
    return bech32.encode(HRP, 0, hash160(pubkey))

def trim_address(a):
    # remove middle part of bech32 address, replace with underscore
    return a[:ADDR_TRIM] + '___' + a[-ADDR_TRIM:]

def bip32_derivation(chain_code, master_privkey, path):
    # return privkey for "m/0" key derived by BIP32 method
    # - non-hardended derivation, always zero key
    # - want private key out, will calc public from that
    # - plus new chain code

    from wallycore import bip32_key_init, bip32_key_get_pub_key, bip32_key_from_parent
    from wallycore import bip32_key_get_priv_key, bip32_key_get_chain_code
    from wallycore import BIP32_VER_MAIN_PUBLIC, BIP32_VER_MAIN_PRIVATE
    from wallycore import BIP32_FLAG_SKIP_HASH, BIP32_FLAG_KEY_PUBLIC

    a = bip32_key_init(BIP32_VER_MAIN_PRIVATE, 0, 0, chain_code,
                        None, master_privkey, None, None)
    for comp in path:
        a = bip32_key_from_parent(a, comp, BIP32_FLAG_SKIP_HASH)

    return bip32_key_get_priv_key(a), bip32_key_get_pub_key(a), bip32_key_get_chain_code(a)


@dataclass
class KeySlot:
    '''
        Info we store for each key slot
    '''
    privkey: bytes = bytes(32)
    pubkey: bytes = bytes(33)
    is_used: bool = False
    is_sealed: bool = True
    chain_code: bytes = bytes(0)
    master_pk: bytes = bytes(0)
    addr: (str, None) = None
    deriv_path: (list, None) = None
    deriv_chain_code: (None, bytes) = None

    def setup(self, chain_code, testnet=False, path=[0]):
        assert not self.is_used
        assert len(chain_code) == 32
        assert len(set(chain_code)) >= 2

        # complex BIP-32 based picking.
        self.master_pk, master_pubkey = pick_keypair()
        self.chain_code = chain_code

        # calculate addres for "m/0" derived from those values
        # with BIP-32 method
        self.privkey, self.pubkey, self.deriv_chain_code = \
                bip32_derivation(self.chain_code, self.master_pk, path)
        self.deriv_path = list(path)

        #self.pubkey = ec_public_key_from_private_key(self.privkey)
        self.addr = render_address(self.pubkey, testnet)
        
        self.is_used = True

    def save_derive(self, path):
        # tapsigner: save updated derive
        assert all_hardened(path)
        self.privkey, self.pubkey, self.deriv_chain_code = \
                bip32_derivation(self.chain_code, self.master_pk, path)
        self.deriv_path = list(path)

    def tmp_derive(self, path):
        # tapsigner: Do one-time derivation (subkey)
        assert none_hardened(path)
        return bip32_derivation(self.deriv_chain_code, self.privkey, path)

    def unseal(self):
        assert self.is_used
        assert self.is_sealed

        self.is_sealed = False

@dataclass
class CardState:
    '''
        Whole-card state
    '''
    card_pubkey: bytes
    card_privkey: bytes
    active_slot: int
    birth: int
    cvc: bytes
    slots: list
    cert_chain: (tuple, None)
    url_prefix: (bytes, None)
    testnet: bool = False

    # tap signer
    is_tapsigner: bool = False
    num_backups: int = 0
    aes_key: (None, bytes) = None

    def __init__(self):
        self.card_privkey, self.card_pubkey = pick_keypair()
        self.slots = [KeySlot() for i in range(NUM_SLOTS)]
        self.active_slot = 0
        self.cvc = None
        self.birth = 0
        self.cert_chain = None
        self.url_prefix = None
        self._new_nonce()

    def _new_nonce(self):
        # call when we need a fresh nonce
        self.nonce = prandom(CARD_NONCE_SIZE)

    def _factory_reset(self):
        # TEST ONLY: reset all state and be a factory-fresh card again
        self.__init__()

    @property
    def cur_slot(self):
        # save typing
        return self.slots[self.active_slot]

    @property
    def card_ident(self):
        assert self.is_tapsigner
        return sha256(self.card_pubkey).digest()[0:8]

    def __repr__(self):
        if not self.birth:
            return f'<CARD: unborn>'

        s = self.cur_slot
        if self.is_tapsigner:
            ident = B2A(self.card_ident)
            if s.is_used:
                return f'<TAPSIGNER: {ident} READY @ {path2str(s.deriv_path)}>'
            else:
                return f'<TAPSIGNER: {ident} UNUSED>'
        else:
            here = s.addr if s.is_used else 'NO-ADDR-YET'
            if not s.is_sealed:
                here += ' UNSEALED'
            return f'<SATSCARD: #{self.active_slot} {here}>'

    # 
    # Commands. 
    #

    def cmd_status(self, **unused):
        # implement the "status" command

        rv = dict(proto=1, ver='0.1.0', birth=self.birth,
                        pubkey=self.card_pubkey, card_nonce=self.nonce)

        if self.testnet:
            rv['testnet'] = True

        if self.is_tapsigner:
            rv['tapsigner'] = True
            rv['num_backups'] = self.num_backups
            if self.cur_slot.is_used:
                rv['path'] = self.cur_slot.deriv_path
        else:
            if self.active_slot < NUM_SLOTS and self.cur_slot.is_used:
                rv['addr'] = trim_address(self.cur_slot.addr)

            rv['slots'] = (self.active_slot,  NUM_SLOTS)

        return rv

    def cmd_read(self, nonce=REQUIRED, **unused):
        # implement "read" command which is used to calculate full address and verify everything
        assert len(nonce) == USER_NONCE_SIZE, 'bad nonce size'
        if len(set(nonce)) == 1: raise CKErrorCode("weak nonce", 417)
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert self.cur_slot.is_used, 'slot unused'

        msg = b'OPENDIME' + self.nonce + nonce + bytes([self.active_slot])
        assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1


        sig = ec_sig_from_digest(self.cur_slot.privkey, sha256s(msg), EC_FLAG_ECDSA)
        self._new_nonce()

        return dict(sig=sig, card_nonce=self.nonce, pubkey=self.cur_slot.pubkey)

    def cmd_new(self, slot=REQUIRED, epubkey=REQUIRED, xcvc=REQUIRED, chain_code=None, path=None, **unused):
        # Pick a new key for current slot
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert not self.cur_slot.is_used, "current slot not used yet"
        if self.is_tapsigner:
            assert slot in {0, REQUIRED}
            slot =0
        assert slot != REQUIRED, 'need slot #'
        assert 0 <= slot < NUM_SLOTS, "card is consumed"
        assert slot == self.active_slot, 'wrong slot'

        if slot != 0:       # XXX hack for dev
            ses_key = self._validate_cvc('new', epubkey, xcvc)

        if not chain_code:
            assert slot >= 1, 'need chain code for first slot at least'
            chain_code = self.slots[slot-1].chain_code
        else:
            assert len(chain_code) == 32, 'bad chain code'

        if self.is_tapsigner:
            if path is None:
                path = DEFAULT_TAPSIGNER_PATH
            assert all_hardened(path), 'need hard path'
        else:
            path = [0]      # m/0

        self.cur_slot.setup(chain_code, testnet=self.testnet, path=path)

        self._new_nonce()
        return dict(slot=slot, card_nonce=self.nonce)

    def cmd_derive(self, nonce=REQUIRED, path=REQUIRED, **unused):
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert nonce != REQUIRED, 'need nonce'
        assert len(nonce) == USER_NONCE_SIZE, 'bad nonce size'
        if len(set(nonce)) == 1: raise CKErrorCode("weak nonce", 417)
        assert self.cur_slot.is_used, 'slot unused'


        if self.is_tapsigner:
            # TAPSIGNER
            path = list(path)
            assert 0 <= len(path) <= 10, 'path too long'
            assert all_hardened(path), 'must have all hardened components'

            # auth required, but for TS case only
            ses_key = self._validate_cvc('derive', unused['epubkey'], unused['xcvc'])

            self.cur_slot.save_derive(path)

            msg = b'OPENDIME' + self.nonce + nonce + self.cur_slot.deriv_chain_code
            sig = ec_sig_from_digest(self.cur_slot.privkey, sha256s(msg), EC_FLAG_ECDSA)

            self._new_nonce()
            return dict(sig=sig, chain_code=self.cur_slot.deriv_chain_code,
                            pubkey=self.cur_slot.pubkey, 
                            card_nonce=self.nonce)
        else:
            # SATSCARD
            assert path==REQUIRED, 'dont give path'
            
            msg = b'OPENDIME' + self.nonce + nonce + self.cur_slot.chain_code
            sig = ec_sig_from_digest(self.cur_slot.master_pk, sha256s(msg), EC_FLAG_ECDSA)

            # pubkey of this slot (or we could store this when constructed?)
            pubkey = ec_public_key_from_private_key(self.cur_slot.master_pk)

            return dict(sig=sig, chain_code=self.cur_slot.chain_code,
                            card_nonce=self.nonce, master_pubkey=pubkey)

    def cmd_change(self, data=REQUIRED, epubkey=REQUIRED, xcvc=REQUIRED, **unused):
        # Change CVC code (PIN)
        if not self.is_tapsigner: raise CKErrorCode('not for sc', 404)
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert data != REQUIRED, 'missing new cvc'
        assert 6 <= len(data) <= 32, 'bad len on new cvc'
        if not self.num_backups: raise CKErrorCode('card not yet backed-up', 425)

        ses_key = self._validate_cvc('change', epubkey, xcvc)

        # decrypt
        new_cvc = xor_bytes(ses_key[0:len(data)], data)

        # save
        self.cvc = new_cvc

        self._new_nonce()
        return dict(success=True, card_nonce=self.nonce)


    def cmd_check(self, nonce=REQUIRED, **unused):
        # prove our pubkey was signed by certs
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert len(nonce) == USER_NONCE_SIZE, 'bad nonce size'
        if len(set(nonce)) == 1: raise CKErrorCode("weak nonce", 417)

        msg = b'OPENDIME' + self.nonce + nonce
        #print(f'signed msg: {B2A(msg)}')
        assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE
        
        sig = ec_sig_from_digest(self.card_privkey, sha256s(msg), EC_FLAG_ECDSA)

        try:
            ec_sig_verify(self.card_pubkey, sha256s(msg), EC_FLAG_ECDSA, sig)
        except ValueError:
            raise RuntimeError("failed selftest")

        self._new_nonce()
        return dict(auth_sig=sig, card_nonce=self.nonce)

    def _validate_cvc(self, cmd, epubkey, xcvc):
        # Check they've done the math right and know the CVC printed on us.
        if epubkey == REQUIRED or xcvc == REQUIRED:
            raise CKErrorCode('need epub&xcvc', 403)
        assert is_valid_pubkey(epubkey), 'they gave a bogus pubkey'
        assert len(xcvc) == len(self.cvc), 'wrong cvc length'

        ses_key, expect = calc_xcvc(cmd, self.nonce, epubkey, self.card_privkey, self.cvc)

        if xcvc != expect:
            raise CKErrorCode('bad auth', 401)

        return ses_key

    def _check_visible_slot(self, slot):
        # Verify indicated slot is already unsealed and has a private key we are allowed to share.
        try:
            if slot == self.active_slot:
                assert not self.cur_slot.is_sealed, "if using current slot, but be unsealed"
            else:
                assert slot < self.active_slot, "can only view old slots"

            was = self.slots[slot]
            assert was.is_used, "never picked a key for that slot"
        except AssertionError as exc:
            raise CKErrorCode(str(exc), 406)

        return was

    def cmd_unseal(self, slot=REQUIRED, epubkey=REQUIRED, xcvc=REQUIRED, **unused):
        # Unseal current slot
        if self.is_tapsigner: raise CKErrorCode('not for ts', 404)
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)

        ses_key = self._validate_cvc('unseal', epubkey, xcvc)

        assert slot == self.active_slot, 'wrong slot'

        # looks ok, do the unseal
        was = self.cur_slot
        was.unseal()

        self.active_slot += 1

        pk = xor_bytes(was.privkey, ses_key)

        self._new_nonce()
        return dict(slot=slot, card_nonce=self.nonce, pubkey=was.pubkey,
                        privkey=pk, chain_code=was.chain_code,
                        master_pk=was.master_pk)

    def cmd_xpub(self, master=False, epubkey=None, xcvc=None, **unused):
        # Dump xpub
        if not self.is_tapsigner: raise CKErrorCode('only for ts', 404)
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        if not self.cur_slot.is_used: raise CKErrorCode('key not yet setup', 400)

        ses_key = self._validate_cvc('xpub', epubkey, xcvc)

        s = self.cur_slot

        if master:
            cc = s.chain_code
            pubkey = ec_public_key_from_private_key(s.master_pk)
            depth = 0
            kid_num = 0
            pfp = bytes(4)
        else:
            cc = s.deriv_chain_code
            pubkey = s.pubkey
            depth = len(s.deriv_path)
            pfp = bytes([0xff]*4)       ## wrong, but compromise
            kid_num = s.deriv_path[-1] if s.deriv_path else 0

        vers = bytes.fromhex('0488B21E' if not self.testnet else '043587CF')

        from struct import pack
        rv = vers + bytes([depth]) + pfp + pack('>I', kid_num) + cc + pubkey
        assert len(rv) == 78

        self._new_nonce()
        return dict(xpub=rv, card_nonce=self.nonce)

    def cmd_dump(self, slot=REQUIRED, epubkey=None, xcvc=None, **unused):
        # Dump information about used slots.
        if self.is_tapsigner: raise CKErrorCode('not for ts', 404)
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)
        assert slot != REQUIRED, 'missing slot'
        assert 0 <= slot < NUM_SLOTS, "bad slot"

        if not epubkey or not xcvc:
            assert epubkey==None and xcvc==None, 'both xcvc and epubkey or neither'
            ses_key = None
        else:
            ses_key = self._validate_cvc('dump', epubkey, xcvc)

        self._new_nonce()
        rv = dict(slot=slot, card_nonce=self.nonce)

        if slot < self.active_slot:
            # unsealed slot
            if not ses_key:
                rv['sealed'] = False
                rv['addr'] = self.slots[slot].addr
            else:
                # they have CVC
                was = self._check_visible_slot(slot)
                pk = xor_bytes(was.privkey, ses_key)
                mpk = xor_bytes(was.master_pk, ses_key)

                rv.update(dict(privkey=pk, master_pk=mpk, chain_code=was.chain_code,
                                    pubkey=was.pubkey))
        else:
            was = self.slots[slot]
                
            if was.is_used:
                rv['sealed'] = True
                rv['addr'] = trim_address(self.slots[slot].addr)
            else:
                rv['used'] = False

        return rv


    def cmd_certs(self, cert_chain=None, **unused):
        # provide our certificates or set them (factory time)
        if cert_chain:
            assert not self.cvc, 'factory commmand must be after certs setup'
            assert not self.cert_chain, 'got certs already'
            assert all(len(c)==65 for c in cert_chain), 'bad certs'
            assert len(cert_chain) == 2, 'expect root+batch only'
            self.cert_chain = cert_chain

            return dict(success=True)

        if not self.cert_chain: raise CKErrorCode('card not yet setup', 406)

        return dict(cert_chain=self.cert_chain)

    def cmd_factory(self, birth=REQUIRED, cvc=REQUIRED, slots=10, url=REQUIRED,
                                aes_key=None,
                                testnet=False, tapsigner=False, **unused_args):
        # One-time factory setup and data capture
        if self.cvc: raise CKErrorCode('already setup', 404)
        assert 6 <= len(cvc) <= 32, 'bad cvc length'
        assert birth > 700000, 'birth out of range'
        assert testnet in { True, False }
        assert tapsigner in { True, False }
        assert not unused_args, "factory should get args right"
        if isinstance(cvc, str):
            cvc = cvc.encode('ascii')

        if not self.cert_chain:
            raise CKErrorCode('need certs to be set first', 406)
            
        # save to "flash"

        self.url_prefix = url
        self.birth = birth
        self.cvc = cvc
        self.testnet = testnet

        if tapsigner:
            # ignore slots arg
            self.is_tapsigner = True
            assert len(aes_key) == 16
            self.aes_key = aes_key
        else:
            # for re-run of test
            self.is_tapsigner = False

        return dict(success=True)

    def cmd_nfc(self, **unused):
        # Return URL for NFC purposes
        return dict(url='https://' + self._nfc_dynread())

    def cmd_sign(self, slot=0, epubkey=REQUIRED, xcvc=REQUIRED, digest=REQUIRED, subpath=[], **unused):
        # Dump information about used slots.
        if not self.cvc: raise CKErrorCode('card not yet setup', 406)

        assert 0 <= slot < NUM_SLOTS, "bad slot"
        # ok to use indicated slot?

        assert epubkey != REQUIRED, 'missing epubkey'
        assert xcvc != REQUIRED, 'missing xcvc'
        assert digest != REQUIRED, 'missing digest'
        assert len(digest) == 32, 'digest wrong size'

        # check security and calc shared session key
        ses_key = self._validate_cvc('sign', epubkey, xcvc)

        # decrypt digest to be signed.
        md = xor_bytes(digest, ses_key)

        maybe_unlucky()

        if self.is_tapsigner:
            assert 0 <= len(subpath) <= 2
            assert none_hardened(subpath)
            pk, pub, _ = self.cur_slot.tmp_derive(subpath)
        else:
            was = self._check_visible_slot(slot)
            pk = was.privkey
            pub = was.pubkey

        # do signature
        sig = ec_sig_from_digest(pk, md, EC_FLAG_ECDSA)
        assert len(sig) == 64

        self._new_nonce()
        return dict(slot=slot, card_nonce=self.nonce, sig=sig, pubkey=pub)

    def cmd_backup(self, epubkey=REQUIRED, xcvc=REQUIRED, **unused):
        if not self.is_tapsigner:
            raise CKErrorCode('ts only', 404)
        assert epubkey != REQUIRED, 'missing epubkey'
        assert xcvc != REQUIRED, 'missing xcvc'

        if not self.cur_slot.is_used:
            raise CKErrorCode('secret not yet setup', 406)
        
        # check security and calc shared session key
        ses_key = self._validate_cvc('backup', epubkey, xcvc)

        d = dict(chain_code=self.cur_slot.chain_code, privkey=self.cur_slot.master_pk,
                    path=self.cur_slot.deriv_path)

        raw = cbor2.dumps(d)

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(self.aes_key), modes.CTR(bytes(16))).encryptor()
        rv = enc.update(raw) + enc.finalize()
        
        if self.num_backups != 127:
            self.num_backups += 1
        self._new_nonce()
        return dict(data=rv, card_nonce=self.nonce)

    def _nfc_dynread(self):
        # Provide the bytes we would emulate over NFC if queried at this moment
        # - just the URL tho
        nonce = prandom(8)

        if self.is_tapsigner:
            state = 'S' if self.cur_slot.is_used else 'U'
            msg = 't=1&u=%s&c=%s&n=%s&s=' % (state, B2A(self.card_ident), B2A(nonce))
            key = self.card_privkey
        else:
            if self.cur_slot.is_used:
                slot = self.cur_slot 
                slot_num = self.active_slot
            elif self.active_slot > 0:
                slot = self.slots[self.active_slot-1]
                slot_num = self.active_slot-1
            else:
                # we are confused / can't sign nothing
                return self.url_prefix

            state = 'S' if slot.is_sealed else 'U'
            addr = slot.addr or ('x'*8)

            msg = 'u=%s&o=%d&r=%s&n=%s&s=' % (state, slot_num, addr[-8:], B2A(nonce))
            key = slot.privkey

        md = sha256s(msg.encode('ascii'))
        sig = ec_sig_from_digest(key, md, EC_FLAG_ECDSA)

        return self.url_prefix + msg + B2A(sig)


    def emulate(self, pipename):
        # Using a unix socket as connector, run as an emulator for the card.
        import atexit, os, sys, socket, errno

        # manage unix socket cleanup for client
        def sock_cleanup():
            if os.path.exists(pipename):
                os.unlink(pipename)
        sock_cleanup()
        atexit.register(sock_cleanup)

        pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        pipe.bind(pipename)
        pipe.listen()
        while 1:
            print(f"Waiting for new connection on: {pipename}")
            con, addr = pipe.accept()

            print(f"Connected.")

            while 1:
                msg = con.recv(256)
                if not msg: break

                cmd = None
                try:
                    try:
                        msg = cbor2.loads(msg)
                    except BaseException as exc:
                        print(f"Unable to decode CBOR:  {B2A(msg)}\nGot: {exc}")
                        raise CKErrorCode('bad cbor', 422)

                    if not isinstance(msg, dict):
                        raise CKErrorCode('bad cbor top-level obj', 422)

                    # decode command to execute

                    cmd = msg.pop('cmd', None)
                    if not cmd: raise CKErrorCode('no cmd in msg', 404)

                    # special commands, not required in real product
                    if cmd == 'XXX_NFC':
                        resp = dict(nfc=self._nfc_dynread())
                    elif cmd == 'XXX_RESET':
                        # completely reset our state!
                        self._factory_reset()
                        resp = dict(ok=True)
                    else:
                        # lookup command
                        method = getattr(self, 'cmd_'+cmd, None)
                        if not method: raise CKErrorCode('unknown cmd', 404)

                        # execute command
                        resp = method(**msg)
                except CKErrorCode as exc:
                    resp = dict(error=str(exc), code=exc.code)
                except AssertionError as exc:
                    resp = dict(error=str(exc), code=400)
                except BaseException as exc:
                    # shouldn't happen
                    print(f"FAILED: Command '{cmd}({msg})' => {exc}")
                    traceback.print_exc()
                    resp = dict(error="internal fail", code=500)

                if DEBUG:
                    if not msg:
                        xargs = '' 
                    elif not hasattr(msg, 'items'):
                        xargs = '(%r)' % msg
                    else:
                        xargs = '(' + ', '.join(f'{k}={v}' for k,v in msg.items()) + ')'

                    print(f"Command '{cmd}{xargs}' => ", end='')
                    if 'error' not in resp:
                        print(', '.join(resp.keys()))
                    else:
                        print(pformat(resp))

                resp = cbor2.dumps(resp)
                con.sendall(resp)

            con.close()


def verify_certs(status_resp, check_resp, certs_resp, my_nonce):
    # Verify the certificate chain works, returns root pubkey when actually used.
    #
    signatures = certs_resp['cert_chain']
    assert len(signatures) >= 2

    r = status_resp
    msg = b'OPENDIME' + r['card_nonce'] + my_nonce
    print(f'SIGNED msg: {B2A(msg)}')
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE

    try:
        ec_sig_verify(r['pubkey'], sha256s(msg), EC_FLAG_ECDSA, check_resp['auth_sig'])
    except ValueError:
        raise RuntimeError("sig from card wrong")
    
    pubkey = r['pubkey']

    for sig in signatures:
        pubkey = ec_sig_to_public_key(sha256s(pubkey), sig)

    return pubkey

def recover_address(status_resp, read_resp, my_nonce):
    # Given the response from "status" and "read" commands, and the nonce we gave for read command,
    # reconstruct the card's verified payment address. Check prefix/suffix match what's expected
    r = status_resp

    expect = r['addr']
    left = expect[0:expect.find('_')]
    right = expect[expect.rfind('_')+1:]

    msg = b'OPENDIME' + r['card_nonce'] + my_nonce + bytes([r['slots'][0]])
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1

    pubkey = read_resp['pubkey']
    assert is_pubkey(pubkey)

    try:
        ec_sig_verify(pubkey, sha256s(msg), EC_FLAG_ECDSA, read_resp['sig'])
    except ValueError:
        raise RuntimeError("bad signature vs. pubkey")
    testnet = r.get('testnet', False)

    got = render_address(pubkey, testnet)
    assert got.startswith(left)
    assert got.endswith(right)

    return got

def recover_master_pubkey(derive_resp, card_nonce, my_nonce, testnet=False):
    # Given the response from "derive" commands, reconstruct XPUB.
    chain_code = derive_resp['chain_code']
    pubkey = derive_resp['master_pubkey']
    assert is_pubkey(pubkey)

    msg = b'OPENDIME' + card_nonce + my_nonce + chain_code
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 32

    try:
        ec_sig_verify(pubkey, sha256s(msg), EC_FLAG_ECDSA, derive_resp['sig'])
    except ValueError:
        raise RuntimeError("failed selftest")

    from wallycore import bip32_key_init, bip32_key_get_pub_key, bip32_key_from_parent
    from wallycore import BIP32_VER_MAIN_PUBLIC, BIP32_VER_MAIN_PRIVATE
    from wallycore import BIP32_FLAG_SKIP_HASH, BIP32_FLAG_KEY_PUBLIC

    m = bip32_key_init(BIP32_VER_MAIN_PUBLIC, 0, 0, chain_code, pubkey, None, None, None)
    node = bip32_key_from_parent(m, 0, BIP32_FLAG_SKIP_HASH | BIP32_FLAG_KEY_PUBLIC)
    a_pubkey = bip32_key_get_pub_key(node)

    return render_address(a_pubkey, testnet)
    
def fake_cert_chain(card_pubkey):
    # Make up some certs for batch and root, sign card's pubkey with batch and make chain.
    r, r_pub = pick_keypair()
    b, b_pub = pick_keypair()

    # NOTE: these signatures are "recoverable" type, since the card doesn't need to make them
    b_sig = ec_sig_from_digest(b, sha256s(card_pubkey), EC_FLAG_ECDSA|EC_FLAG_RECOVERABLE)
    r_sig = ec_sig_from_digest(r, sha256s(b_pub), EC_FLAG_ECDSA|EC_FLAG_RECOVERABLE)

    global ROOT_PUBKEY
    assert not ROOT_PUBKEY
    ROOT_PUBKEY = bytes(r_pub)

    return [b_sig, r_sig]

def calc_xcvc(cmd, card_nonce, pubkey, privkey, cvc):
    # Calcuate session key and xcvc value need for auth'ed commands
    # - requires privkey from app and pubkey from card OR vice-versa
    assert 6 <= len(cvc) <= 32

    # standard ECDH
    session_key = wally_ecdh(pubkey, privkey)

    mask = xor_bytes(session_key, sha256s(card_nonce + cmd.encode('ascii')))[0:len(cvc)]
    xcvc = xor_bytes(cvc, mask)

    return session_key, xcvc

# Options we want for all commands
@click.group()
#@click.option('--debug', '-d', is_flag=True, help='More debugging')
@click.option('--quiet', '-q', is_flag=True, help='Less debugging')
@click.option('--testnet', '-t', is_flag=True, help='Operate on testnet3 rather than mainnet')
@click.option('--rng-seed', '-r', type=int, default=42, help='Seed value for (not) RNG', metavar="integer")
def main(testnet, rng_seed, debug=False, quiet=False):
    global DEBUG
    #DEBUG = debug
    DEBUG = not quiet

    global TESTNET
    TESTNET = testnet
    random.seed(rng_seed)


@main.command('emulate')
@click.option('--factory', '-f', is_flag=True, help='Has no key picked, needs factory setup')
@click.option('--tapsigner', '--ts', '-t', is_flag=True, help='Be a TAPSIGNER')
@click.option('--pipe', '-p', type=str, default='/tmp/ecard-pipe', help='Unix pipe for comms', metavar="PATH")
def emulate_card(pipe, factory=False, tapsigner=False):
    '''
        Emulate a card which is fresh from factory. Has no key picked.
    '''
    card = CardState()


    if not factory:
        card.cmd_certs(cert_chain=fake_cert_chain(card.card_pubkey))
        card.cmd_factory(birth=700001, cvc=b'123456', testnet=TESTNET,
                            aes_key=FIXED_AES_KEY,
                            url=NDEF_URL(tapsigner), tapsigner=tapsigner)
        card.cmd_new(chain_code=prandom(32), slot=0)

    print(card)

    card.emulate(pipe)

@main.command('satscard')
def sc_basic_test():
    '''
    Build a SATSCARD and do the basics with it.
    '''

    card = CardState()
    card.cmd_certs(cert_chain=fake_cert_chain(card.card_pubkey))
    card.cmd_factory(birth=700001, cvc=b'123456', testnet=TESTNET, url=NDEF_URL(0))
    card.cmd_new(chain_code=prandom(32), slot=0)

    #if DEBUG:
    print(card)
    st = card.cmd_status()
    print('status = ' + pformat(st))
    #hexdump(cbor2.dumps(st))
    card_pubkey = st['pubkey']

    my_nonce = prandom(USER_NONCE_SIZE)
    rr = card.cmd_read(my_nonce)
    print(f"read({B2A(my_nonce)}) = {pformat(rr)}")

    addr = recover_address(st, rr, my_nonce)
    print(f"CORRECTLY recovered addr: {addr}")

    certs = card.cmd_certs()
    print(f"certs() = {pformat(certs)}")

    st = card.cmd_status()      # for card_nonce and details
    my_nonce = prandom(USER_NONCE_SIZE)
    chk = card.cmd_check(my_nonce)
    print(f"cmd_check({B2A(my_nonce)}) = {pformat(chk)}")

    root_pubkey = verify_certs(st, chk, certs, my_nonce)

    global ROOT_PUBKEY
    assert ROOT_PUBKEY == root_pubkey
    print(f"Got correct root pubkey; cert chain works")

    # try unseal
    my_priv, my_pub = pick_keypair()
    ses_key, xcvc = calc_xcvc('unseal', chk['card_nonce'], card_pubkey, my_priv, b'123456')

    us = card.cmd_unseal(slot=0, epubkey=my_pub, xcvc=xcvc)
    print(f"cmd_unseal(...) = {pformat(us)}")
    assert us['slot'] == 0
    pk = xor_bytes(ses_key, us['privkey'])
    assert pk == card.slots[0].privkey
    print("Got correct privkey after unseal operation")

    # try pick
    ses_key, xcvc = calc_xcvc('new', us['card_nonce'], card_pubkey, my_priv, b'123456')
    resp = card.cmd_new(slot=1, epubkey=my_pub, xcvc=xcvc)

    st = card.cmd_status()
    my_nonce = prandom(USER_NONCE_SIZE)
    rr = card.cmd_read(my_nonce)
    chk_addr = recover_address(st, rr, my_nonce)

    print(f"New addr => {chk_addr}")

    resp = card.cmd_derive(nonce=my_nonce)
    got_addr2 = recover_master_pubkey(resp, rr['card_nonce'], my_nonce, testnet=TESTNET)
    assert got_addr2 == chk_addr

    ses_key, xcvc = calc_xcvc('unseal', rr['card_nonce'], card_pubkey, my_priv, b'123456')
    us = card.cmd_unseal(slot=1, epubkey=my_pub, xcvc=xcvc)

    cn = us['card_nonce']
    for idx in range(2):
        ses_key, xcvc = calc_xcvc('dump', cn, card_pubkey, my_priv, b'123456')
        dd = card.cmd_dump(slot=idx, epubkey=my_pub, xcvc=xcvc)
        cn = dd.pop('card_nonce')

        print(f"slot[{idx}] => {pformat(dd)}")
        #print(f"slot[{idx}] => {dd['addr']}")

@main.command('tapsigner')
def ts_basic_test():
    '''
    Build a TAPSIGNER card and do the basics with it.
    '''

    card = CardState()
    card.cmd_certs(cert_chain=fake_cert_chain(card.card_pubkey))
    card.cmd_factory(birth=700001, cvc=b'123456', testnet=TESTNET, url=NDEF_URL(1), 
                        aes_key=FIXED_AES_KEY, tapsigner=True)
    card.cmd_new(chain_code=prandom(32), slot=0)

    #if DEBUG:
    print(card)
    aes_key = FIXED_AES_KEY
    #print(f'AES key: ' + aes_key)
    st = card.cmd_status()
    print('status = ' + pformat(st))
    assert 'addr' not in st
    assert 'path' in st
    #hexdump(cbor2.dumps(st))
    card_pubkey = st['pubkey']
    my_priv, my_pub = pick_keypair()

    # do backup
    my_priv, my_pub = pick_keypair()
    ses_key, xcvc = calc_xcvc('backup', st['card_nonce'], card_pubkey, my_priv, b'123456')
    bk = card.cmd_backup(epubkey=my_pub, xcvc=xcvc)
    open('debug.aes', 'wb').write(bk['data'])
    dec = subprocess.check_output(f'openssl aes-128-ctr -iv 0 -K {aes_key.hex()} < debug.aes', shell=1)
    dec = cbor2.loads(dec)
    assert dec.keys() == { 'chain_code', 'path', 'privkey' }
    print(f"BACKUP works")

    certs = card.cmd_certs()
    #print(f"certs() = {pformat(certs)}")

    st = card.cmd_status()      # for card_nonce and details
    my_nonce = prandom(USER_NONCE_SIZE)
    chk = card.cmd_check(my_nonce)
    print(f"cmd_check({B2A(my_nonce)}) = {pformat(chk)}")

    root_pubkey = verify_certs(st, chk, certs, my_nonce)

    global ROOT_PUBKEY
    assert ROOT_PUBKEY == root_pubkey
    print(f"Got correct root pubkey; cert chain works")

    tpath = [HARD(123), HARD(0)]
    st = card.cmd_status()
    my_nonce = prandom(USER_NONCE_SIZE)
    ses_key, xcvc = calc_xcvc('derive', st['card_nonce'], card_pubkey, my_priv, b'123456')
    resp = card.cmd_derive(nonce=my_nonce, path=tpath, epubkey=my_pub, xcvc=xcvc)

    st = card.cmd_status()
    assert st['path'] == tpath

    ses_key, xcvc = calc_xcvc('change', st['card_nonce'], card_pubkey, my_priv, b'123456')
    new_cvc = xor_bytes(b'987654321', ses_key[0:9])
    resp = card.cmd_change(nonce=my_nonce, data=new_cvc, epubkey=my_pub, xcvc=xcvc)
    assert resp['success']

    # change back
    ses_key, xcvc = calc_xcvc('change', resp['card_nonce'], card_pubkey, my_priv, b'987654321')
    new_cvc = xor_bytes(b'123456', ses_key[0:6])
    resp = card.cmd_change(nonce=my_nonce, data=new_cvc, epubkey=my_pub, xcvc=xcvc)
    assert resp['success']

    print("change CVC works")



if __name__ == '__main__':
    main()

# EOF
