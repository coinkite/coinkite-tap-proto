# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import os, base58, bech32, struct
from binascii import b2a_hex, a2b_hex
from .constants import *
from .compat import hash160, sha256s
from .compat import CT_ecdh, CT_sig_verify, CT_sig_to_pubkey, CT_pick_keypair
from .compat import CT_bip32_derive, CT_priv_to_pubkey
from cktap.descriptors import descsum_create

# show bytes as hex in a string
B2A = lambda x: b2a_hex(x).decode('ascii')

def xor_bytes(a, b): # XOR the bytes of A and B
    assert len(a) == len(b)
    return bytes(i^j for i,j in zip(a,b))

def pick_nonce():
    # pick a nonce for our side
    # - must always be a "non trival" value or else card will reject
    for retry in range(3):
        rv = os.urandom(USER_NONCE_SIZE)
        if rv[0] != rv[-1] or len(set(rv)) >= 2:
            return rv

    raise RuntimeError("stuck RNG?")

# Serialization/deserialization tools
# - need this for text msg signing
def ser_compact_size(l):
    if l < 253:
        return struct.pack("B", l)
    elif l < 0x10000:
        return struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        return struct.pack("<BI", 254, l)
    else:
        return struct.pack("<BQ", 255, l)


# high bit set in LE32 indicating hardened BIP-32 path component
HARDENED = 0x8000_0000

def path_component_in_range(num: int) -> bool:
    # cannot be less than 0
    # cannot be more than (2 ** 31) - 1
    if 0 <= num < HARDENED:
        return True
    return False

def path2str(path):
    # take numeric path (list of numbers) and convert to human form
    # - standardizing on "m/84h" style
    return '/'.join(['m'] + [str(i & ~HARDENED)+('h' if i&HARDENED else '') for i in path])

def str2path(path):
    # normalize notation and return numbers, no error checking
    rv = []

    for i in path.split('/'):
        if i == 'm':
            continue
        if not i:
            # trailing or duplicated slashes
            continue

        if i[-1] in "'phHP":
            if len(i) < 2:
                raise ValueError(f"Malformed bip32 path component: {i}")
            num = int(i[:-1], 0)
            if not path_component_in_range(num):
                raise ValueError(f"Hardened path component out of range: {i}")
            here = num | HARDENED
        else:
            here = int(i, 0)
            if not path_component_in_range(here):
                # cannot be less than 0
                # cannot be more than (2 ** 31) - 1
                raise ValueError(f"Non-hardened path component out of range: {i}")

        rv.append(here)

    return rv

# predicates for numeric paths. stop giggling
all_hardened = lambda path: all(bool(i & HARDENED) for i in path)
none_hardened = lambda path: not any(bool(i & HARDENED) for i in path)


def card_pubkey_to_ident(card_pubkey):
    # convert pubkey into a hash formated for humans
    # - sha256(compressed-pubkey)
    # - skip first 8 bytes of that (because that's revealed in NFC URL)
    # - base32 and take first 20 chars in 4 groups of five
    # - insert dashes
    # - result is 23 chars long
    from base64 import b32encode
    assert len(card_pubkey) == 33, 'expecting compressed pubkey'

    md = b32encode(sha256s(card_pubkey)[8:]).decode('ascii')

    return '-'.join(md[pos:pos+5] for pos in range(0, 20, 5))

def verify_certs(status_resp, check_resp, certs_resp, my_nonce):
    # Verify the certificate chain works, returns label for pubkey recovered from signatures.
    # - raises on any verification issue
    #
    signatures = certs_resp['cert_chain']
    assert len(signatures) >= 2

    r = status_resp
    msg = b'OPENDIME' + r['card_nonce'] + my_nonce
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE
    pubkey = r['pubkey']

    # check card can sign with indicated key
    ok = CT_sig_verify(pubkey, sha256s(msg), check_resp['auth_sig'])
    if not ok:
        raise RuntimeError("bad sig in verify_certs")

    # follow certificate chain to factory root
    for sig in signatures:
        pubkey = CT_sig_to_pubkey(sha256s(pubkey), sig)

    if pubkey not in FACTORY_ROOT_KEYS:
        # fraudulent device
        raise RuntimeError("Root cert is not from Coinkite. Card is counterfeit.")

    return FACTORY_ROOT_KEYS[pubkey]

def recover_pubkey(status_resp, read_resp, my_nonce, ses_key):
    # [TS] Given the response from "status" and "read" commands,
    # and the nonce we gave for read command, and session key ... reconstruct
    # the card's current pubkey.
    assert status_resp.get('tapsigner', False)

    msg = b'OPENDIME' + status_resp['card_nonce'] + my_nonce + bytes([0])
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1

    # have to decrypt pubkey
    pubkey = read_resp['pubkey']
    pubkey = pubkey[0:1] + xor_bytes(pubkey[1:], ses_key)

    # Critical: proves card knows key
    ok = CT_sig_verify(pubkey, sha256s(msg), read_resp['sig'])
    if not ok:
        raise RuntimeError("Bad sig in recover_pubkey")

    return pubkey

def recover_address(status_resp, read_resp, my_nonce):
    # [SC] Given the response from "status" and "read" commands, and the
    # nonce we gave for read command, reconstruct the card's verified payment
    # address. Check prefix/suffix match what's expected
    assert not status_resp.get('tapsigner', False)

    sl = status_resp['slots'][0]
    msg = b'OPENDIME' + status_resp['card_nonce'] + my_nonce + bytes([sl])
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1

    pubkey = read_resp['pubkey']

    # Critical: proves card knows key
    ok = CT_sig_verify(pubkey, sha256s(msg), read_resp['sig'])
    if not ok:
        raise RuntimeError("Bad sig in recover_address")

    expect = status_resp['addr']
    left = expect[0:expect.find('_')]
    right = expect[expect.rfind('_')+1:]

    # Critical: counterfieting check
    addr = render_address(pubkey, status_resp.get('testnet', False))
    if not (addr.startswith(left)
                and addr.endswith(right)
                and len(left) == len(right) == ADDR_TRIM):
        raise RuntimeError("Corrupt response")

    return pubkey, addr

def force_bytes(foo):
    # convert strings to bytes where needed
    return foo.encode('ascii') if isinstance(foo, str) else foo

def calc_xcvc(cmd, card_nonce, his_pubkey, cvc):
    # Calcuate session key and xcvc value need for auth'ed commands
    # - also picks an arbitrary keypair for my side of the ECDH?
    # - requires pubkey from card and proposed CVC value
    assert 6 <= len(cvc) <= 32

    cvc = force_bytes(cvc)

    # fresh new ephemeral key for our side of connection
    my_privkey, my_pubkey = CT_pick_keypair()

    # standard ECDH
    # - result is sha256s(compressed shared point (33 bytes))
    session_key = CT_ecdh(his_pubkey, my_privkey)

    md = sha256s(card_nonce + cmd.encode('ascii'))
    mask = xor_bytes(session_key, md)[0:len(cvc)]
    xcvc = xor_bytes(cvc, mask)

    return session_key, dict(epubkey=my_pubkey, xcvc=xcvc)

def render_address(pubkey, testnet=False):
    # make the text string used as a payment address

    if len(pubkey) == 32:
        # actually a private key, convert
        pubkey = CT_priv_to_pubkey(pubkey)

    HRP = 'bc' if not testnet else 'tb'
    return bech32.encode(HRP, 0, hash160(pubkey))

def render_wif(privkey, bip_178=False, electrum=False, testnet=False):
    # Show the WIF in useful text format (base58)
    # - we are always trying to do bech32/segwit but hard to communicate that
    # - BIP-178 not accepted by community nor Core
    # - electrum adds a prefix for humans (decent idea)
    # - Core 22.0 does not seem to support bech32 import (assumes legacy or does all, IDK)
    assert len(privkey) == 32
    assert (bip_178 or electrum) or not any([bip_178, electrum])

    prefix = bytes([0x80 if not testnet else 0xef])
    suffix = bytes([0x01 if not bip_178 else 0x11])

    rv = base58.b58encode_check(prefix + privkey + suffix).decode('ascii')

    return ('p2wpkh:' + rv) if electrum else rv

def render_descriptor(address=None, privkey=None, bip_178=False, electrum=False, testnet=False, checksum=True):
    # Create a "descriptor" for Core to understand.
    assert address or privkey
    if privkey:
        rv = 'wpkh(%s)' % render_wif(privkey, testnet=testnet)
    else:
        rv = 'addr(%s)' % address
    if checksum:
        return descsum_create(rv)
    return rv

def verify_master_pubkey(pub, sig, chain_code, my_nonce, card_nonce):
    # using signature response from 'deriv' command, recover the master pubkey
    # for this slot
    msg = b'OPENDIME' + card_nonce + my_nonce + chain_code
    assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 32

    ok = CT_sig_verify(pub, sha256s(msg), sig)
    if not ok:
        raise RuntimeError("bad sig in verify_master_pubkey")

    return pub

def verify_derive_address(chain_code, master_pub, testnet=False):
    # re-derive the address we should expect
    # - this is "m/0" in BIP-32 nomenclature
    # - accepts master public key (before unseal) or master private key (after)
    pubkey = CT_bip32_derive(chain_code, master_pub, [0])

    return render_address(pubkey, testnet=testnet), pubkey


def make_recoverable_sig(digest, sig, addr=None, expect_pubkey=None, is_testnet=False):
    # The card will only make non-recoverable signatures (64 bytes)
    # but we usually know the address which should be implied by
    # the signature's pubkey, so we can try all values and discover
    # the correct "rec_id" 
    assert len(digest) == 32
    assert len(sig) == 64

    for rec_id in range(4):
        # see BIP-137 for magic value "39"... perhaps not well supported tho
        try:
            rec_sig = bytes([39 + rec_id]) + sig
            pubkey = CT_sig_to_pubkey(digest, rec_sig)
        except ValueError:
            if rec_id >= 2: continue        # because crypto I don't understand
    
        if expect_pubkey:
            if expect_pubkey != pubkey:
                continue
        if addr:
            got = render_address(pubkey, is_testnet)
            if got.endswith(addr):
                return rec_sig
        else:
            return rec_sig

    # failed to recover right pubkey value
    raise ValueError("sig may not be created by that address/pubkey??")

    
def render_sats_value(c, u):
    # string value for humans: making this hard to parse on purpose
    if not c and not u:
        return '-zero-'
    elif not u:
        return f'{c:,} sats'
    elif c:
        return f'{c:,} sats (+{u:,} soon)'
    else:
        return f'-zero- (+{u:,} soon)'



# EOF
