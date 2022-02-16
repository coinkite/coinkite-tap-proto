#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import os
from .compat import sha256s
from .compat import CT_sig_to_pubkey
from .utils import card_pubkey_to_ident, render_address


def all_keys(sig, md):
    # generates all possible pubkeys from sig + digest
    for rec_id in range(4):
        # see BIP-137 for magic value "39"... perhaps not well supported tho
        try:
            yield CT_sig_to_pubkey(md, bytes([39 + rec_id]) + sig)
        except ValueError:
            if rec_id >= 2: continue        # because crypto I don't understand
            raise

def url_decoder(fragment):
    # Takes the URL (after the # part) and verifies it
    # and returns dict of useful values, or raise on errors/frauds
    from urllib.parse import parse_qsl

    assert '#' not in fragment
    assert '?' not in fragment

    msg = fragment[0:fragment.rfind('=')+1]
    try:
        raw = dict(parse_qsl(fragment, strict_parsing=True))
    except:
        raise RuntimeError("Badly formated link")

    try:
        nonce = bytes.fromhex(raw['n'])
        is_tapsigner = bool(raw.get('t', False))
        assert len(nonce) == 8
        slot_num = int(raw.get('o', -1))
        addr = raw.get('r', None)
        sig = bytes.fromhex(raw['s'])
        assert len(sig) == 64
        card_ident = raw.get('c', None)
    except KeyError as exc:
        raise RuntimeError("Required field missing")

    md = sha256s(msg.encode('ascii'))

    if is_tapsigner:
        assert card_ident, 'missing card ident value'
        card_ident = bytes.fromhex(card_ident)
        full_card_ident = None

        for pubkey in all_keys(sig, md):
            expect = sha256s(pubkey)
            if expect[0:8] == card_ident:
                full_card_ident = card_pubkey_to_ident(pubkey)
                break

        if not full_card_ident:
            raise RuntimeError("Could not reconstruct card ident.")

        return dict(nonce=nonce.hex(),
                    card_ident=full_card_ident,
                    virgin=(raw['u'] == 'U'),
                    is_tapsigner=True, tampered=(raw['u'] == 'E'))

    else:
        # SATSCARD
        confirmed_addr = None
        is_testnet = False
        state = dict(S='Sealed', U='UNSEALED', E='Error/Tampered').get(raw['u'], 'Unknown state')

        for pubkey in all_keys(sig, md):
            if addr is not None:
                got = render_address(pubkey, False)
                if got.endswith(addr):
                    confirmed_addr = got
                    break

                got = render_address(pubkey, True)
                if got.endswith(addr):
                    confirmed_addr = got
                    is_testnet = True
                    break

        if addr and not confirmed_addr:
            raise RuntimeError("Could not reconstruct full payment address.")

        rv = dict(state=state, addr=confirmed_addr, nonce=nonce.hex(),
                    is_tapsigner=False,
                    slot_num=slot_num,
                    sealed=(raw['u'] == 'S'),
                    tampered=(raw['u'] == 'E'))

        if is_testnet:
            rv['testnet'] = True

        return rv


