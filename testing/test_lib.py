#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Tests. Best w/ a card with at least one unsealed slot. Does not modify state of card.
#
# NOTE: these are just cktap tests; we have much more complex test suite for the card.
#
import pytest
import os
from cktap.constants import *
from cktap.compat import *
from cktap.utils import xor_bytes, verify_derive_address, render_address, str2path
from cktap.verify_link import url_decoder

def test_wrap():
    # crypto lib wrappers need to function

    assert sha256s(b'abc') == \
            bytes.fromhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    assert hash160(b'abc') == \
            b'\xbb\x1b\xe9\x8c\x14$D\xd7\xa5j\xa3\x98\x1c9B\xa9x\xe4\xdc3'

    #'CT_ecdh', 'CT_sig_verify', 'CT_sig_to_public_key', 'CT_sign',
    #'CT_pick_keypair', 'CT_bip32_derive'

    pk, pub = CT_pick_keypair()
    assert CT_priv_to_pubkey(pk) == pub

    md = bytes(32)

    s1 = CT_sign(pk, md)
    assert len(s1) == 64
    assert CT_sig_verify(pub, md, s1)

    s2 = CT_sign(pk, md, recoverable=True)
    assert len(s2) == 65
    chk = CT_sig_to_pubkey(md, s2)
    assert chk == pub

    got = CT_bip32_derive(b'c'*32, b'\x02'*33, [1,2,3])
    assert got == b'\x03fo\xbb\xee\xc7\xb9hP\xa0\xa7\xff\xb7\x0c]\xf7\xec\xc4l\x9a\x89\x92\xd21\xcb\xb1{\x7f\xd9\xea\xff\xcb\x88'

    pk = b'c'*32
    pub = b'\x02'*33
    ss = CT_ecdh(pub, pk)
    assert ss == b'\x10L^\xf4iY\x01<\xc5*.jZ\xcc&\xb97\xf7\xcf\x91\x0f\r\x80O{\xf2x\xef\x1e\xb2\xd9\xed'


@pytest.mark.device
def test_addr(dev, known_cvc):
    # core functions
    pk = None
    if not dev.is_tapsigner:
        status = dev.get_status()
        cur_slot, num_slots = status["slots"]
        _, what, _ = dev.get_slot_usage(slot=cur_slot)
        if what in ("UNSEALED", "unused"):
            for i in range(0, num_slots):
                cur_slot_dump = dev.get_slot_usage(slot=i)
                if i == cur_slot and cur_slot_dump[1] != "unused":
                    pk, addr = dev.get_address(incl_pubkey=True, cvc=known_cvc, slot=i)
                elif i < cur_slot:
                    addr = dev.get_address(incl_pubkey=False, slot=i)
                else:
                    #unused
                    continue

                # can be None if unused slot
                assert addr[0:3] in { 'tb1', 'bc1' }
                a2 = dev.address(faster=True, slot=i)
                assert a2 == addr

                if not dev.tr.is_emulator:
                    dev.certificate_check(None if i == 9 else pk)
        else:
            pk, addr = dev.get_address(incl_pubkey=True, cvc=known_cvc, slot=cur_slot)
            # can be None if unused slot
            assert addr[0:3] in {'tb1', 'bc1'}
            a2 = dev.address(faster=True, slot=cur_slot)
            assert a2 == addr
            if not dev.tr.is_emulator:
                dev.certificate_check(None if cur_slot == 9 else pk)
    else:
        # tapsigner - cert check
        if not dev.tr.is_emulator:
            dev.certificate_check(None)


@pytest.mark.device
def test_status_fields(dev):
    st = dev.send('status')
    assert st.pop('proto') == 1

    # expect x.y.z format, decimal
    parts = st.pop('ver').split('.')
    assert len(parts) == 3
    assert all(len(p) in {1,2} for  p in parts)
    assert all(p.isdigit() for  p in parts), parts

    birth = st.pop('birth', 0)
    assert isinstance(birth, int)
    assert (700000 <= birth < 1000000)

    pk = st.pop('pubkey')
    assert len(pk) == 33

    nonce = st.pop('card_nonce')
    assert len(nonce) == CARD_NONCE_SIZE
    assert len(set(nonce)) > 3

    tn = st.pop('testnet', None)
    assert tn in { None, True }

    if st.pop('tapsigner', False):
        # TAPSIGNER
        assert 'slots' not in st
        if 'path' in st:
            assert isinstance(st.pop('path'), list)
        if 'num_backups' in st:
            assert 0 <= st.pop('num_backups') <= 127
        else:
            assert st.pop('satschip') == True
            assert dev.product_name == 'SATSCHIP'
    else:
        # SATSCARD
        slots = st.pop('slots')
        active, total = slots
        assert 0 <= active <= total
        assert total == NUM_SLOTS

        if 'addr' in st:
            addr = st.pop('addr')
            assert len(addr) == (ADDR_TRIM*2)+3
            assert '___' in addr
        else:
            # current slot unused (not sealed)
            pass

    assert len(st) == 0, f'Extra fields: {st}'

@pytest.mark.satscard
@pytest.mark.device


@pytest.mark.device
def test_set_derivation(dev, known_cvc):
    if not dev.is_tapsigner: raise pytest.skip("satscard")
    with pytest.raises(ValueError) as err:
        dev.set_derivation("m/84h/0h/0h/0h/0h/0h/0h/0h/0h", known_cvc)  # more than 8 components
    assert err.value.args[0] == 'No more than 8 path components allowed.'
    dev.set_derivation("m/84h/0h/0h/0h/0h/0h/0h/0h", known_cvc)  # exactly 8 components - must pass


@pytest.mark.device
def test_sign_digest(dev, known_cvc):
    if not dev.is_tapsigner:
        try:
            dev.unseal_slot(known_cvc)
        except:
            # was unsealed in previous run
            pass
    for _ in range(10):
        msg_digest = sha256s(sha256s(os.urandom(32)))
        sig = dev.sign_digest(cvc=known_cvc, slot=0, digest=msg_digest)
        assert len(sig) == 65

    if dev.is_tapsigner:
        for i in range(10):
            msg_digest = sha256s(sha256s(os.urandom(32)))
            sig = dev.sign_digest(cvc=known_cvc, slot=0, digest=msg_digest, subpath=f"{i}/{i+100}")
            assert len(sig) == 65
            sig = dev.sign_digest(cvc=known_cvc, slot=0, digest=msg_digest, fullpath=f"m/84'/1'/0'/{i}/{i+100}")
            assert len(sig) == 65

        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), subpath="0/0/0")
        assert err.value.args[0] == 'Length of subpath 0/0/0 is greater than 2'
        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), subpath="0/0h")
        assert err.value.args[0] == "subpath 0/0h contains hardened components"
        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), fullpath="m/84'/1'/0'/0/0/0")
        assert err.value.args[0] == 'Length of subpath 0/0/0 is greater than 2'
        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), fullpath="m/84'/1'/0'/0/0h")
        assert err.value.args[0] == "Hardened path component after non-hardened m/84h/1h/0h/0/0h"
    else:
        # SATSCARD does not support subpath
        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), subpath="0/0")
        assert err.value.args[0] == "Cannot use 'subpath/fullpath' option for SATSCARD"
        # SATSCARD does not support fullpath
        with pytest.raises(ValueError) as err:
            dev.sign_digest(cvc=known_cvc, slot=0, digest=sha256s(os.urandom(32)), fullpath="m/84'/1'/0'/0/0")
        assert err.value.args[0] == "Cannot use 'subpath/fullpath' option for SATSCARD"

    # digest len not equal to 32
    with pytest.raises(ValueError) as err:
        dev.sign_digest(cvc=known_cvc, slot=0, digest=os.urandom(33), subpath="0/0")
    assert err.value.args[0] == "Digest must be exactly 32 bytes"


@pytest.mark.satscard
@pytest.mark.device
def test_dump_unauth(dev):
    # all slots can be dumped w/o CVC but limited info
    if dev.is_tapsigner: raise pytest.skip("tapsigner")

    for slot in range(0, NUM_SLOTS):
        d = dev.send('dump', slot=slot)
        assert 'card_nonce' in d
        d.pop('card_nonce')
        assert d.pop('slot') == slot

        s = d.pop('sealed', None)
        if s == None:
            assert d.pop('used') == False
        elif s == False:
            assert s in {True, False}
            addr = d.pop('addr')
            assert '___' not in addr
        elif s == True:
            addr = d.pop('addr', None)
            if addr:
                assert '___' in addr
        else:
            raise ValueError(s)

        assert not d.keys(), repr(d)


@pytest.mark.satscard
@pytest.mark.device
def test_dump_unsealed(dev, known_cvc):
    # dump details of all unsealed slots 
    if dev.is_tapsigner: raise pytest.skip("tapsigner")

    st = dev.send('status')
    testnet = st.get('testnet', False)
    if st.pop('tapsigner', False): raise pytest.skip("tapsigner")
    active, num_slots = st['slots']
    if active == 0:
        raise pytest.skip("no unsealed slots yet")

    got_pk = set()
    got_mpk = set()
    for slot in range(0, active):
        sk, d = dev.send_auth('dump', known_cvc, slot=slot)

        assert set(d) == { 'slot', 'privkey', 'master_pk', 'chain_code', 'card_nonce', 'pubkey'}
        assert d['slot'] == slot
        assert len(d['master_pk']) == 32
        assert len(d['chain_code']) == 32 
    
        privkey = xor_bytes(d['privkey'], sk)
        assert privkey not in got_pk
        got_pk.add(privkey)

        master_pk = xor_bytes(d['master_pk'], sk)
        assert master_pk not in got_mpk
        got_mpk.add(master_pk)

        # fully check derivation
        derived_addr, derived_pubkey = verify_derive_address(d['chain_code'], master_pk, testnet=testnet)

        # critical: does the privkey match?
        actual = CT_priv_to_pubkey(privkey)
        assert derived_pubkey == actual
        assert actual == d['pubkey']
        assert render_address(actual, st.get('testnet', False)) == derived_addr


@pytest.mark.satscard
@pytest.mark.device
def test_get_privkey(dev, known_cvc):
    if dev.is_tapsigner: raise pytest.skip("tapsigner")
    
    count = 0
    for slot in range(0, dev.active_slot):
        pk = dev.get_privkey(known_cvc, slot)
        assert len(pk) == 32
        assert len(set(pk)) >= 6

        addr = dev.address(slot=slot, faster=True)
        assert addr == render_address(pk, dev.is_testnet)
        count += 1

    if not count:
        raise pytest.xfail("no unsealed slots")


@pytest.mark.device
def test_derive_xpub_at_path(dev, known_cvc):
    if not dev.is_tapsigner:
        raise pytest.skip("satscard")
    to_derive_success = [
        "m/84'/1'/0'",
        "m/84'/0'/0'",
        "m/84'/0'/0'/0/0",
        "m/84'/1'/0'/1/0",
        "m/84'/1'/0'/1000/0",
        "m/84'/1'/0'/9999/9999/999/9999",
    ]
    for path in to_derive_success:
        dev.derive_xpub_at_path(known_cvc, fullpath=path)
    to_derive_fail = [
        "m/84'/0'/0'/0/0'",
        "m/84'/1'/0'/1/{}".format(2**31),
    ]
    for path in to_derive_fail:
        with pytest.raises(ValueError):
            dev.derive_xpub_at_path(known_cvc, fullpath=path)

@pytest.mark.satscard
@pytest.mark.device
def test_get_usage_1(dev, known_cvc):
    if dev.is_tapsigner: raise pytest.skip("tapsigner")
    for slot in range(NUM_SLOTS):
        (a, st, d) = dev.get_slot_usage(slot, known_cvc)
        assert st in { 'UNSEALED', 'unused', 'sealed' }


@pytest.mark.satscard
@pytest.mark.device
def test_get_usage_2(dev):
    if dev.is_tapsigner: raise pytest.skip("tapsigner")
    for slot in range(NUM_SLOTS):
        (a, st, d) = dev.get_slot_usage(slot)
        assert st in { 'UNSEALED', 'unused', 'sealed' }

@pytest.mark.device
def test_url_from_card(dev):
    history = set()
    for n in range(10):
        prefix, frag = dev.get_nfc_url().split('#')
        assert frag not in history, 'dup nonce?!'
        history.add(frag)

        r = url_decoder(frag)
        assert ('state' in r) or ('virgin' in r)
        assert 'nonce' in r
        assert r.get('is_tapsigner') == dev.is_tapsigner
        if r.get('addr'):
            exp = dev.address(slot=r['slot_num'], faster=True)
            assert exp == r.get('addr')
        if dev.is_tapsigner:
            assert dev.card_ident == r.get('card_ident')

def test_url_decoder_sc():
    frag = 'u=U&o=1&r=mc0gk3l2&n=3efca6c545903a9a&s=a4020efe154842e6f97a363c08463c097da9edc6c5f2e909d4ec4a6605d99b8f3fa44fa9eed5768d562de2f21c85aab6c4b327519ab44c454eb80c6da14e34ec'
    r = url_decoder(frag)
    assert r['addr'] == 'tb1qh36pafmmawe337kn5c2a2wzanfpww3mc0gk3l2'
    assert r['nonce'] == '3efca6c545903a9a'
    assert r['state'] == 'UNSEALED'
    assert r['slot_num'] == 1
    assert r['is_tapsigner'] == False

def test_url_decoder_ts():
    frag = 't=1&u=U&c=2c6923818eed775b&n=419a154c57b6f5ab&s=6c9735bc0f9ff2450bb564e2f1bf635789ac303319492f849e0b1978655e1a307efa50205e9c152618d5f75ee36f58b499c09e4ae2237ce3dcb18a664fe6cf16'
    r = url_decoder(frag)
    assert r['card_ident'] == 'BU5HI-HTBCS-KLLZX-552ZO'
    assert r['is_tapsigner'] == True
    assert r['nonce'] == '419a154c57b6f5ab'
    assert r['virgin'] == True
    assert r['tampered'] == False

def test_nonce_quality():
    from cktap.utils import pick_nonce

    for i in range(1_000_000):
        n = pick_nonce()
        assert len(n) == USER_NONCE_SIZE
        assert len(set(n)) >= 2

# EOF
