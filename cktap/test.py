#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Quick tests
#
from compat import *

def test_wrap():
    assert sha256s(b'abc') == \
            bytes.fromhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    assert hash160(b'abc') == \
            b'\xbb\x1b\xe9\x8c\x14$D\xd7\xa5j\xa3\x98\x1c9B\xa9x\xe4\xdc3'

    #'CT_ecdh', 'CT_sig_verify', 'CT_sig_to_public_key', 'CT_sign',
    #'CT_pick_keypair', 'CT_bip32_derive'

    pk, pub = CT_pick_keypair()
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

    

def test_connection():
    from transport import CKTapCard
    a = CKTapCard()
    print("addr: " + a.address())

if __name__ == '__main__':
    test_wrap()
    test_connection()

# EOF
