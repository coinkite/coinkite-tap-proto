#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import os
from typing import Tuple, List

from cktap._ecdsa import privkey_to_pubkey, ecdsa_verify, ecdsa_recover, ecdsa_sign, ecdh
from cktap.bip32 import PrvKeyNode, PubKeyNode

# WRAP
def CT_pick_keypair() -> Tuple[bytes, bytes]:
    # return (priv[32], pub[33])
    for _ in range(10):
        try:
            privkey = os.urandom(32)
            pubkey = privkey_to_pubkey(privkey)
            return privkey, pubkey
        except ValueError:
            continue
    raise RuntimeError("PRNG issues?")


def CT_priv_to_pubkey(pk: bytes) -> bytes:
    # return compressed pubkey 33bytes
    assert len(pk) == 32
    return privkey_to_pubkey(pk)


def CT_sig_verify(pub: bytes, msg_digest: bytes, sig: bytes) -> bool:
    assert len(sig) == 64
    assert len(msg_digest) == 32
    # 0 byte is ignored firther in verification - needed for proper decoding
    return ecdsa_verify(msg_digest, b"\x00" + sig, pub)


def CT_sig_to_pubkey(msg_digest: bytes, sig: bytes) -> bytes:
    return ecdsa_recover(msg_digest, sig)


def CT_ecdh(his_pubkey: bytes, my_privkey: bytes) -> bytes:
    # returns a 32-byte session key, which is sha256s(compressed point)
    return ecdh(his_pubkey, my_privkey)


def CT_sign(privkey: bytes, msg_digest: bytes, recoverable: bool = False) -> bytes:
    if recoverable:
        return ecdsa_sign(msg_digest, privkey)
    else:
        sig = ecdsa_sign(msg_digest, privkey)
        assert len(sig) == 65
        # remove header byte
        return sig[1:]


def CT_bip32_derive(chain_code: bytes, master_priv_pub: bytes, subkey_path: List[int]) -> bytes:
    if len(master_priv_pub) == 32:
        # it's actually a private key (from unsealed slot)
        master = PrvKeyNode(chain_code=chain_code, key=master_priv_pub)
    else:
        # load 'm'
        master = PubKeyNode(chain_code=chain_code, key=master_priv_pub)

    # derive m/0
    node = master.get_extended_pubkey_from_path(subkey_path)

    return node.sec()