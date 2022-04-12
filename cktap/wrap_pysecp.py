import os
from typing import Tuple

from cktap.bip32 import PrvKeyNode, PubKeyNode
from pysecp256k1 import (
    ec_seckey_verify, ec_pubkey_create, ec_pubkey_serialize, ecdsa_verify, ecdsa_signature_parse_compact,
    ec_pubkey_parse, ecdsa_sign, ecdsa_signature_serialize_compact
)
from pysecp256k1.recovery import (
    ecdsa_sign_recoverable, ecdsa_recoverable_signature_serialize_compact, ecdsa_recover,
    ecdsa_recoverable_signature_parse_compact
)
from pysecp256k1.ecdh import ecdh


# almost no one (wally, cc) is using BIP137, mostly just compressed 31 and uncompressed 27
def header_from_rec_id(rec_id: int) -> bytes:
    # only compressed
    return bytes([31 + rec_id])


def rec_id_from_header(header: int) -> int:
    header_num = header & 0xFF
    if header_num >= 39:
        header_num -= 12
    elif header_num >= 35:
        header_num -= 8
    elif header_num >= 31:
        header_num -= 4
    rec_id = header_num - 27
    return rec_id


def CT_pick_keypair() -> Tuple[bytes, bytes]:
    # return (priv, pub)
    for _ in range(10):
        try:
            sk = secret_bytes = os.urandom(32)
            ec_seckey_verify(secret_bytes)
            pub = ec_pubkey_create(secret_bytes)
            pk = ec_pubkey_serialize(pub, compressed=True)
            return sk, pk
        except:
            continue
    else:
        raise RuntimeError("stuck rng?")


def CT_priv_to_pubkey(pk: bytes) -> bytes:
    # return compressed pubkey
    pub = ec_pubkey_create(pk)
    return ec_pubkey_serialize(pub, compressed=True)


def CT_sig_verify(pub, msg_digest, sig):
    # returns True or False
    assert len(sig) == 64
    _sig = ecdsa_signature_parse_compact(sig)
    _pk = ec_pubkey_parse(pub)
    return ecdsa_verify(_sig, _pk, msg_digest)


def CT_sig_to_pubkey(msg_digest, sig):
    # returns a pubkey (33 bytes)
    assert len(sig) == 65
    header, compact_sig = sig[0], sig[1:]
    rec_id = rec_id_from_header(header)
    _rec_sig = ecdsa_recoverable_signature_parse_compact(compact_sig, rec_id)
    _pub = ecdsa_recover(_rec_sig, msg_digest)
    return ec_pubkey_serialize(_pub, compressed=True)


def CT_ecdh(his_pubkey, my_privkey):
    # returns a 32-byte session key, which is sha256s(compressed point)
    _pub = ec_pubkey_parse(his_pubkey)
    return ecdh(my_privkey, _pub)


def CT_sign(privkey, msg_digest, recoverable=False):
    # returns 64-byte sig
    if recoverable:
        _rec_sig = ecdsa_sign_recoverable(privkey, msg_digest)
        compact_sig, rec_id = ecdsa_recoverable_signature_serialize_compact(_rec_sig)
        header = header_from_rec_id(rec_id)
        return header + compact_sig
    else:
        _sig = ecdsa_sign(privkey, msg_digest)
        return ecdsa_signature_serialize_compact(_sig)


def CT_bip32_derive(chain_code, master_priv_pub, subkey_path):
    if len(master_priv_pub) == 32:
        # it's actually a private key (from unsealed slot)
        master = PrvKeyNode(chain_code=chain_code, key=master_priv_pub)
    else:
        # load 'm'
        master = PubKeyNode(chain_code=chain_code, key=master_priv_pub)

    # derive m/0
    node = master.get_extended_pubkey_from_path(subkey_path)

    return node.public_key.sec()

