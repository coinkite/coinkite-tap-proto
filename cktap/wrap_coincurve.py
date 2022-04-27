#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
#
# Compatibility wrapper for "coincurve".
#
# nice docs: <https://ofek.dev/coincurve/api/>
#
# - generally using terribile serializations for signatures (DER)
# - docs do not make it clear what serialization is needed
#
from coincurve.ecdsa import deserialize_compact, serialize_compact, der_to_cdata, cdata_to_der
from coincurve import PrivateKey, PublicKey
from cktap.bip32 import PrvKeyNode, PubKeyNode

def CT_sig_verify(pub, msg_digest, sig):
    assert len(sig) == 64
    der = cdata_to_der(deserialize_compact(sig))
    return PublicKey(pub).verify(der, msg_digest, hasher=None)

def CT_sig_to_pubkey(msg_digest, sig):
    assert len(sig) == 65
    rec_id = sig[0]
    # from BIP-137
    if 31 <= rec_id <= 34:
        rec_id -= 31        # P2PKH compressed (most compatible)
    elif 39 <= rec_id <= 42:
        rec_id -= 39        # P2WPKH (most correct for this project)
    else:
        raise ValueError(f'See BIP-137 for recid encoding, saw: {rec_id}')

    sig2 = sig[1:] + bytes([rec_id])
    nxt = PublicKey.from_signature_and_message(sig2, msg_digest, hasher=None)
    return nxt.format()

def CT_ecdh(pubkey, privkey):
    return PrivateKey(privkey).ecdh(pubkey)

def CT_pick_keypair():
    # Choose pub/private pair, return private key (32 bytes) and compressed pubkey
    pk = PrivateKey()
    return pk.secret, PublicKey.from_secret(pk.secret).format()

def CT_sign(privkey, msg_digest, recoverable=False):
    pk = PrivateKey(privkey)
    if recoverable:
        # provides rec_id at end?
        sig = pk.sign_recoverable(msg_digest, hasher=None)
        bip137 = sig[-1] + 31
        return bytes([bip137]) + sig[0:64]
    else:
        der = pk.sign(msg_digest, hasher=None)
        return serialize_compact(der_to_cdata(der))

def CT_priv_to_pubkey(priv):
    pk = PrivateKey(priv)
    return pk.public_key.format()

def CT_bip32_derive(chain_code, master_priv_pub, subkey_path):
    if len(master_priv_pub) == 32:
        # it's actually a private key (from unsealed slot)
        master = PrvKeyNode(chain_code=chain_code, key=master_priv_pub)
    else:
        # load 'm'
        master = PubKeyNode(chain_code=chain_code, key=master_priv_pub)

    # derive m/0
    node = master.get_extended_pubkey_from_path(subkey_path)

    return node.sec()

# EOF
