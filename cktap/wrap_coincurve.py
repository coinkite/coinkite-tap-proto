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

def CT_sig_verify(pub, msg_digest, sig):
    # XXX need some compact->der here
    assert len(sig) == 64
    der = cdata_to_der(deserialize_compact(sig))
    return PublicKey(pub).verify(der, msg_digest, hasher=None)

def CT_sig_to_pubkey(msg_digest, sig):
    # XXX need some recoverable compact->der here
    assert len(sig) == 65
    nxt = PublicKey.from_signature_and_message(sig, msg_digest, hasher=None)
    return nxt.format()

def CT_ecdh(pubkey, privkey):
    return PrivateKey(privkey).ecdh(his_pubkey)

def CT_pick_keypair():
    # Choose pub/private pair, return private key (32 bytes) and compressed pubkey
    pk = PrivateKey()
    return pk.secret, PublicKey.from_secret(pk.secret).format()

def CT_sign(privkey, msg_digest, recoverable=False):
    pk = PrivateKey(privkey)
    if recoverable:
        return pk.sign_recoverable(msg_digest, hasher=None)
    else:
        der = pk.sign(msg_digest, hasher=None)
        return serialize_compact(der_to_cdata(der))


def CT_bip32_derive(chain_code, master_priv_pub, subkey_path):
    from bip32 import BIP32

    if len(master_priv_pub) == 32:
        # it's actually a private key (from unsealed slot)
        master = BIP32(chaincode=chain_code, privkey=master_priv_pub)
    else:
        # load 'm'
        master = BIP32(chaincode=chain_code, pubkey=master_priv_pub)

    # derive m/0
    _, pubkey = master.get_extended_pubkey_from_path(subkey_path)

    return pubkey

# EOF
