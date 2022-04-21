#
# Compatibility wrapper for "wallycore".
#
# see <https://wally.readthedocs.io/en/release_0.8.3/crypto/>
#
# - using good serializations already, just very poor docs
#
from os import urandom

from wallycore import ec_sig_verify, ec_sig_to_public_key
from wallycore import ec_public_key_from_private_key
from wallycore import ec_sig_from_bytes as ec_sig_from_digest       # fix misnomer
from wallycore import ecdh as wally_ecdh                            # preference
from wallycore import EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE

# correct API already!
from wallycore import hash160                           # = ripemd160(sha256(x)) => 20 bytes
from wallycore import sha256 as sha256s

def CT_pick_keypair():
    for retry in range(10):
        priv = urandom(32)
        try:
            pub = ec_public_key_from_private_key(priv)
            return priv, pub
        except ValueError:
            continue
    else:
        raise RuntimeError("stuck rng?")

def CT_priv_to_pubkey(priv):
    return ec_public_key_from_private_key(priv)

def CT_sig_verify(pub, msg_digest, sig):
    assert len(sig) == 64
    try:
        ec_sig_verify(pub, msg_digest, EC_FLAG_ECDSA, sig)

        return True
    except ValueError:
        return False

def CT_sig_to_pubkey(msg_digest, sig):
    assert len(sig) == 65
    return bytes(ec_sig_to_public_key(msg_digest, sig))

def CT_ecdh(pubkey, privkey):
    return wally_ecdh(pubkey, privkey)

def CT_sign(privkey, msg_digest, recoverable=False):
    return ec_sig_from_digest(privkey, msg_digest, 
                EC_FLAG_ECDSA | (EC_FLAG_RECOVERABLE if recoverable else 0))

def CT_bip32_derive(chain_code, master_priv_pub, subkey_path):
    from wallycore import bip32_key_init, bip32_key_get_pub_key, bip32_key_from_parent
    from wallycore import BIP32_VER_MAIN_PUBLIC, BIP32_VER_MAIN_PRIVATE
    from wallycore import BIP32_FLAG_SKIP_HASH, BIP32_FLAG_KEY_PUBLIC, BIP32_FLAG_KEY_PRIVATE

    if len(master_priv_pub) == 32:
        m = bip32_key_init(BIP32_VER_MAIN_PRIVATE, 0, 0, chain_code,
            None, master_priv_pub, None, None)
        flag = BIP32_FLAG_KEY_PRIVATE
    else:
        m = bip32_key_init(BIP32_VER_MAIN_PUBLIC, 0, 0, chain_code,
            master_priv_pub, None, None, None)
        flag = BIP32_FLAG_KEY_PUBLIC

    node = m
    for sk in subkey_path:
        node = bip32_key_from_parent(node, sk, BIP32_FLAG_SKIP_HASH | flag)

    return bip32_key_get_pub_key(node)

# EOF
