#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Wrappers for choice of crypto libraries. AKA API Cleanup
#
# My standards:
# - pubkeys: 33 bytes, always compressed
# - private key: 32 bytes
# - signature: 64 bytes or 65 bytes if recoverable
# - no DER, no PEM, no other serializations
# - message digests (for sig/verify) are already digested
# - ECDSA verify returns bool, doesn't raise exception
# - tragically? these all are libsecp256k1 underneath
#

__all__ = [ 'sha256s', 'hash160', 
            'CT_ecdh', 'CT_sig_verify', 'CT_sig_to_pubkey', 'CT_sign',
            'CT_pick_keypair', 'CT_bip32_derive', 'CT_priv_to_pubkey']

# Fall-back code, might be overriden below.
#
def sha256s(msg):
    # single-shot SHA256
    from hashlib import sha256
    return sha256(msg).digest()

def hash160(x):
    # classic bitcoin nested hashes
    from .ripemd import RIPEMD160
    return RIPEMD160(sha256s(x)).digest()

# Other codes must be implemented elsewhere...
#

def CT_pick_keypair():
    # return (priv, pub)
    raise NotImplementedError

def CT_priv_to_pubkey(pk):
    # return compressed pubkey
    raise NotImplementedError

def CT_sig_verify(pub, msg_digest, sig):
    # returns True or False
    assert len(sig) == 64
    raise NotImplementedError

def CT_sig_to_pubkey(msg_digest, sig):
    # returns a pubkey (33 bytes)
    assert len(sig) == 65
    raise NotImplementedError

def CT_ecdh(his_pubkey, my_privkey):
    # returns a 32-byte session key, which is sha256s(compressed point)
    raise NotImplementedError

def CT_sign(privkey, msg_digest, recoverable=False):
    # returns 64-byte sig
    raise NotImplementedError

def CT_bip32_derive(chain_code, master_priv_pub, subkey_path):
    # return pubkey (33 bytes)
    raise NotImplementedError


try:
    from cktap.wrap_pysecp import CT_pick_keypair, CT_bip32_derive, CT_priv_to_pubkey
    from cktap.wrap_pysecp import CT_ecdh, CT_sig_verify, CT_sig_to_pubkey, CT_sign

except ImportError:
    try:
        # Wally Core <https://wally.readthedocs.io/en/release_0.8.3/crypto/>
        import wallycore

        from cktap.wrap_wally import hash160, sha256s
        from cktap.wrap_wally import CT_ecdh, CT_sig_verify, CT_sig_to_pubkey, CT_sign
        from cktap.wrap_wally import CT_pick_keypair, CT_bip32_derive, CT_priv_to_pubkey

    except ImportError:
        try:
            # Coincurve <https://ofek.dev/coincurve/api/>
            import coincurve

            from cktap.wrap_coincurve import CT_ecdh, CT_sig_verify, CT_sig_to_pubkey, CT_sign
            from cktap.wrap_coincurve import CT_pick_keypair, CT_bip32_derive, CT_priv_to_pubkey

        except ImportError:
            # python ECDSA
            try:
                from cktap.wrap_ecdsa import CT_ecdh, CT_sig_verify, CT_sig_to_pubkey, CT_sign
                from cktap.wrap_ecdsa import CT_pick_keypair, CT_bip32_derive, CT_priv_to_pubkey
            except ImportError:
                raise RuntimeError("need a crypto library")

# EOF
