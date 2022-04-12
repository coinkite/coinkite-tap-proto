import hmac
import ecdsa
import hashlib
from typing import Tuple, List

from cktap.bip32 import PrvKeyNode, PubKeyNode


# Elliptic curve parameters (secp256k1)
P = 2 ** 256 - 2 ** 32 - 977  # P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 2**0
# = fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
# = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
#  = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
#  = 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = (Gx, Gy)

BASE256_CODE_STRING = ''.join([chr(x) for x in range(256)])


def encode_base256(val, minlen=0):
    minlen = int(minlen)
    code_string = BASE256_CODE_STRING
    result_bytes = bytearray()
    while val > 0:
        curcode = code_string[val % 256]
        result_bytes.insert(0, ord(curcode))
        val //= 256

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00'
    if (pad_size > 0):
        result_bytes = bytes(bytearray(padding_element * pad_size) + result_bytes)

    return result_bytes


def decode_base256(string):
    base = 256
    if base == 16:
        string = string.lower()
    result = 0
    while len(string) > 0:
        result *= base
        result += string[0]
        string = string[1:]
    return result


# Extended Euclidean Algorithm
def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def to_jacobian(p):
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p):
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M ** 2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)


def jacobian_add(p, q):
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)


def from_jacobian(p):
    z = inv(p[2], P)
    return ((p[0] * z ** 2) % P, (p[1] * z ** 3) % P)


def jacobian_multiply(a, n):
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n // 2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n // 2)), a)


def fast_multiply(a, n):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def fast_add(a, b):
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))


def get_pubkey_format(pub):
    if len(pub) == 65 and pub[0] == 4:
        return 'bin'
    elif len(pub) == 33 and pub[0] in [2, 3]:
        return 'bin_compressed'
    else:
        raise Exception("Pubkey not in recognized format")


def encode_pubkey(pub, formt):
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return b'\x04' + encode_base256(pub[0], 32) + encode_base256(pub[1], 32)
    elif formt == 'bin_compressed':
        return bytes([2 + (pub[1] % 2)]) + encode_base256(pub[0], 32)
    else:
        raise Exception("Invalid format!")


def decode_pubkey(pub, formt=None):
    """takes pubkey, detects type, returns tuple of (x, y)"""
    if not formt:
        formt = get_pubkey_format(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return decode_base256(pub[1:33]), decode_base256(pub[33:65])
    elif formt == 'bin_compressed':
        x = decode_base256(pub[1:33])
        beta = pow(int(x * x * x + A * x + B), int((P + 1) // 4), int(P))
        y = (P - beta) if ((beta + pub[0])) % 2 else beta
        return (x, y)
    else:
        raise Exception("Invalid format!")


def privkey_to_pubkey(privkey):
    privkey = decode_base256(privkey)
    if privkey >= N:
        raise Exception("Invalid privkey")
    return encode_pubkey(fast_multiply(G, privkey), "bin")


# EDCSA


def encode_sig(v, r, s) -> bytes:
    vb, rb, sb = bytes([v]), encode_base256(r, 32), encode_base256(s, 32)
    return vb + rb + sb


def decode_sig(sig: bytes):
    return sig[0], decode_base256(sig[1:33]), decode_base256(sig[33:])


# https://tools.ietf.org/html/rfc6979#section-3.2
def deterministic_generate_k(msghash, priv):
    hmac_sha256 = lambda k, s: hmac.new(k, s, hashlib.sha256)
    v = bytearray(b'\1' * 32)
    k = bytearray(32)  # b'\0' * 32
    msghash = encode_base256(decode_base256(msghash), 32)  # encode msg hash as 32 bytes
    k = hmac_sha256(k, v + b'\0' + priv + msghash).digest()
    v = hmac_sha256(k, v).digest()
    k = hmac_sha256(k, v + b'\1' + priv + msghash).digest()
    v = hmac_sha256(k, v).digest()
    res = hmac_sha256(k, v).digest()
    return decode_base256(res)


# MSG SIGNING

def ecdsa_raw_sign(msghash, priv):
    """sign msg hash (z) with privkey & RFC6979 (k);
    returns signature (v,r,s) with low s (BIP66) by default"""
    z = decode_base256(msghash)
    k = deterministic_generate_k(msghash, priv)

    r, y = fast_multiply(G, k)
    s = inv(k, N) * (z + r * decode_base256(priv)) % N

    is_compressed = True
    is_high_s = s * 2 > N

    v = 27 + ((y % 2) ^ (1 if is_high_s else 0))
    if is_compressed:
        v += 4  # 27 for uncompressed, 31 for compressed
    s = N - s if is_high_s else s
    return v, r, s


def ecdsa_sign(msg_digest, priv):
    """Sign a msg with privkey, returning base64 signature"""
    v, r, s = ecdsa_raw_sign(msg_digest, priv)
    sig = encode_sig(v, r, s)
    assert ecdsa_verify(msg_digest, sig, privkey_to_pubkey(priv)), \
        "Bad Sig!\t %s\nv,r,s = %d,\n%d\n%d" % (sig, v, r, s)
    return sig


def ecdsa_raw_verify(msghash, vrs, pub):
    """Verifies signature against pubkey for digest hash (msghash)"""
    v, r, s = vrs
    # if v is not None and (v not in xrange(27, 34+1)):     # fails for v = 0,1
    #     return False                                      # in ecdsa_tx_recover

    w = inv(s, N)
    z = decode_base256(msghash)

    u1, u2 = z * w % N, r * w % N
    pub = decode_pubkey(pub)
    x, y = fast_add(fast_multiply(G, u1), fast_multiply(pub, u2))
    return bool(r == x and ((r % N) != 0 and (s % N) != 0))


def ecdsa_verify(msg_digest, sig, pub):
    """Verify (base64) signature of a message using pubkey"""
    vrs = decode_sig(sig)
    return ecdsa_raw_verify(msg_digest, vrs, pub)


def ecdsa_raw_recover(msghash, vrs):
    """Recovers (x,y) point from msghash and sig values (v,r,s)"""
    v, r, s = vrs
    # if v not in (None, 0, 27, 28, 29, 30, 31, 32, 33, 34):
    #     raise ValueError("{0} must in range 27-34".format(v))
    x = r
    alpha = (x ** 3 + A * x + B) % P
    beta = pow(alpha, (P + 1) // 4, P)  # determine which
    y = beta if ((v % 2) ^ (beta % 2)) else (P - beta)  # y val from parity and v
    # If alpha isn't a quadratic residue, the sig is invalid
    # => r cannot be the x coord for a point on the curve
    if (alpha - y * y) % P != 0 or not (r % N) or not (s % N):
        raise Exception("Invalid signature!")
    z = decode_base256(msghash)
    Gz = jacobian_multiply((Gx, Gy, 1), (N - z) % N)
    XY = jacobian_multiply((x, y, 1), s)
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(r, N))
    Q = from_jacobian(Q)
    return Q


def ecdsa_recover(msg: bytes, sig: bytes):
    v, r, s = decode_sig(sig)
    Q = ecdsa_raw_recover(msg, (v, r, s))
    return encode_pubkey(Q, 'bin_compressed' if v >= 30 else 'bin')


# WRAP
def CT_pick_keypair() -> Tuple[bytes, bytes]:
    # return (priv[32], pub[33])
    pk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = pk.get_verifying_key()
    return pk.to_string(), vk.to_string("compressed")


def CT_priv_to_pubkey(pk: bytes) -> bytes:
    # return compressed pubkey 33bytes
    assert len(pk) == 32
    pk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    vk = pk.get_verifying_key()
    return vk.to_string("compressed")


def CT_sig_verify(pub: bytes, msg_digest: bytes, sig: bytes) -> bool:
    assert len(sig) == 64
    assert len(msg_digest) == 32
    vk = ecdsa.VerifyingKey.from_string(pub, curve=ecdsa.SECP256k1)
    return vk.verify_digest(sig, msg_digest)


def CT_sig_to_pubkey(msg_digest: bytes, sig: bytes) -> bytes:
    return ecdsa_recover(msg_digest, sig)


def CT_ecdh(his_pubkey: bytes, my_privkey: bytes) -> bytes:
    # returns a 32-byte session key, which is sha256s(compressed point)
    pk_other = ecdsa.VerifyingKey.from_string(his_pubkey, curve=ecdsa.SECP256k1)
    sk_our = ecdsa.SigningKey.from_string(my_privkey, curve=ecdsa.SECP256k1)
    result = (
        pk_other.pubkey.point
        * sk_our.privkey.secret_multiplier
    )
    secret_bytes = ecdsa.util.number_to_string(
        result.x(), sk_our.curve.curve.p()
    )
    assert result != ecdsa.ellipticcurve.INFINITY, "Invalid shared secret (INFINITY)."
    if result.y() % 2 == 0:
        prefix = b"\x02"
    else:
        prefix = b"\x03"
    res = prefix + secret_bytes
    return hashlib.sha256(res).digest()


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

    return node.public_key.sec()