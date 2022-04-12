#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

import hmac
import ecdsa
import hashlib
from io import BytesIO
from typing import Union, List

from cktap.base58 import decode_base58_checksum, encode_base58_checksum


HARDENED = 2 ** 31

Prv_or_PubKeyNode = Union["PrvKeyNode", "PubKeyNode"]

SECP256k1 = ecdsa.curves.SECP256k1
CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER = CURVE_GEN.order()
FIELD_ORDER = SECP256k1.curve.p()
INFINITY = ecdsa.ellipticcurve.INFINITY
Point_or_PointJacobi = Union[
    ecdsa.ellipticcurve.Point,
    ecdsa.ellipticcurve.PointJacobi
]


def hash160(s: bytes) -> bytes:
    """
    sha256 followed by ripemd160

    :param s: data
    :return: hashed data
    """
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def big_endian_to_int(b: bytes) -> int:
    """
    Big endian representation to integer.

    :param b: big endian representation
    :return: integer
    """
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    """
    Represents integer in big endian byteorder.

    :param n: integer
    :param length: byte length
    :return: big endian
    """
    return n.to_bytes(length, "big")


class PrivateKey(object):

    __slots__ = (
        "sec_exp",
        "k",
        "K"
    )

    def __init__(self, sec_exp: int):
        """
        Initializes private key from secret exponent.

        :param sec_exp: secret
        """
        self.sec_exp = sec_exp
        self.k = ecdsa.SigningKey.from_secret_exponent(
            secexp=sec_exp,
            curve=SECP256k1
        )
        self.K = PublicKey(key=self.k.get_verifying_key())

    def __bytes__(self) -> bytes:
        """
        Encodes private key into corresponding byte sequence.

        :return: byte representation of PrivateKey object
        """
        return self.k.to_string()

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PrivateKey":
        """
        Initializes private key from byte sequence.

        :param key_bytes: byte representation of private key
        :return: private key
        """
        return cls(sec_exp=big_endian_to_int(key_bytes))


class PublicKey(object):

    __slots__ = (
        "K"
    )

    def __init__(self, key: ecdsa.VerifyingKey):
        """
        Initializes PublicKey object from ecdsa verifying key

        :param key: ecdsa verifying key
        """
        self.K = key

    @property
    def point(self) -> ecdsa.ellipticcurve.Point:
        """
        Point on curve (x and y coordinates).

        :return: point on curve
        """
        return self.K.pubkey.point

    def sec(self, compressed: bool = True) -> bytes:
        """
        Encodes public key to SEC format.

        :param compressed: whether to use compressed format (default=True)
        :return: SEC encoded public key
        """
        if compressed:
            return self.K.to_string(encoding="compressed")
        return self.K.to_string(encoding="uncompressed")

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PublicKey":
        """
        Initializes public key from byte sequence.

        :param key_bytes: byte representation of public key
        :return: public key
        """
        return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point: Point_or_PointJacobi) -> "PublicKey":
        """
        Initializes public key from point on elliptic curve.

        :param point: point on elliptic curve
        :return: public key
        """
        return cls(ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1))


class InvalidKeyError(Exception):
    """Raised when derived key is invalid"""


class PubKeyNode(object):

    mark: str = "M"
    testnet_version: int = 0x043587CF
    mainnet_version: int = 0x0488B21E

    __slots__ = (
        "parent",
        "key",
        "chain_code",
        "depth",
        "index",
        "parsed_parent_fingerprint",
        "parsed_version",
        "testnet",
        "children"
    )

    def __init__(self, key: bytes, chain_code: bytes, index: int = 0,
                 depth: int = 0, testnet: bool = False,
                 parent: Union["PubKeyNode", "PrvKeyNode"] = None,
                 parent_fingerprint: bytes = None):
        """
        Initializes Pub/PrvKeyNode.

        :param key: public or private key
        :param chain_code: chain code
        :param index: current node derivation index (default=0)
        :param depth: current node depth (default=0)
        :param testnet: whether this node is testnet node (default=False)
        :param parent: parent node of the current node (default=None)
        :param parent_fingerprint: fingerprint of parent node (default=None)
        """
        self.parent = parent
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parsed_parent_fingerprint = parent_fingerprint
        self.parsed_version = None
        self.testnet = testnet
        self.children = []

    def __eq__(self, other) -> bool:
        """
        Checks whether two private/public key nodes are equal.

        :param other: other private/public key node
        """
        if type(self) != type(other):
            return False
        self_key = big_endian_to_int(self.key)
        other_key = big_endian_to_int(other.key)
        return self_key == other_key and \
            self.chain_code == other.chain_code and \
            self.depth == other.depth and \
            self.index == other.index and \
            self.testnet == other.testnet and \
            self.parent_fingerprint == other.parent_fingerprint

    @property
    def public_key(self) -> PublicKey:
        """
        Public key node's public key.

        :return: public key of public key node
        """
        return PublicKey.parse(key_bytes=self.key)

    @property
    def parent_fingerprint(self) -> bytes:
        """
        Gets parent fingerprint.

        If node is parsed from extended key, only parsed parent fingerprint
        is available. If node is derived, parent fingerprint is calculated
        from parent node.

        :return: parent fingerprint
        """
        if self.parent:
            fingerprint = self.parent.fingerprint()
        else:
            fingerprint = self.parsed_parent_fingerprint
        # in case there is still None here - it is master
        return fingerprint or b"\x00\x00\x00\x00"

    @property
    def pub_version(self) -> int:
        """
        Decides which extended public key version integer to use
        based on testnet parameter.

        :return: extended public key version
        """
        if self.testnet:
            return PubKeyNode.testnet_version
        return PubKeyNode.mainnet_version

    def __repr__(self) -> str:
        if self.is_master() or self.is_root():
            return self.mark
        if self.is_hardened():
            index = str(self.index - 2**31) + "'"
        else:
            index = str(self.index)
        parent = str(self.parent) if self.parent else self.mark
        return parent + "/" + index

    def is_hardened(self) -> bool:
        """Check whether current key node is hardened."""
        return self.index >= 2**31

    def is_master(self) -> bool:
        """Check whether current key node is master node."""
        return self.depth == 0 and self.index == 0 and self.parent is None

    def is_root(self) -> bool:
        """Check whether current key node is root (has no parent)."""
        return self.parent is None

    def fingerprint(self) -> bytes:
        """
        Gets current node fingerprint.

        :return: first four bytes of SHA256(RIPEMD160(public key))
        """
        return hash160(self.public_key.sec())[:4]

    @classmethod
    def parse(cls, s: Union[str, bytes, BytesIO],
              testnet: bool = False) -> Prv_or_PubKeyNode:
        """
        Initializes private/public key node from serialized node or
        extended key.

        :param s: serialized node or extended key
        :param testnet: whether this node is testnet node
        :return: public/private key node
        """
        if isinstance(s, str):
            s = BytesIO(decode_base58_checksum(s=s))
        elif isinstance(s, bytes):
            s = BytesIO(s)
        elif isinstance(s, BytesIO):
            pass
        else:
            raise ValueError("has to be bytes, str or BytesIO")
        return cls._parse(s, testnet=testnet)

    @classmethod
    def _parse(cls, s: BytesIO, testnet: bool = False) -> Prv_or_PubKeyNode:
        """
        Initializes private/public key node from serialized node buffer.

        :param s: serialized node buffer
        :param testnet: whether this node is testnet node (default=False)
        :return: public/private key node
        """
        version = big_endian_to_int(s.read(4))
        depth = big_endian_to_int(s.read(1))
        parent_fingerprint = s.read(4)
        index = big_endian_to_int(s.read(4))
        chain_code = s.read(32)
        key_bytes = s.read(33)
        key = cls(
            key=key_bytes,
            chain_code=chain_code,
            index=index,
            depth=depth,
            testnet=testnet,
            parent_fingerprint=parent_fingerprint,
        )
        key.parsed_version = version
        return key

    def _serialize(self, key: bytes, version: int = None) -> bytes:
        """
        Serializes public/private key node to extended key format.

        :param version: extended public/private key version (default=None)
        :return: serialized extended public/private key node
        """
        # 4 byte: version bytes
        result = int_to_big_endian(version, 4)
        # 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys
        result += int_to_big_endian(self.depth, 1)
        # 4 bytes: the fingerprint of the parent key (0x00000000 if master key)
        if self.is_master():
            result += int_to_big_endian(0x00000000, 4)
        else:
            result += self.parent_fingerprint
        # 4 bytes: child number. This is ser32(i) for i in xi = xpar/i,
        # with xi the key being serialized. (0x00000000 if master key)
        result += int_to_big_endian(self.index, 4)
        # 32 bytes: the chain code
        result += self.chain_code
        # 33 bytes: the public key or private key data
        # (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        result += key
        return result

    def serialize_public(self, version: int = None) -> bytes:
        """
        Serializes public key node to extended key format.

        :param version: extended public key version (default=None)
        :return: serialized extended public key node
        """
        return self._serialize(
            version=self.pub_version if version is None else version,
            key=self.public_key.sec()
        )

    def extended_public_key(self, version: int = None) -> str:
        """
        Base58 encodes serialized public key node. If version is not
        provided (default) it is determined by result of self.pub_version.

        :param version: extended public key version (default=None)
        :return: extended public key
        """
        return encode_base58_checksum(self.serialize_public(version=version))

    def ckd(self, index: int) -> "PubKeyNode":
        """
        The function CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child
        extended public key from the parent extended public key.
        It is only defined for non-hardened child keys.

        * Check whether i ≥ 231 (whether the child is a hardened key).
        * If so (hardened child):
            return failure
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(Kpar) || ser32(i)).
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key Ki is point(parse256(IL)) + Kpar.
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or Ki is the point at infinity,
            the resulting key is invalid, and one should proceed with the next
             value for i.

        :param index: derivation index
        :return: derived child
        """
        if index >= HARDENED:
            raise RuntimeError("failure: hardened child for public ckd")
        I = hmac.new(key=self.chain_code, msg=self.key + int_to_big_endian(index, 4), digestmod=hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            InvalidKeyError(
                "public key {} is greater/equal to curve order".format(
                    big_endian_to_int(IL)
                )
            )
        point = PrivateKey.parse(IL).K.point + self.public_key.point
        if point == INFINITY:
            raise InvalidKeyError("public key is a point at infinity")
        Ki = PublicKey.from_point(point=point)
        child = self.__class__(
            key=Ki.sec(),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        self.children.append(child)
        return child

    def generate_children(self, interval: tuple = (0, 20)
                          ) -> List[Prv_or_PubKeyNode]:
        """
        Generates children of current node.

        :param interval: specific interval of integers
                        from which to generate children (default=(0, 20))
        :return: list of generated children
        """
        return [self.ckd(index=i) for i in range(*interval)]

    def get_extended_pubkey_from_path(self, index_list: List[int]) -> Prv_or_PubKeyNode:
        """
        Derives node from current node.

        :param index_list: specific index list (or index path) for derivation
        :return: derived node
        """
        node = self
        for i in index_list:
            node = node.ckd(index=i)
        return node


class PrvKeyNode(PubKeyNode):

    mark: str = "m"
    testnet_version: int = 0x04358394
    mainnet_version: int = 0x0488ADE4

    @property
    def private_key(self) -> PrivateKey:
        """
        Private key node's private key.

        :return: public key of private key node
        """
        return PrivateKey(sec_exp=big_endian_to_int(self.key))

    @property
    def public_key(self) -> PublicKey:
        """
        Private key node's public key.

        :return: public key of public key node
        """
        return self.private_key.K

    @property
    def prv_version(self) -> int:
        """
        Decides which extended private key version integer to use
        based on testnet parameter.

        :return: extended private key version
        """
        if self.testnet:
            return PrvKeyNode.testnet_version
        return PrvKeyNode.mainnet_version

    @classmethod
    def master_key(cls, bip39_seed: bytes, testnet=False) -> "PrvKeyNode":
        """
        Generates master private key node from bip39 seed.

        * Generate a seed byte sequence S (bip39_seed arg) of a chosen length
          (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
        * Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
        * Split I into two 32-byte sequences, IL and IR.
        * Use parse256(IL) as master secret key, and IR as master chain code.

        :param bip39_seed: bip39_seed
        :param testnet: whether this node is testnet node (default=False)
        :return: master private key node
        """
        I = hmac.new(key=b"Bitcoin seed", msg=bip39_seed, digestmod=hashlib.sha512).digest()
        # private key
        IL = I[:32]
        # In case IL is 0 or ≥ n, the master key is invalid
        int_left_key = big_endian_to_int(IL)
        if int_left_key == 0:
            raise InvalidKeyError("master key is zero")
        if int_left_key >= CURVE_ORDER:
            raise InvalidKeyError(
                "master key {} is greater/equal to curve order".format(
                    int_left_key
                )
            )
        # chain code
        IR = I[32:]
        return cls(
            key=IL,
            chain_code=IR,
            testnet=testnet
        )

    def serialize_private(self, version: int = None) -> bytes:
        """
        Serializes private key node to extended key format.

        :param version: extended private key version (default=None)
        :return: serialized extended private key node
        """
        return self._serialize(
            version=self.prv_version if version is None else version,
            key=b"\x00" + bytes(self.private_key)
        )

    def extended_private_key(self, version: int = None) -> str:
        """
        Base58 encodes serialized private key node. If version is not
        provided (default) it is determined by result of self.prv_version.

        :param version: extended private key version (default=None)
        :return: extended private key
        """
        return encode_base58_checksum(self.serialize_private(version=version))

    def ckd(self, index: int) -> "PrvKeyNode":
        """
        The function CKDpriv((kpar, cpar), i) → (ki, ci) computes
        a child extended private key from the parent extended private key:

        * Check whether i ≥ 2**31 (whether the child is a hardened key).
        * If so (hardened child):
            let I = HMAC-SHA512(Key=cpar, Data=0x00 || ser256(kpar) || ser32(i))
            (Note: The 0x00 pads the private key to make it 33 bytes long.)
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(point(kpar)) || ser32(i))
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key ki is parse256(IL) + kpar (mod n).
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
            and one should proceed with the next value for i.
            (Note: this has probability lower than 1 in 2**127.)

        :param index: derivation index
        :return: derived child
        """
        if index >= HARDENED:
            # hardened
            data = b"\x00"+bytes(self.private_key) + int_to_big_endian(index, 4)
        else:
            data = self.public_key.sec() + int_to_big_endian(index, 4)
        I = hmac.new(key=self.chain_code, msg=data, digestmod=hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            InvalidKeyError(
                "private key {} is greater/equal to curve order".format(
                    big_endian_to_int(IL)
                )
            )
        ki = (int.from_bytes(IL, "big") +
              big_endian_to_int(bytes(self.private_key))) % CURVE_ORDER
        if ki == 0:
            InvalidKeyError("private key is zero")
        child = self.__class__(
            key=int_to_big_endian(ki, 32),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        self.children.append(child)
        return child

