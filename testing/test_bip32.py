import pytest
from io import BytesIO

from cktap.base58 import decode_base58_checksum
from cktap.bip32 import PrvKeyNode, PubKeyNode, PrivateKey, PublicKey



def test_parse():
    xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    xpriv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    pub_node = PubKeyNode.parse(s=xpub)
    assert pub_node.extended_public_key() == xpub
    assert PrvKeyNode.parse(s=xpriv).extended_private_key() == xpriv

def test_parse_incorrect_type():
    xpriv = "xprv9s21ZrQH143K3YFDmG48xQj4BKHUn15if4xsQiMwSKX8bZ6YruYK6mV6oM5Tbodv1pLF7GMdPGaTcZBno3ZejMHbVVvymhsS5GcYC4hSKag"
    assert PrvKeyNode.parse(xpriv).extended_private_key() == xpriv
    assert PrvKeyNode.parse(decode_base58_checksum(xpriv)).extended_private_key() == xpriv
    assert PrvKeyNode.parse(BytesIO(decode_base58_checksum(xpriv))).extended_private_key() == xpriv
    with pytest.raises(ValueError):
        PrvKeyNode.parse(1584784554)

def test_equality():
    xpriv = "xprv9s21ZrQH143K4EK4Fdy4ddWeDMy1x4tg2s292J5ynk23sn3hxSZ9MqqLZCTj2dHPP16CsTdAFeznbnNhSN3v66TtSKzJf4hPZSqDjjp9t42"
    m0 = PrvKeyNode.parse(s=xpriv)
    m1 = PrvKeyNode.parse(s=xpriv)
    assert m0 == m1

    xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    M0 = PubKeyNode.parse(s=xpub)
    M1 = PubKeyNode.parse(s=xpub)
    assert M0 == M1

    seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    m0 = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    m1 = PrvKeyNode.parse(s=m0.extended_private_key())
    assert m0 == m1

    m0 = PrvKeyNode.parse(s=xpriv)
    M0 = PubKeyNode.parse(s=m0.extended_public_key())
    assert m0 != M0


def test_ckd_pub_ckd_priv_matches_public_key():
    seed = "b4385b54033b047216d71031bd83b3c059d041590f24c666875c980353c9a5d3322f723f74d1f5e893de7af80d80307f51683e13557ad1e4a2fe151b1c7f0d8b"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    master_xpub = m.extended_public_key()
    M = PubKeyNode.parse(s=master_xpub)
    m44 = m.ckd(index=44)
    M44 = M.ckd(index=44)
    assert m44.extended_public_key() == M44.extended_public_key()
    assert m44.extended_public_key() == "xpub68gENos6i4PQxkSjJB2Ww79EfUVX8J4nrTHYzUWa3q6gMivLymbzHiu1MBoxi3fVDUQVi61Lv7brNs18sHjzdBVgCXocZxDwrsGrAf4GN3T"
    m440 = m44.ckd(index=0)
    M440 = M44.ckd(index=0)
    assert m440.extended_public_key() == M440.extended_public_key()
    assert m440.extended_public_key() == "xpub6AotjNzqVqVCmdvqAsMi2zNEDCobz7s9zit2pfdKPPc9LQ2GwSGybYDKuqDGC7mVhSWNZBNeRwqtjvA7rX4ACKXa8GrnD5XQkGb542RuzZ5"
    m440thousand = m440.ckd(index=1000)
    M440thousand = M440.ckd(index=1000)
    assert m440thousand.extended_public_key() == M440thousand.extended_public_key()
    assert m440thousand.extended_public_key() == "xpub6CqqMNRRTuyJNyP6VNCxY1SJWNY4t2QsmsWTsBmiZyUvbYDKMU77DaDJpeqMqNkzwCuTqXghQ58DbhNVpe9r2vtuvPSvwUWNB2Wc6RWh3US"
    m440thousand__ = m440thousand.ckd(index=2**31-1)
    M440thousand__ = M440thousand.ckd(index=2**31-1)
    assert m440thousand__.extended_public_key() == M440thousand__.extended_public_key()
    assert m440thousand__.extended_public_key() == "xpub6EtrsXwXdacQ9iDpmqTeYpu8AstEBrwiXbpdoVU4Q1yhjmN5c8Niw2KvJRwSGS4VtndPgCuHH15SstUzENBksqpVP8YxzubWcERugoDafnq"
    m440thousand__0 = m440thousand__.ckd(index=0)
    M440thousand__0 = M440thousand__.ckd(index=0)
    assert m440thousand__0.extended_public_key() == M440thousand__0.extended_public_key()
    assert m440thousand__0.extended_public_key() == "xpub6FymQUeMhBdyk57T6P9oAZVcPTniJyXWHYKxzurkT6u729eC8bdtzdP6i4RShvHrnKpiEhhZHY2kQBYxyKJPFUbUzum7w6a3W4JdADuCisC"

def test_ckd_pub_hardened_failure():
    xpub = "xpub6FUwZTpNvcMeHRJGUQoy4WTqXjzmGLUFNe3sUKeWChEbzTJDpBjZjn2cMysV5Ffw874VUVooxmupZeLjrdpM5wXLUxkatTdnayXGy6Ln7kR"
    M = PubKeyNode.parse(s=xpub)
    with pytest.raises(RuntimeError):
        M.ckd(2**31)
    with pytest.raises(RuntimeError):
        M.ckd(2 ** 31 + 256)

def test_vector_1():
    # Chain m
    seed ="000102030405060708090a0b0c0d0e0f"
    xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    assert m.extended_public_key() == xpub
    assert m.extended_private_key() == xpriv
    assert m.__repr__() == "m"

    # chain m/0'
    xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    xpriv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    m0h = m.ckd(index=2**31)
    assert m0h.extended_public_key() == xpub
    assert m0h.extended_private_key() == xpriv
    assert m0h.__repr__() == "m/0'"

    # chain M/0'
    M0h = PubKeyNode.parse(xpub)
    # chain M/0'/1
    M0h1 = M0h.ckd(index=1)
    public_only_xpub = M0h1.extended_public_key()

    # chain m/0'/1
    xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    xpriv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    m0h1 = m0h.ckd(index=1)
    assert public_only_xpub == xpub
    assert m0h1.extended_public_key() == xpub
    assert m0h1.extended_private_key() == xpriv
    assert m0h1.__repr__() == "m/0'/1"

    # chain m/0'/1/2'
    xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
    xpriv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    m0h12h = m0h1.ckd(index=2**31+2)
    assert m0h12h.extended_public_key() == xpub
    assert m0h12h.extended_private_key() == xpriv
    assert m0h12h.__repr__() == "m/0'/1/2'"

    # chain m/0'/1/2'/2
    xpub = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
    xpriv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    m0h12h2 = m0h12h.ckd(index=2)
    assert m0h12h2.extended_public_key() == xpub
    assert m0h12h2.extended_private_key() == xpriv
    assert m0h12h2.__repr__() == "m/0'/1/2'/2"

    # chain M/0'/1/2'/2
    M0h12h2 = PubKeyNode.parse(xpub)
    # chain M/0'/1/2'/2/1000000000
    M0h12h21000000000 = M0h12h2.ckd(index=1000000000)
    public_only_xpub = M0h12h21000000000.extended_public_key()

    # chain m/0'/1/2'/2/1000000000
    xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    xpriv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    m0h12h21000000000 = m0h12h2.ckd(index=1000000000)
    assert m0h12h21000000000.extended_public_key() == xpub
    assert public_only_xpub == xpub
    assert m0h12h21000000000.extended_private_key() == xpriv
    assert m0h12h21000000000.__repr__() == "m/0'/1/2'/2/1000000000"

def test_vector_2():
    # Chain m
    seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    xpriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    assert m.extended_public_key() == xpub
    assert m.extended_private_key() == xpriv
    assert m.__repr__() == "m"

    # Chain m/0
    xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    xpriv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    m0 = m.ckd(index=0)
    assert m0.extended_public_key() == xpub
    assert m0.extended_private_key() == xpriv
    assert m0.__repr__() == "m/0"

    # Chain m/0/2147483647'
    xpub = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
    xpriv = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    m02147483647h = m0.ckd(index=2**31+2147483647)
    assert m02147483647h.extended_public_key() == xpub
    assert m02147483647h.extended_private_key() == xpriv
    assert m02147483647h.__repr__() == "m/0/2147483647'"

    # Chain m/0/2147483647'/1
    xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
    xpriv = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    m02147483647h1 = m02147483647h.ckd(index=1)
    assert m02147483647h1.extended_public_key() == xpub
    assert m02147483647h1.extended_private_key() == xpriv
    assert m02147483647h1.__repr__() == "m/0/2147483647'/1"

    # Chain m/0/2147483647'/1/2147483646'
    xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    xpriv = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
    m02147483647h12147483646h = m02147483647h1.ckd(index=2**31+2147483646)
    assert m02147483647h12147483646h.extended_public_key() == xpub
    assert m02147483647h12147483646h.extended_private_key() == xpriv
    assert m02147483647h12147483646h.__repr__() == "m/0/2147483647'/1/2147483646'"

    # Chain m/0/2147483647'/1/2147483646'/2
    xpub = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
    xpriv = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    m02147483647h12147483646h2 = m02147483647h12147483646h.ckd(index=2)
    assert m02147483647h12147483646h2.extended_public_key() == xpub
    assert m02147483647h12147483646h2.extended_private_key() == xpriv
    assert m02147483647h12147483646h2.__repr__() == "m/0/2147483647'/1/2147483646'/2"

def test_vector_3():
    # Chain m
    seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
    xpriv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    assert m.extended_public_key() == xpub
    assert m.extended_private_key() == xpriv
    assert m.__repr__() == "m"

    # chain m/0'
    xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    xpriv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    m0h = m.ckd(index=2 ** 31)
    assert m0h.extended_public_key() == xpub
    assert m0h.extended_private_key() == xpriv
    assert m0h.__repr__() == "m/0'"

def test_vector_4():
    # https://blog.polychainlabs.com/bitcoin,/bip32,/bip39,/kdf/2021/05/17/inconsistent-bip32-derivations.html
    # https://github.com/btcsuite/btcutil/issues/172
    # Chain m
    seed = "1cae71ac5ed584ff88a078a119512d12bb61e5398521785e123b6d08809d44b2"
    xpub = "xpub661MyMwAqRbcEmwzw5S7mHW26Urp4kngnBFwoZUXSgakbHGs5bgZ7RYsqX9nyCP3YKqrJ2gVfaJc6waZBJC2VFsnmJB7iPSNA5LvmZpcBcQ"
    xpriv = "xprv9s21ZrQH143K2HsXq3u7Q9ZHYT2KfJ4qQxLM1B4utM3miUwiY4NJZdEPzDpzbH7xxtMr3QfT2VH13rabABKkw1eLU83YC1QMeXsX3DBe2yP"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    assert m.extended_public_key() == xpub
    assert m.extended_private_key() == xpriv
    assert m.__repr__() == "m"

    # chain m/44'
    xpub = "xpub695cM7RLktQbMS9DgS2SmkGF6W4msU7dW3ZkshyPV5PVWsWyoNxtvSBtm6VPSbcBR3a1NSp9BYy3v3QhUTi8T1HDa6rMShYmF682N6BaYpk"
    xpriv = "xprv9v6FwbtSvWrJ8x4kaQVSQcKWYUEHU1Pn8peA5KZmvjrWe5BqFqeeNdsQuqDXN9JqeAxmAvs5v682JLDQZJsB8Up4guNVPSGidN19N2iH1Lr"
    m0h = m.ckd(index=44 + 2**31)
    assert m0h.extended_public_key() == xpub
    assert m0h.extended_private_key() == xpriv
    assert m0h.__repr__() == "m/44'"

    # chain m/44'/0'
    xpub = "xpub6Begh3MMx7oX2KoJb5D9sfJruuqsqsrqBZTBBznYMRfk7RBo8EcKDodYJm529ykTr2wrK1KBKXCbdSPu74pA37hZmPxkCP3hbEJBuqJgruy"
    xpriv = "xprv9xfLHXpU7kFDoqiqV3g9WXN8Mt1PSR8ypLXaPcNvo68mEcreahJ4g1K4TWqn4qu6HCKByGeivW9neAEzSS7idYdpGaGXJgvb79fxvV4qhse"
    m0h0h = m0h.ckd(index=2 ** 31)
    assert m0h0h.extended_public_key() == xpub
    assert m0h0h.extended_private_key() == xpriv
    assert m0h0h.__repr__() == "m/44'/0'"

def test_vector_5():
    # https://github.com/bitcoin/bips/pull/1030
    # Chain m
    seed = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"
    xpub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
    xpriv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    m = PrvKeyNode.master_key(bip39_seed=bytes.fromhex(seed))
    assert m.extended_public_key() == xpub
    assert m.extended_private_key() == xpriv
    assert m.__repr__() == "m"

    # chain m/0'
    xpub = "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
    xpriv = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    m0h = m.ckd(index=2**31)
    assert m0h.extended_public_key() == xpub
    assert m0h.extended_private_key() == xpriv
    assert m0h.__repr__() == "m/0'"

    # chain m/0'/1'
    xpub = "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
    xpriv = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    m0h1h = m0h.ckd(index=1 + 2 ** 31)
    assert m0h1h.extended_public_key() == xpub
    assert m0h1h.extended_private_key() == xpriv
    assert m0h1h.__repr__() == "m/0'/1'"


def test_sec():
    data = [
        (
            999 ** 3,
            '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9',
            '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
        ),
        (
            123,
            '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b',
            '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
        ),
        (
            42424242,
            '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3',
            '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'
        )
    ]
    for secret, uncompressed, compressed in data:
        pubkey = PrivateKey(sec_exp=secret).K
        assert pubkey.sec(compressed=False) == bytes.fromhex(uncompressed)
        assert pubkey.point == PublicKey.parse(bytes.fromhex(uncompressed)).point
        assert pubkey.sec(compressed=True) == bytes.fromhex(compressed)
        assert pubkey.point == PublicKey.parse(bytes.fromhex(compressed)).point

