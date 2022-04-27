#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
from cktap.descriptors import descsum_create, descsum_check


def test_simple_descsum_check():
    d1 = "addr(tb1qdu05evh9kw0w482lfl2ktxm6ylp060kmqpe5js)", 'addr(tb1qdu05evh9kw0w482lfl2ktxm6ylp060kmqpe5js)#n0s7nyz0'
    d2 = "wpkh(cU7CGBhwnMdLDbqBaXm3xE22KFyaA5s3YDBis88LyuPLnmfpDFFU)", 'wpkh(cU7CGBhwnMdLDbqBaXm3xE22KFyaA5s3YDBis88LyuPLnmfpDFFU)#2kyyxsrc'

    for d, expected in [d1, d2]:
        d_w_sum = descsum_create(d)
        assert d_w_sum == expected
        assert descsum_check(d_w_sum)

