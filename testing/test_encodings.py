#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Test encoding/serializations from utils.py
# 
import pytest

from cktap.utils import card_pubkey_to_ident, path2str, str2path

def test_card_pubkey_to_ident():
    assert card_pubkey_to_ident(bytes(33)) == 'F4SYL-A67EY-W3Y7L-PNDZK'

@pytest.mark.parametrize('case',
    [ 'm', 'm/1/2/3', 'm/1h/2h/3/4' ]
)
def test_paths(case):
    assert path2str(str2path(case)) == case
    with pytest.raises(ValueError) as err:
        str2path("m/84h/0h/0h/2147483648h")
    assert err.value.args[0] == 'Hardened path component out of range: 2147483648h'
    with pytest.raises(ValueError) as err:
        str2path("m/84h/h/0h")
    assert err.value.args[0] == 'Malformed bip32 path component: h'
    with pytest.raises(ValueError) as err:
        str2path("m/84h/0h/2147483648")
    assert err.value.args[0] == 'Non-hardened path component out of range: 2147483648'
    with pytest.raises(ValueError) as err:
        str2path("m/84h/0h/-1")
    assert err.value.args[0] == 'Non-hardened path component out of range: -1'

# EOF
