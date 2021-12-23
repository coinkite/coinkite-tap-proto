#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
#
from cktap.sweep import NetConnection, UTXO, UTXOList

def test_useragent():
    a = NetConnection('http://httpbin.org')
    assert a.is_tor == True
    x = a.get_json('/user-agent')
    assert x['user-agent'] == None

def test_fetch():
    # weak, fragile but better-than-nothing testcase
    addr='tb1q39xdpaq5utt9f6pn7zvw5qwf6hweukwqm4avgp'
    ul = UTXOList(addr)
    assert ul.addr == addr
    ul.fetch()
    assert ul.confirmed_balance() == 719_394

# EOF
