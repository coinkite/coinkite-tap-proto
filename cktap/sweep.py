#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Functions related to sweeping funds and building transactions.
#
# - Requires 'requests[socks]' module
# - Will try to use Tor if you have it running locally already
# - Uses data from <blockstream.info>
#
import sys, os, time, json
from pprint import pformat
#from binascii import b2a_hex, a2b_hex
from getpass import getpass
from collections import namedtuple
from cktap.utils import render_sats_value

# Explora protocol <https://github.com/Blockstream/esplora/blob/master/API.md>
DEFAULT_SERVER = 'https://blockstream.info'
ONION_SERVER = 'http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion'

# we check for any of these ports being open and assume it's Tor if found
LOCALHOST_PROXY_PORTS = [ 9150, 9050 ]

class NetConnection:

    def __init__(self, server=None):
        import requests
        self.ses = requests.Session()
        self.is_tor = self.tor_upgrade()
        self.server = server or (DEFAULT_SERVER if not self.is_tor else ONION_SERVER)
        assert not self.server.endswith('/')

        # I want no user-agent header at all, so have to
        # use this one strange hack into urllib3...
        from urllib3.util import SKIP_HEADER
        self.ses.headers['user-agent'] = SKIP_HEADER

    def tor_upgrade(self):
        # See if Tor is running, if so, apply socks-proxy details
        # - not doing generalized socks proxies but
        # - you can override with HTTP_PROXY / HTTPS_PROXY in environment
        #   which would be directly implemented in requests, see
        #   <https://2.python-requests.org/en/master/user/advanced/#proxies>
        import requests

        if ('HTTP_PROXY' in os.environ) or ('HTTPS_PROXY' in os.environ) or self.ses.proxies:
            return False

        try:
            # do we have support for socks?
            import socks
        except ImportError:
            return False

        for port in LOCALHOST_PROXY_PORTS:
            try:
                r = requests.get(f'http://127.0.0.1:{port}')
            except:
                continue
            if ('This is a SOCKS Proxy, Not An HTTP Proxy' in r.text):
                # usual socks error message from Tord running locally.
                self.ses.proxies['https'] = f'socks5h://127.0.0.1:{port}'
                self.ses.proxies['http'] = f'socks5h://127.0.0.1:{port}'

                return True

        return False
            
    def get_json(self, path, **kws):
        # fetch a JSON response
        assert path[0] == '/'
        r = self.ses.get(self.server + path, **kws)
        r.raise_for_status()
        try:
            return r.json()
        except json.decoder.JSONDecodeError:
            raise ValueError("Bad json: " + r.text)
            


    
UTXO = namedtuple('UTXO', 'txid vout value height confirmed')

class UTXOList:

    def __init__(self, address, slot_num=None, server=None):
        # must call self.fetch() after setup
        self.slot = slot_num
        self.addr = address
        self.testnet = address.startswith('tb1')
        self.web = NetConnection(server)
        self.utxos = []


    def fetch(self):
        # load up the data from network
        # - TODO: cursor support for > 25 utxo? Not clear if supported on server

        path = ('/testnet' if self.testnet else '') + f'/api/address/{self.addr}/utxo'
        ans = self.web.get_json(path)
        for u in ans:
            h = u['status'].get('block_height', -1)
            conf = u['status'].get('confirmed', False)

            utxo = UTXO(u['txid'], u['vout'], u['value'], h, conf)

            self.utxos.append(utxo)

        return len(self.utxos)

    # never, ever, add these values together!
    def confirmed_balance(self):
        return sum(u.value for u in self.utxos if u.confirmed)
    def unconfirmed_balance(self):
        return sum(u.value for u in self.utxos if not u.confirmed)

    def balance(self):
        # string value for humans, start with this
        c = self.confirmed_balance()
        u = self.unconfirmed_balance()
        return render_sats_value(c, u)

    def fetch_txns(self):
        # Fetch transaction details for all desposit transactions
        # - should be all the data needed to build a transaction for signing
        # - except for miner fee, and reconstructing redeem scripts, etc...
        # - oh, and hashing correctly
        prefix = '/testnet' if self.testnet else ''

        txns = {}
        for txid in set(u.txid for u in self.utxos):
            txns[txid] = self.web.get_json(prefix + f'/api/tx/{txid}')

        return txns


# use pytest to run these test(s)

def test_useragent():
    a = NetConnection('http://httpbin.org')
    assert a.is_tor == True
    x = a.get_json('/user-agent')
    assert x['user-agent'] == None

if __name__ == '__main__':

    addr = sys.argv[-1]
    if addr[2] != '1':
        # lots of txn on this one?
        addr = 'tb1q39xdpaq5utt9f6pn7zvw5qwf6hweukwqm4avgp'

    ul = UTXOList(addr)
    ul.fetch()
    #print(ul.utxos)
    print('Balance: ' + ul.balance())

    ins = ul.fetch_txns()
    print('txns: ' + repr(ins))

# EOF
