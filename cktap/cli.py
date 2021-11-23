#!/usr/bin/env python
#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "cktap" in your path.
#
#
import click, sys, os, pdb, time, json
from pprint import pformat
from binascii import b2a_hex, a2b_hex
from functools import wraps
from getpass import getpass

from .utils import xor_bytes, render_address, render_wif, render_descriptor
from .constants import *
from .transport import CKTapCard, find_cards

B2A = lambda x: b2a_hex(x).decode('ascii')

global force_uid
force_uid = None

# Cleanup display (supress traceback) for user-feedback exceptions
_sys_excepthook = sys.excepthook
def my_hook(ty, val, tb):
    if ty in { CardRuntimeError, RuntimeError }:
        print("\n\n%s" % val, file=sys.stderr)
    else:
        return _sys_excepthook(ty, val, tb)
sys.excepthook=my_hook

def get_card():
    # XXX search based on uid or something
    # and/or wait?
    for c in find_cards():
        return c

def fail(msg):
    # show message and stop
    click.echo(msg)
    sys.exit(1)

def dump_dict(d):

    for k,v in d.items():
        if k == 'card_nonce':
            # no point showing this value
            continue

        if isinstance(v, (bytes, bytearray)):
            v = B2A(v)

        click.echo('%s: %s' % (k, v))

def cleanup_cvc(cvc, missing_ok=False):
    # Cleanup CVC provided (digits only) and prompt if needed, fail if invalid syntax
    if not cvc:
        if missing_ok:
            return None
        cvc = getpass("Enter spending code (6 digits): ")

    cvc = cvc[0:0].join(d for d in cvc if d.isdigit())

    if not cvc and missing_ok:
        # blank/empty response, ok in this case
        return None

    if len(cvc) != CVC_LENGTH:
        fail("Need 6-digit numeric code from back of card.")

    return cvc
    
def display_errors(f):
    # clean-up display of errors from device
    # XXX use me
    @wraps(f)
    def wrapper(*args, **kws):
        try:
            return f(*args, **kws)
        except RuntimeError as exc:
            click.echo("\n%s\n" % str(exc.args[0]))
            sys.exit(1)
    return wrapper

#
# Options we want for all commands
#
@click.group()
@click.option('--uid', '-u', default=None, metavar="HEX",
                    help="Operate on specific card (default: first found)")
def main(uid):
    global force_uid
    force_uid = uid
        
@main.command()
def debug():
    "Start interactive (local) debug session"
    import code
    import readline
    import atexit
    import os
            
    class HistoryConsole(code.InteractiveConsole):
        def __init__(self, locals=None, filename="<console>",
                     histfile=os.path.expanduser("~/.console-history")):
            code.InteractiveConsole.__init__(self, locals, filename)
            self.init_history(histfile)
        
        def init_history(self, histfile):
            readline.parse_and_bind("tab: complete")
            if hasattr(readline, "read_history_file"):
                try:
                    readline.read_history_file(histfile)
                except IOError:
                    pass
                atexit.register(self.save_history, histfile)
        
        def save_history(self, histfile):
            readline.write_history_file(histfile)

    # useful stuff
    import pdb
    from pdb import pm
    C = get_card()
    G = C.send

    cli = HistoryConsole(locals=dict(globals(), **locals()))
    cli.interact(banner="Go for it: 'C' is the connected card, G=C.send ... G('status')", exitmsg='')

@main.command('chain')
def get_block_chain():
    '''Get which blockchain (Bitcoin/Testnet) is configured.

    BTC=>Bitcoin  or  XTN=>Bitcoin Testnet
    '''

    card = get_card()

    click.echo('XTN' if card.is_testnet else 'BTC')

    
@main.command('msg')
@click.argument('message')
@click.option('--verbose', '-v', is_flag=True, help='Include fancy ascii armour')
@click.option('--just-sig', '-j', is_flag=True, help='Just the signature itself, nothing more')
@click.option('--segwit', '-s', is_flag=True, help='Address in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Address in segwit wrapped in P2SH (p2wpkh)')
def sign_message(message, path=2, verbose=True, just_sig=False, wrap=False, segwit=False):
    "Sign a short text message"

    card = get_card()

    if wrap:
        addr_fmt = AF_P2WPKH_P2SH
    elif segwit:
        addr_fmt = AF_P2WPKH
    else:
        addr_fmt = AF_CLASSIC

    # NOTE: initial version of firmware not expected to do segwit stuff right, since
    # standard very much still in flux, see: <https://github.com/bitcoin/bitcoin/issues/10542>

    # not enforcing policy here on msg contents, so we can define that on product
    message = message.encode('ascii') if not isinstance(message, bytes) else message

    ok = dev.send_recv(CCProtocolPacker.sign_message(message, path, addr_fmt), timeout=None)
    assert ok == None

    print("Waiting for OK on the Coldcard...", end='', file=sys.stderr)
    sys.stderr.flush()

    while 1:
        time.sleep(0.250)
        done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)
        if done == None:
            continue

        break

    print("\r                                  \r", end='', file=sys.stderr)
    sys.stderr.flush()

    if len(done) != 2:
        click.echo('Failed: %r' % done)
        sys.exit(1)

    addr, raw = done

    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    if just_sig:
        click.echo(str(sig))
    elif verbose:
        click.echo('-----BEGIN SIGNED MESSAGE-----\n{msg}\n-----BEGIN '
                  'SIGNATURE-----\n{addr}\n{sig}\n-----END SIGNED MESSAGE-----'.format(
                        msg=message.decode('ascii'), addr=addr, sig=sig))
    else:
        click.echo('%s\n%s\n%s' % (message.decode('ascii'), addr, sig))
    

"""
@main.command('backup')
@click.option('--outdir', '-d', 
            type=click.Path(exists=True,dir_okay=True, file_okay=False, writable=True),
            help="Save into indicated directory (auto filename)", default='.')
@click.option('--outfile', '-o', metavar="filename.aes",
                        help="Name for backup file", default=None,
                        type=click.File('wb'))
@display_errors
def start_backup(outdir, outfile, verbose=False):
    '''Creates 7z encrypted backup file after prompting user to remember a massive passphrase. \
Downloads the AES-encrypted data backup and by default, saves into current directory using \
a filename based on today's date.'''

    card = get_card()
    
    #card.send('backup', cvc=
    
    #ok = dev.send_recv(card.
    #assert ok == None

    #result, chk = wait_and_download(dev, CCProtocolPacker.get_backup_file(), 0)

    if outfile:
        outfile.write(result)
        outfile.close()
        fn = outfile.name
    else:
        assert outdir

        # pick a useful filename, if they gave a dirname
        fn = os.path.join(outdir, time.strftime('backup-%Y%m%d-%H%M.7z'))

        open(fn, 'wb').write(result)

    click.echo("Wrote %d bytes into: %s\nSHA256: %s" % (len(result), fn, str(b2a_hex(chk), 'ascii')))
"""

@main.command('version')
def get_version():
    "Get the version of the card's firmware installed (not upgradable)"

    card = get_card()

    click.echo(card.card_version)

@main.command('list')
def _list():
    "List all cards detected on any reader attached"

    count = 0
    for card in find_cards():
        #click.echo("\nColdcard {serial_number}:\n{nice}".format(
                            #nice=pformat(info, indent=4)[1:-1], **info))
        click.echo(repr(card))
        count += 1

    if not count:
        click.echo("(none found)")

@main.command('usage')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def get_usage(cvc):
    "Show slots usage so far"

    card = get_card()

    print('SLOT# |  STATUS  | ADDRESS')
    print('------+----------+-------------')
    for slot in range(card.num_slots):
        session_key, here = card.send_auth('dump', cleanup_cvc(cvc, missing_ok=True), slot=slot)

        status = '???'
        addr = None
        if here.get('sealed', None) == True:
            status = 'sealed'
            if slot == card.active_slot:
                addr = card.address()
        elif (here.get('sealed', None) == False) or ('privkey' in here):
            status = 'UNSEALED'
            if 'privkey' in here:
                pk = xor_bytes(session_key, here['privkey'])
                addr = render_address(pk, card.is_testnet)
        elif here.get('used', None) == False:
            status = "unused"
        else:
            dump_dict(here)
            pass

        addr = addr or here.get('addr')
        
        print('%3d   | %-8s | %s' % (slot, status, addr or ''))

@main.command('addr')
def get_addr():
    "Show current deposit address"
    card = get_card()

    addr = card.address()
    if not addr:
        fail("Current slot not yet setup and has no address.")

    click.echo(addr)

@main.command('open')
def get_addr_open_app():
    "Get address and open associated bitcoin app to handle"
    card = get_card()

    addr = card.address()
    if not addr:
        fail("Current slot not yet setup and has no address.")

    url = 'bitcoin:' + addr

    click.launch(url)

@main.command('qr')
@click.option('--outfile', '-o', metavar="filename.png",
                        help="Save an SVG or PNG (depends on extension)", default=None,
                        type=click.File('wb'))
@click.option('--error-mode', '-e', default='L', metavar="L|M|H",
            help="Forward error correction level (L = low, H=High=bigger)")
def get_deposit_qr(outfile, error_mode):
    "Show current deposit address as a QR"
    import pyqrcode

    card = get_card()
    addr = card.address()

    if not addr:
        fail("Current slot not yet setup and has no address.")

    url = 'bitcoin:{addr}'.format(addr=addr).upper()
    q = pyqrcode.create(url, error=error_mode, mode='alphanumeric')

    if not outfile:
        print(q.terminal())
        print('      ' + addr)
        print()
    elif outfile.name.lower().endswith('.svg'):
        q.svg(outfile, scale=1)
    else:
        q.png(outfile)

@main.command('dump')
@click.argument('slot', type=int, metavar="[SLOT#]", required=False, default=0)
@click.argument('cvc', type=str, metavar="[6-digit code]", required=False)
def dump_slot(slot, cvc):
    "Show state of slot number indicated. Provide code to get more info for unsealed slots."
    card = get_card()

    session_key, resp = card.send_auth('dump', cleanup_cvc(cvc, missing_ok=True), slot=slot)
    if 'privkey' in resp:
        resp['privkey'] = xor_bytes(session_key, resp['privkey'])

    dump_dict(resp)
        
@main.command('check')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def check_cvc(cvc):
    "Check you have the spending code correct. Does nothing with it"

    card = get_card()
    cvc = cleanup_cvc(cvc)

    # do a dump command
    ses_key, resp = card.send_auth('dump', cvc, slot=0)

    if 'error' in resp:
        fail(resp['error'])
    
    print("Code is correct %r" % resp)
    
@main.command('unseal')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def unseal_slot(cvc):
    "Unseal current slot. Does not setup next slot."

    #'privkey': (32 bytes)   # private key for spending
    #'pubkey': (33 bytes)    # slot's pubkey (convenience, since could be calc'd from privkey)
    #'master_pk': (32 bytes)      # card's master private key
    #'chain_code': (32 bytes)     # nonce provided by customer

    card = get_card()

    # only one possible value for slot number
    target = card.active_slot

    # but that slot must be used and sealed (note: unauthed)
    resp = card.send('dump', slot=target)

    if resp.get('sealed', None) == False:
        fail(f"Slot {target} has already been unsealed.")

    if resp.get('sealed', None) != True:
        fail(f"Slot {target} has not been used yet.")

    cvc = cleanup_cvc(cvc)
    ses_key, resp = card.send_auth('unseal', cvc, slot=target)

    pk = xor_bytes(ses_key, resp['privkey'])

    # could dump xprv here, but will confuse people
    #m_pk = xor_bytes(ses_key, resp['master_pk'])

    # show all the details
    dump_info(resp['slot'], pk, is_testnet=card.is_testnet)

@main.command('wif')
@click.option('--slot', '-s', type=int, metavar="#", default=-1, help="Slot number, default: last used")
@click.option('--bip178', '-8', is_flag=True, 
                help="Use binary encoding defined in BIP-178")
@click.option('--bare', is_flag=True, 
                help="Remove text prefix proposed by Electrum")
@click.argument('cvc', type=str, metavar="[6-digit code]", required=False)
def dump_wif(cvc, slot, bip178, bare):
    "Show WIF for last unsealed slot, or give slot number"
    card = get_card()

    if slot == -1:
        st = card.send('status')
        active = st['slots'][0]
        slot = active-1

    cvc = cleanup_cvc(cvc)
    
    ses_key, resp = card.send_auth('dump', cvc, slot=slot)

    if 'privkey' not in resp:
        if resp.get('used', None) == False:
            fail(f"That slot ({slot}) is not yet used (no key yet)")
        if resp.get('sealed', None) == True:
            fail(f"That slot ({slot}) is not yet unsealed.")
        # unreachable:
        fail(f"Not sure of the key for that slot ({slot}).")

    pk = xor_bytes(ses_key, resp['privkey'])

    if bip178:
        bare=True

    wif = render_wif(pk, bip_178=bip178, electrum=(not bare), testnet=card.is_testnet)

    if not bare:
        click.echo(f'Slot {slot} private key WIF:\n')
        click.echo(wif)
        click.echo()
    else:
        click.echo(wif)
    

def dump_info(slot_num, privkey, is_testnet=False):

    addr = render_address(privkey, is_testnet)

    wif = render_wif(privkey, is_testnet)

    click.echo(f"Slot #{slot_num}:\n\n{addr}\n\n{wif}")

@main.command('setup')
@click.option('--chain-code', '-c', type=str, metavar="HEX",
                help="Chain code to be used for XPRV of resulting slot (32 bytes)")
@click.option('--new-chain-code', '-n', is_flag=True, 
                help="Pick a fresh chain code randomly.")
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def setup_slot(cvc, chain_code, new_chain_code):
    "Setup a new slot with a private key."

    card = get_card()

    # only one possible value for slot number
    target = card.active_slot

    # but that slot must be un-used.
    resp = card.send('dump', slot=target)

    if resp.get('used', True):
        fail(f"Slot {target} has been used already. Unseal it, and move to next")

    args = dict(slot=target)

    if chain_code and new_chain_code:
        fail("Provide a chain code or make me pick one, not both")

    if new_chain_code:
        chain_code = os.urandom(32)
    elif chain_code:
        try:
            chain_code = b2a_hex(chain_code)
            assert len(chain_code) == 32
        except:
            fail("Need 64 hex digits (32 bytes) for chain code.")
        args['chain_code'] = chain_code
    elif target == 0:
        # rare, not expected case since factory setup on slot zero
        fail("Chain code required for slot zero setup")
    
    cvc = cleanup_cvc(cvc)
    ses_key, resp = card.send_auth('new', cvc, **args)

    # only one field: new slot number
    card.active_slot = resp['slot']

    click.echo(card.address())

@main.command('core')
@click.option('--pretty', '-p', is_flag=True, help="Pretty-print JSON")
@click.argument('cvc', type=str, metavar="(6-digit code)", required=False)
def export_to_core(cvc, pretty):
    "Show JSON needed to import private keys into Bitcoin Core"

    # see 
    # - <https://bitcoincore.org/en/doc/0.21.0/rpc/wallet/importmulti/>
    # - <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>

    card = get_card()

    # CVC is optional, but they probably want it
    if not cvc:
        click.echo("Warning: Without the code, can only watch addresses from this card.", err=1)
    cvc = cleanup_cvc(cvc, missing_ok=True)

    shared = dict(timestamp=PROJECT_EPOC_TIME_T, descr=[], internal=False)
    if not cvc:
        shared['watchonly'] = True

    rv = []
    for slot in range(card.active_slot+1):
        session_key, here = card.send_auth('dump', cvc, slot=slot)

        if here.get('used', None) == False:
            continue

        pk = None
        addr = None
        if here.get('sealed', None) == True:
            if cvc: continue
            pubkey, addr = card.address(incl_pubkey=1)

        if 'privkey' in here:
            pk = xor_bytes(session_key, here['privkey'])
            addr = render_address(pk, card.is_testnet)

        line = dict()
        line.update(shared)

        if pk:
            w = render_descriptor(privkey=pk, testnet=card.is_testnet)
        elif addr:
            w = render_descriptor(address=addr)
            line['pubkeys'] = [B2A(pubkey)]
        else:
            continue

        line['desc'] = [w]
        rv.append(line)

    # TODO this doesn't work, but looks likely
    click.echo('importmulti \'%s\'' % json.dumps(rv, indent=(2 if pretty else None)))

    

# EOF
