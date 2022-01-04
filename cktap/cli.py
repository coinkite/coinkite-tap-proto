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

from .utils import xor_bytes, render_address, render_wif, render_descriptor, B2A, ser_compact_size
from .utils import make_recoverable_sig, render_sats_value
from .compat import sha256s
from .constants import *
from .exceptions import CardRuntimeError
from .transport import CKTapCard, find_cards

# dict of options that apply to all commands
global global_opts
global_opts = dict()

# Cleanup display (supress traceback) for user-feedback exceptions
_sys_excepthook = sys.excepthook
def my_hook(ty, val, tb):
    if ty in { CardRuntimeError, RuntimeError }:
        print("\n\nFATAL: %s" % val, file=sys.stderr)
    else:
        return _sys_excepthook(ty, val, tb)
sys.excepthook=my_hook

def fail(msg):
    # show message and stop
    click.echo(msg)
    sys.exit(1)

def get_card():
    # Pick a card to work with
    global global_opts
    pk_filter = (global_opts.get('card_pubkey') or '').lower()
    wait_for_it = global_opts.get('wait', False)

    first = True
    while 1:
        for c in find_cards():
            if pk_filter:
                if not B2A(c.pubkey).endswith(pk_filter):
                    c.close()
                    continue
            return c

        if not wait_for_it: 
            fail("No cards found. Is it in place on reader?")

        if first:
            click.echo("Waiting for card...")
            first = False

        time.sleep(1)
        

def dump_dict(d):

    for k,v in d.items():
        if k == 'card_nonce':
            # no point showing this value
            continue

        if isinstance(v, (bytes, bytearray)):
            v = B2A(v)

        click.echo('%s: %s' % (k, v))

def cleanup_cvc(cvc, missing_ok=False):
    # Cleanup CVC provided (digits only) and prompt if needed, fail if wrong length
    if not cvc:
        if missing_ok:
            return None
        cvc = getpass("Enter spending code (6 digits): ")

    cvc = cvc[0:0].join(d for d in cvc if d.isdigit())

    if not cvc and missing_ok:
        # blank/empty response, ok in this case
        return None

    if len(cvc) != CVC_LENGTH:
        fail(f"Need {CVC_LENGTH}-digit numeric code from back of card.")

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

# Accept any prefix of a command name.
#
# from <https://click.palletsprojects.com/en/8.0.x/advanced/?#command-aliases>
class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail(f"Abiguous command. Pick one of: {', '.join(sorted(matches))}")

    def resolve_command(self, ctx, args):
        # always return the full command name
        _, cmd, args = super().resolve_command(ctx, args)
        return cmd.name, cmd, args


#
# Options we want for all commands
#
@click.group(cls=AliasedGroup)
@click.option('--card-pubkey', '-c', default=None, metavar="HEX",
                    help="Operate on specific card (rightmost hex digits of public key)")
@click.option('--wait', '-w', is_flag=True, 
                    help="Waits until a card is in place.")
@click.option('--pdb', is_flag=True, 
                    help="Prepare patient for surgery to remove bugs.")
def main(**kws):
    '''
    Control and interact with SATSCARD via NFC tap.


    You can use "bal", or "b" for "balance": any distinct prefix for all commands.
    '''

    # implement PDB option here
    if kws.pop('pdb', False):
        import pdb, sys
        def doit(ex_cls, ex, tb):
            pdb.pm()
        sys.excepthook = doit

    # global options, mostly not considered here
    global global_opts
    global_opts.update(kws)
        
@main.command('debug')
def interactive_debug():
    "Start interactive (local) debug session."
    import code
    import atexit
    import os
            
    try:
        import readline
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
    except ImportError:
        # windows probably, keep going
        HistoryConsole = code.InteractiveConsole

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
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
@click.option('--verbose', '-v', is_flag=True, help='Include full ascii armour')
@click.option('--just-sig', '-j', is_flag=True, help='Just the signature itself, nothing more')
@click.option('--slot', '-s', type=int, metavar="#", default=0, help="Slot number, default: zero")
def sign_message(cvc, message, path=2, verbose=True, just_sig=False, slot=0):
    "Sign a short text message (TODO -- INCOMPLETE)"
    from base64 import b64encode

    card = get_card()

    message = message.encode('ascii') if not isinstance(message, bytes) else message

    # TODO: 
    # - using <https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki>
    # - build a message digest, based on BIP-340 "tagged hash" and a fake to_sign txn
    # - send digest to card
    # - serialize result, which includes to_sign txn

    # XXX until then, pretend we are living in a simple 2010 world.
    # - I don't know of any tools which can be used to verify this signature... so it's useless
    xmsg = b'\x18Bitcoin Signed Message:\n' + ser_compact_size(len(message)) + message
    md = sha256s(sha256s(xmsg))

    cvc = cleanup_cvc(cvc)
    ses_key, resp = card.send_auth('sign', cvc, slot=slot, digest=md)

    addr = card.address(slot=slot)

    # problem: not a recoverable signature, need to calc recid based on our
    # knowledge of address
    raw = make_recoverable_sig(md, resp['sig'], addr, card.is_testnet)

    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    if just_sig:
        click.echo(str(sig))
    else:
        if verbose:
            click.echo('-----BEGIN SIGNED MESSAGE-----\n{msg}\n-----BEGIN '
                      'SIGNATURE-----\n{addr}\n{sig}\n-----END SIGNED MESSAGE-----'.format(
                            msg=message.decode('ascii'), addr=addr, sig=sig))
        else:
            click.echo('%s\n%s\n%s' % (message.decode('ascii'), addr, sig))
    
@main.command('version')
def get_version():
    "Get the version of the card's firmware installed (but not upgradable)"

    card = get_card()

    click.echo(card.applet_version)

@main.command('list')
def list_cards():
    "List all cards detected on any reader attached."

    count = 0
    for card in find_cards():
        click.echo(repr(card))
        count += 1

    if not count:
        click.echo("(none found)")

@main.command('usage')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def get_usage(cvc):
    "Show slots usage so far."

    cvc = cleanup_cvc(cvc, missing_ok=True)
    card = get_card()

    print('SLOT# |  STATUS  | ADDRESS')
    print('------+----------+-------------')
    for slot in range(card.num_slots):
        addr, status, _ = card.get_slot_usage(slot, cvc=cvc)
        
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
@click.option('--slot', '-s', type=int, metavar="#", default=None, help="Slot number (optional)")
def get_addr_open_app(slot):
    "Get address and open associated local Bitcoin app to handle it"
    card = get_card()

    addr = card.address(slot=slot)
    if not addr:
        fail("Current slot not yet setup and has no address.")

    url = 'bitcoin:' + addr

    click.launch(url)

@main.command('url')
@click.option('--open-browser', '-o', is_flag=True, 
                help="Launch web browser app to view the URL")
def get_nfc_url(open_browser):
    "Get website URL used for NFC verification, and optionally open it"
    card = get_card()

    url = card.get_nfc_url()

    click.echo(url)

    if open_browser:
        click.launch(url)

@main.command('qr')
@click.option('--outfile', '-o', metavar="filename.png",
                        help="Save an SVG or PNG (depends on extension)", default=None,
                        type=click.File('wb'))
@click.option('--slot', '-s', type=int, metavar="#", default=None, help="Slot number (optional)")
@click.option('--error-mode', '-e', default='L', metavar="L|M|H",
            help="Forward error correction level (L = low, H=High=bigger)")
def get_deposit_qr(outfile, slot, error_mode):
    "Show current deposit address as a QR"
    import pyqrcode

    card = get_card()

    addr = card.address(slot=slot)
    if not addr:
        fail("Current slot not yet setup and has no address.")

    url = 'bitcoin:{addr}'.format(addr=addr).upper()
    q = pyqrcode.create(url, error=error_mode, mode='alphanumeric')

    if not outfile:
        # TODO: this doesn't work on Windows
        print(q.terminal(quiet_zone=2))
        print((' '*12) + addr)
        print()
    else:
        if outfile.name.lower().endswith('.svg'):
            q.svg(outfile, scale=1)
        else:
            q.png(outfile)

        click.echo(f"Wrote {outfile.tell():,} bytes to: {outfile.name}", err=1)

@main.command('dump')
@click.argument('slot', type=int, metavar="[SLOT#]", required=False, default=0)
@click.argument('cvc', type=str, metavar="[6-digit code]", required=False)
def dump_slot(slot, cvc):
    "Show state of slot number indicated. Needs CVC to get more info on unsealed slots."
    card = get_card()

    session_key, resp = card.send_auth('dump', cleanup_cvc(cvc, missing_ok=True), slot=slot)
    if 'privkey' in resp:
        resp['privkey'] = xor_bytes(session_key, resp['privkey'])

    dump_dict(resp)
        
@main.command('check')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def check_cvc(cvc):
    "Verify you have the spending code (CVC) correct. Does nothing with it"

    card = get_card()
    cvc = cleanup_cvc(cvc)

    if card.auth_delay:
        with click.progressbar(label="Requires security delay", length=card.auth_delay) as bar:
            for n in range(card.auth_delay):
                card.send('unlock')
                bar.update(1)

    # do a dump command
    try:
        ses_key, resp = card.send_auth('dump', cvc, slot=0)
        click.echo("Code is correct.")
    except CardRuntimeError as exc:
        if exc.code == 429:
            # not expected
            fail("Rate limited. Need to wait.")
        elif exc.code == 401:
            fail("Incorrect code.")
        else:
            raise
    
        
@main.command('certs')
def check_certs():
    "Check this card was made by Coinkite: Verifies a certificate chain up to root factory key."

    card = get_card()

    label = card.certificate_check()
    
    click.echo("Genuine card from Coinkite.\n\nHas cert signed by: %s" % label)
    
@main.command('unseal')
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def unseal_slot(cvc):
    "Unseal current slot and reveal private key. Does not setup next slot."

    card = get_card()

    cvc = cleanup_cvc(cvc)

    pk, slot_num = card.unseal_slot(cvc)

    # show all the details
    dump_key_info(slot_num, pk, is_testnet=card.is_testnet)

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

    # guess most useful slot to show
    if slot == -1:
        st = card.send('status')
        active = st['slots'][0]
        slot = active-1 if active >= 1 else 0

    if bip178:
        bare = True

    cvc = cleanup_cvc(cvc)
    pk = card.get_privkey(cvc, slot)
    wif = render_wif(pk, bip_178=bip178, electrum=(not bare), testnet=card.is_testnet)

    if not bare:
        dump_key_info(slot, pk, wif, is_testnet=card.is_testnet)
    else:
        click.echo(wif)
    

def dump_key_info(slot_num, privkey, wif=None, is_testnet=False):
    # Show the WIF and address

    addr = render_address(privkey, is_testnet)

    wif = wif or render_wif(privkey, is_testnet)

    click.echo(f"Slot #{slot_num}:\n\n{addr}\n\n{wif}")

@main.command('setup')
@click.option('--chain-code', '-c', type=str, metavar="HEX",
                help="Chain code to be used for XPRV of resulting slot (32 bytes)")
@click.option('--new-chain-code', '-n', is_flag=True, 
                help="Pick a fresh chain code randomly.")
@click.argument('cvc', type=str, metavar="(6-digit # code)", required=False)
def setup_slot(cvc, chain_code, new_chain_code):
    "Setup next slot with a fresh private key (not shown)."

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
        args['chain_code'] = os.urandom(32)
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

@main.command('balance')
@click.argument('cvc', type=str, metavar="(6-digit code)", required=False)
def show_balance(cvc):
    "Show the balance held on all slots"
    from cktap.sweep import UTXOList

    cvc = cleanup_cvc(cvc, missing_ok=True)
    card = get_card()

    rv = []
    click.echo('%-42s | Balance' % 'Address')
    click.echo(('-'*42) + '-+-------------')

    for slot in range(card.active_slot+1):
        addr = card.address(slot=slot, faster=True)
        if addr:
            b = UTXOList(addr)
            b.fetch()
            bal = b.balance()
            click.echo(f'{addr:40} | {bal}')
            

@main.command('core')
@click.option('--pretty', '-p', is_flag=True, help="Pretty-print JSON")
@click.argument('cvc', type=str, metavar="(6-digit code)", required=False)
def export_to_core(cvc, pretty):
    "Show JSON needed to import private keys into Bitcoin Core"

    # see 
    # - <https://bitcoincore.org/en/doc/0.21.0/rpc/wallet/importmulti/>
    # - <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>
    # - <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>
    # - <https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki>

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
