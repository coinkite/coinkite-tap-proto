# Coinkite Tap Protocol and Helper Program

This Python library enables easy communication with **TAPSIGNER<sup>&trade;</sup>** and **SATSCARD<sup>&trade;</sup>**.

**-==[Request card development samples [here](https://coinkite.cards/dev)]==-**

Repository contents:

1. The protocol specification
2. Python library for speaking the protocol
3. Supporting documentation

Examples/Libraries in other languages will be added when available.

## Documentation Links

- **[Docs and Spec subdirectory (./docs)](docs)**
  - [Protocol specification](docs/protocol.md)
  - [NFC specification](docs/nfc-spec.md)
  - [Developer's Guide and Usage Hints for TAPSIGNER](docs/tapsigner-hints.md)
- [Emulator README](emulator/README.md)
- [Testing README](testing/README.md)


# Install

## Setup For Everyday Use

First update `pip` to latest version and install wheel (otherwise legacy setup.py install will be used)
```shell
pip install -U pip wheel
```

Install `cktap`, our helpful command-line program, with just:

    pip install 'coinkite-tap-protocol[cli]'

**OR**

If you just want the Python library, use: `pip install coinkite-tap-protocol`


## Setup If You Might Change the Code

1. Do a git checkout
2. Make a fresh virtualenv (suggested)
3. Run:

```
# only library
pip install --editable .
# or with cktap cmdline utility
pip install --editable '.[cli]'
# for testing purposes
pip install --editable '.[test]'
```

This installs `cktap` and any changes you make will be immediately
reflected in the installed version.

## Requirements

- Python 3.6 or higher
- `pyscard` for access to smart card readers
- A supported smart card reader. In theory, all smart card USB CCID class-compliant
  devices should work. Our observations:
    - **ACS ACR1252U** - okay and widely available
    - **Identiv uTrust 3700F** - reliable and looks nice
    - **HID Omnikey 5022 CL** (not 5021) - fast, cute, and small
    - **NOT recommended:** ACS ACR122U. It can work, and is widely available, but is not reliable.
- See `requirements.txt` file for python packages needed.


## Ubuntu/Debian Notes
Installing `pyscard` require SWIG and libpcsclite:
```shell
# run below before installing dependencies with pip
# tested on Ubuntu 20.04 (only)
sudo apt-get install swig
sudo apt-get install libpcsclite-dev
```


## Windows Notes

Installing `pyscard` may require SWIG:

1. Download .zip from <http://swig.org>.
2. Extract and move into `C:\Program Files`.
3. Add that to system PATH.
4. Test: `swig` at command prompt should work.
5. Run `pip install pyscard`.


## FreeBSD Notes

Tested against 13.0-RELEASE.

1. `pkg install py38-pyscard py38-coincurve`
    - follow devfs.conf instructions
    - install usr/ports/devel/libccid
    - add `pcscd_enable="YES"` to rc.conf
2. `pip install base58`
3. `pip install -e git+https://github.com/coinkite/python-bip32.git@iss27#egg=bip32`
4. Make your virtualenv with: `virtualenv ENV --system-site-packages`
5. `pkg install py38-secp256k1` (pulls a tragic set of dependencies)

**NOTE:** SWIG is needed to build wheel for `pyscard`. You may need to run `pkg install swig`.


## Emulator

Python code for an emulator which communicates with `cktap`
via a local Unix socket. It's provided without warranty and isn't
installed by default. `cktap` prefers to speak to the emulator
if it is running.

See [README for emulator](emulator/README.md).

# Using the Library

### SATSCARD

```python
>>> from cktap.transport import find_first
>>> card = find_first()
>>> print(card)
<CKTapCard SATSCARD: 26NKY-RWPK4-65YR7-BU4WL>
>>> card.address()
'bc1q7h0u5yn8y4pajn94ze4gnhz487c8ysvekusqj5'
```

### TAPSIGNER

```python
>>> from cktap.transport import find_first
>>> card = find_first()
>>> print(card)
<CKTapCard TAPSIGNER via EMU: 2LNJA-NIGMW-Q5AKC-KD5Q2> 
>>> card.get_xpub('123456')
'xpub6DXuQW17LykdXFyEtRrq9Z3MAegRPLAwFovT34afzK6NNHkwJrWCs4Knhrjf1U22QSSbykyzpfRsDZc9ryk9b6VUfGp89vkQw6YjY4CaEQ3'
```

# Using the CLI


## Providing CVC

Any command which reveals private key info or changes the state of
the card requires the 6-digit numeric code from the back of the
card (called _CVC_, _spend code_, or _Starting PIN Code_ on TAPSIGNER).
You can provide this on the command line, or omit it. Commands
requiring the CVC but entered without it will prompt you for the
CVC.  Some commands display limited information without the CVC.
To see more detail, include the CVC on the command line.


## Most Useful Commands

### cktap library

`cktap --version`
- Get the version of cktap library

### For SATSCARD

`cktap open`
- Opens Bitcoin Core or your other wallet by activating the BITCOIN:addr URL scheme for the current slot of the card.

`cktap qr`
- Displays deposit QR code.

`cktap unseal`
- Unseals the current slot and shows the WIF for funds sweeping.
- WIF must be imported into a blockchain-aware wallet.

`cktap balance`
- Calls a web service to get UTXO and show current Bitcoin balance.
- Uses `tord` (if running locally) to proxy the request.


### For TAPSIGNER

`cktap status`
- Shows status info.

`cktap setup`
- Tells card to pick private key (call once).

`cktap xpub`
- Shows the XPUB in effect.

`cktap backup`
- Saves the card's XPRV into an AES-128-CTR encrypted file with the current date.

`cktap change OLDPINCODE NEWPINCODE`
- Use to change the PIN on the card

`cktap path`
- Shows the derivation path in effect, by default: `m/84h/0h/0h`


## Detailed Examples

```
% cktap
Usage: cktap [OPTIONS] COMMAND [ARGS]...

  Interact with SATSCARD and TAPSIGNER cards via NFC tap.

  Command marked [TS] are only for TAPSIGNER and [SC] only for SATSCARD.

  You can use "bal", or "b" for "balance": any distinct prefix for all
  commands.

Options:
  -i, --card-ident BLAHZ-  Operate on specific card (any substring is enough)
  -w, --wait               Waits until a card is in place.
  -v, --verbose            Show traffic with card.
  --pdb                    Prepare patient for surgery to remove bugs.
  --version                Show the version and exit.
  --help                   Show this message and exit.

Commands:
  address  [SC] Show current deposit address
  backup   [TS] Backup private key from card into AES-128-CTR encrypted file
  balance  [SC] Show the balance held on all slots
  certs    Check this card was made by Coinkite: Verifies a certificate...
  chain    Get which blockchain (Bitcoin/Testnet) is configured.
  change   [TS] Change the CVC code (PIN code)
  check    Verify you have the spending code (CVC) correct.
  core     [SC] Show JSON needed to import keys into Bitcoin Core
  debug    Start interactive (local) debug session.
  derive   [TS] Change the subkey derivation path to use (shows xpub)
  dump     [SC] Show state of slot number indicated.
  json     [TS] Dump wallet values in JSON format similar to Coldcard...
  list     List all cards detected on any reader attached.
  msg      Sign a short text message
  open     [SC] Get address and open associated local Bitcoin app to...
  path     [TS] Show the subkey derivation path in effect
  qr       [SC] Show current deposit address as a QR (or private key if...
  setup    Setup with a fresh private key.
  status   Show a few things about status of card
  unlock   Clear login delay (takes 15 seconds)
  unseal   [SC] Unseal current slot and reveal private key.
  url      Get website URL used for NFC verification, and optionally open it
  usage    [SC] Show slots usage so far.
  version  Get the version of the card's firmware installed (but not...
  wif      [SC] Show WIF for last unsealed slot, or give slot number
  xpub     [TS] Show the xpub in use


% cktap list
<CKTapCard SATSCARD: 26NKY-RWPK4-65YR7-BU4WL>
<CKTapCard TAPSIGNER: RUIXK-5XI6U-G55IQ-DVGVI>

% cktap -i RUIXK status
-- TAPSIGNER Card --
Card ident: RUIXK-5XI6U-G55IQ-DVGVI
Birth Height: 723471
Number of backups: 25
Current derivation: m/84h/0h/0h

% cktap -i 26NKY status
-- SATSCARD --
Card ident: 26NKY-RWPK4-65YR7-BU4WL
Birth Height: 723597
Address: bc1q7h0u5yn8y4pajn94ze4gnhz487c8ysvekusqj5

```

### SATSCARD
```
% cktap usage
SLOT# |  STATUS  | ADDRESS
------+----------+-------------
  0   | UNSEALED | (use spend code to view)
  1   | UNSEALED | (use spend code to view)
  2   | UNSEALED | (use spend code to view)
  3   | sealed   | bc1qu4vsv2jqgl0y30ehrs4d0dg23xazpgnxdwuqum
  4   | unused   |
  5   | unused   |
  6   | unused   |
  7   | unused   |
  8   | unused   |
  9   | unused   |

% cktap usage 123456
SLOT# |  STATUS  | ADDRESS
------+----------+-------------
  0   | UNSEALED | bc1q4rdps7e8xkaat4ewmmv0hmunsu20s329tf8pdm
  1   | UNSEALED | bc1qe8q7zjtj7utsjlgsq9vn7dl6gqf7kj02tuuec6
  2   | UNSEALED | bc1q9n97zn2nwp7cdhujsgqpgqpv0z49f70lxz9ns2
  3   | sealed   | bc1qu4vsv2jqgl0y30ehrs4d0dg23xazpgnxdwuqum
  4   | unused   |
  5   | unused   |
  6   | unused   |
  7   | unused   |
  8   | unused   |
  9   | unused   |

% cktap qr -o today.svg
(SVG of QR is saved to file)

% cktap addr
bc1qu4vsv2jqgl0y30ehrs4d0dg23xazpgnxdwuqum

% cktap wif -s 1
Enter spending code (6 digits):
p2wpkh:L16cgmhZJWD7fq3eDi3gL7Yko6WYixxZi4f5T3XxxDCF2HnZdHJa
```

### TAPSIGNER

```
% cktap status
-- TAPSIGNER Card --
Card ident: RUIXK-5XI6U-G55IQ-DVGVI
Birth Height: 723471
Number of backups: 25
Current derivation: m/84h/0h/0h

% cktap backup 347634
Wrote 109 bytes to: backup-RUIXK-2022-02-16T0926.aes

% hd backup-RUIXK-2022-02-16T0926.aes
00000000  d6 3e 40 59 f0 fd 7a 3d  06 67 a5 94 0b 5d 01 09  |.>@Y..z=.g...]..|
00000010  27 58 c3 2a 1f c1 66 d9  84 84 25 96 af 71 23 a1  |'X.*..f...%..q#.|
00000020  0b bc aa ba c1 a3 98 6d  f2 cd 9c 24 51 8c f7 bf  |.......m...$Q...|
00000030  09 ad 53 0d 9b 07 2b 8e  12 be 73 24 3a 09 a9 3d  |..S...+...s$:..=|
00000040  26 6c 98 59 34 95 aa 78  a1 0b 7a 2b 77 98 1f 7a  |&l.Y4..x..z+w..z|
00000050  d1 cf d6 e6 fd 31 b3 88  1a d9 df 68 03 a3 8b 06  |.....1.....h....|
00000060  db 66 ef d6 ea 5f 5f 08  9a ed f2 2a 71           |.f...__....*q|
0000006d

```
For more information about specific `cktap` commands check `docs/cli.md`