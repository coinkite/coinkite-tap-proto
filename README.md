# Coinkite Tap Protocol and Helper Program

This python library will make it easy to talk to the TAPSIGNER and SATSCARD.

This repo includes:

1. The protocol specification
2. Python library for speaking the protocol
3. (someday) Examples/libraries in other languages

# Full Documentation

[Protocol spec](docs/protocol.md) is now public!

Related documentation can be found in [docs subdir](docs).

[Coinkite-tap-proto source code](https://github.com/coinkite/coinkite-tap-proto)

# Install

This is the python code and command-line utilities you need to communicate with it over USB.

## Setup For Everyday Use

- `pip install 'coinkite-tap-proto[cli]'`

This installs a single helpful command line program: `cktap`

If you just want the python library, use:

- `pip install coinkite-tap-proto`


## Setup If You Might Change the Code

- do a git checkout
- probably make a fresh virtual env
- run:

```
pip install -r requirements.txt
pip install --editable '.[cli]'
```

## Requirements

- python 3.6 or higher
- `pyscard` for access to smartcard readers
- a supported smart-card reader:
    - "ACS ACR1252U" is okay and widely available.
    - "Identiv uTrust 3700F" is reliable and looks nice
    - HID Omnikey 5022 CL (not 5021) is fast, cute and small.
    - "ACS ACR122U" can work, and is widely available, but is not reliable nor recommended!
    - in theory, all smartcard USB CCID class-compliant devices should work.
- see `requirements.txt` file for more details.

## Windows Notes

- to install pyscard, I needed swig installed:
    - download zip from <http://swig.org>
    - extract, move into `C:\Program Files`
    - add that to system PATH
    - test: `swig` at command prompt should work
    - then `pip install pyscard` worked

## FreeBSD Notes

- tested against 13.0-RELEASE
- need `pkg install py38-pyscard py38-coincurve` 
    - follow devfs.conf instructions
    - install usr/ports/devel/libccid
    - add `pcscd_enable="YES"` to rc.conf
- `pip install base58`
- `pip install -e git+https://github.com/coinkite/python-bip32.git@iss27#egg=bip32`
- make your virtualenv with: `virtualenv ENV --system-site-packages`
- need `pkg install py38-secp256k1` (which pulls a tragic set of dependencies)
- MAYBE: 'swig' is needed to build wheel for `pyscard`, so `pkg install swig`?

## Emulator

There is python code for an emulator which communicates with `cktap`
via a local Unix socket. It's provided without warrantee and isn't
installed by default. `cktap` will prefer to speak to the emulator
if it is running.

See [README for emulator](emulator/README.md).

# Using the Library

```python
>>> from cktap import find_first
>>> card = find_first()
>>> print(card)
<CKTapCard SATSCARD: 26NKY-RWPK4-65YR7-BU4WL> 
>>> card.address()
'bc1q7h0u5yn8y4pajn94ze4gnhz487c8ysvekusqj5'
```

# Using the CLI

## Providing CVC

Any command which reveals private key info or changes the state of
the card will require the 6-digit numeric code from the back of the
card (called CVC or "spend code", or "Starting PIN Code" on TAPSIGNER).
You can provide this on the command line, or omit it. When required,
you will be prompted for the CVC if it wasn't on the command line.
Some commands will display what information they can without the
CVC. In those cases, to see more detail, add the CVC on the command line.

## Most Useful Commands

### SATSCARD

`cktap open` 
- opens Bitcoin Core or your other wallet, by activating the BITCOIN:addr 
URL scheme for the current slot of the card.

`cktap qr` 
- displays QR code for deposit

`cktap unseal`
- unseals the current slot and shows the WIF for funds sweeping
- you will require a blockchain-aware wallet to import that WIF into

`cktap balance`
- calls a webservice to get UTXO and show current Bitcoin balance
- if you have `tord` already running locally, it will be used to proxy the request

### TAPSIGNER

`cktap status`
- show info about state

`cktap setup`
- causes card to pick private key (call once)

`cktap xpub`
- show the XPUB in effect

`cktap backup`
- save card's XPRV into AES-128-CTR encrypted file with today's date

`cktap change OLDPINCODE NEWPINCODE`
- change the PIN on the card

`cktap path`
- show the derivation path in effect, by default: `m/84h/0h/0h`


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
  --help                   Show this message and exit.


Commands:
  address   [SC] Show current deposit address
  backup    [TS] Backup private key from card into AES-128-CTR encrypted...
  balance   [SC] Show the balance held on all slots
  certs     Check this card was made by Coinkite: Verifies a certificate...
  chain     [SC] Get which blockchain (Bitcoin/Testnet) is configured.
  change    [TS] Change the CVC code (PIN code)
  check     Verify you have the spending code (CVC) correct.
  core      [SC] Show JSON needed to import private keys into Bitcoin Core
  debug     Start interactive (local) debug session.
  derive    [TS] Change the subkey derivation path to use
  dump      [SC] Show state of slot number indicated.
  json      [TS] Dump wallet values in JSON format similar to Coldcard...
  list      List all cards detected on any reader attached.
  msg       Sign a short text message (TODO -- INCOMPLETE)
  open      [SC] Get address and open associated local Bitcoin app to...
  path      [TS] Show the subkey derivation path in effect
  qr        [SC] Show current deposit address as a QR (or private key if...
  setup     Setup with a fresh private key.
  status    Show a few things about status of card
  unlock    Clear login delay (takes 15 seconds)
  unseal    [SC] Unseal current slot and reveal private key.
  url       Get website URL used for NFC verification, and optionally...
  usage     [SC] Show slots usage so far.
  version   Get the version of the card's firmware installed (but not...
  wif       [SC] Show WIF for last unsealed slot, or give slot number
  xpub      [TS] Show the xpub in use

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
