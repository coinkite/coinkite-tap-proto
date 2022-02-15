# Coinkite Tap Protocol and Helper Program

This python library will make it easy to talk to the TAPSIGNER and SATSCARD.

This repo includes:

1. The protocol specification
2. Python library for speaking the protocol
3. (maybe) Examples/libraries in other languages

# Protocol Spec

See files in <./docs>.

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
- `pyscard` for acceess to smartcard readers
- a supported smart-card reader:
    - "ACS ACR1252U" is better and also available.
    - "Identiv uTrust 3700F" is reliable and looks nice
    - HID Omnikey 5022 CL (not 5021) is fast, cute and small.
    - "ACS ACR122U" can work, and is widely available, but is not recommended!
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
- need `pkg install py38-secp256k1` (which pulls a tragic set of dependancies)
- MAYBE: 'swig' is needed to build wheel for `pyscard`, so `pkg install swig`?

# Using the Library

```python
from cktap.transport import CKTapCard
card = CKTapCard.find_first()
print(card.address())
```

# Using the CLI

## Providing CVC

Any command which reveals private key info or changes the
state of the card will require the 6-digit numeric code
from the back of the code (called CVC or "spend code"). You can
provide this on the command line, or omit it. If required, you
will be prompted for the CVC. Some commands will display
what information they can without the CVC. To see more, add the code
on the command line

## Most Useful Commands

`cktap open` 
- opens Bitcoin Core or your other wallet, by activating the BITCOIN:addr 
URL scheme for the curent slot of the card.

`cktap qr` 
- displays QR code for deposit

`cktap unseal`
- unseals the current slot and shows the WIF for funds sweaping
- you will require a blockchain-aware wallet to import that WIF into

## Examples

```
% cktap 
Usage: cktap [OPTIONS] COMMAND [ARGS]...

Options:
  -u, --uid HEX  Operate on specific card (default: first found)
  --help         Show this message and exit.

Commands:
  addr     Show current deposit address
  chain    Get which blockchain (Bitcoin/Testnet) is configured.
  check    Check you have the spending code correct.
  core     Show JSON needed to import private keys into Bitcoin Core
  debug    Start interactive (local) debug session
  dump     Show state of slot number indicated.
  list     List all cards detected on any reader attached
  msg      Sign a short text message
  open     Get address and open associated bitcoin app to handle
  qr       Show current deposit address as a QR
  setup    Setup a new slot with a private key.
  unseal   Unseal current slot.
  usage    Show slots usage so far
  version  Get the version of the card's firmware installed (not upgradable)
  wif      Show WIF for last unsealed slot, or give slot number
```

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
