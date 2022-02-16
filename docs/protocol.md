# Coinkite Tap Cards Protocol

## Background

This document describes the protocol for both the SATSCARD and
TAPSIGNER products. They share much of the same code, although their
usage and security model is very different.

- the card implements ISO-7816 protocol for operations, and emulates an NFC tag
- RF protocol is ISO/IEC 7816-4:2020 and/or ISO/IEC 14443-A
- mobile app will send APDU requests and get responses
- body of APDU will be CBOR serialized mappings, as documented here
- only one specific APDU CLS/IN for our application (0x00/0xCB)
- NFC response can be dynamic, always contain a single URL, and the URL prefix
  is set at factory and not change in field. Please see `nfc-spec.md` for details.

## Design Principals

- Private keys, when sent over the air, are encrypted by the session key (XOR).
- For the SATSCARD, the full deposit address is not shown in full, so that client
  apps must do the crypto work that legitimately verifies operation of the card.
- The TAPSIGNER is meant to be general-purpose BIP-32 based key signer, but would
  probably be used as a multisig co-signer or as a "hardware wallet"-like product.

## Message encoding

- we will use [CBOR](https://cbor.io/) to frame and encode data in both directions.
- the CBOR message will be written using a APDU's data field, and the reply is CBOR as well.
    - `CLA=0x00 INS=0xCB`
    - length varies based on CBOR content
- there is only one APDU implemented, all parameters and subcommands will be done in CBOR data structure

## Testnet Support

For test and development purposes, when a card is first setup it
can be marked as operating on Testnet rather than the default of
Bitcoin Mainnet. This affects the addresses because it is rendered
with a different HRP (human readable part). On testnet, addresses
start with "tb1" rather than "bc1". Testnet can only be enabled
in the factory when the card is being born.

## TAPSIGNER Differences (vs. SATSCARD)

- same CBOR command protocol, but a few additional commands/changes
- only one slot so omit `slot` parameter to commands
- option to use arbitrary derivation for slot's key, on SATSCARD forced to be: `m/0` 
- key material can be backed-up off-card via a AES encrypted backup command
- no unsealed/sealed concept, single slot effectively in `new` or `sealed` mode
- only way to get to private key is via backup command
- the derived address defaults to `m/84h/0h/0h` rather than `m/0`, after a `new` command
- can change CVC as desired to any 6 to 32 byte string

## Status Response

To start, the app must start by getting the current status of the card:

```python
{ 
    'cmd': 'status',          # command code
}
```

The card will reply with:

```python
{ 
    'proto': 1,                     # (int) version of CBOR protocol in use (ie. this document)
    'ver': '1.1.0',                 # firmware version of card itself
    'birth': 700553,                # card birth block height (int) (fixed after production)
    'slots': (0, 10),               # tuple of (active_slot, num_slots)
    'addr': 'bc1qsqu64khv___qf735wvl3lh8'   # payment address, middle chars blanked out with 3 underscores
    'pubkey': (33 bytes)            # public key unique to this card (fixed for card life) aka: card_pubkey
    'card_nonce': (16 bytes),       # random bytes, changed each time we reply to a valid cmd
}
```

This is a "mapping" in CBOR. Keys are simple, short strings to save space. Order is not defined.

If this card is for development purposes, then it will **also** have a `testnet=True` field.
That field is not provided if false.

If there have been a number of authentication failures (ie. wrong CVC),
then a field `auth_delay` is added. It holds an integer: the number
of seconds of delay required before any authenticated command can
proceed. Each attempt at such a command will fail with
429 (rate limited) until this delay is consumed using the `wait` command.

The current slot could be "new" (no key picked yet) or "sealed". The current slot will never
be unsealed. When the card is completely consumed, then `active_slot == num_slots`.
When the current slot is "new" (ie. not yet used), the "addr" field is not provided (omitted).


### TAPSIGNER differences

Fields `slots`, and `addr` are removed, and a field `tapsigner=True` is added.

An additional field: `path` (a short array of integers)
is added, which is the current subkey derivation in effect. It encodes a BIP-32
derivation path, such as
`m/84h/0h/0h`, which would be a typical value for segwit usage, although the value
is controlled by the wallet application. That field is only
present if a master key has been picked (ie. setup is complete).

Each time the backup command is used, the `num_backups` value increments (up to a maximum
value of 127).

Here's an example response:

```python
{ 
    'proto': 1,                     # (int) version of CBOR protocol in use (ie. this document)
    'ver': '1.1.0',                 # firmware version of card itself
    'birth': 700553,                # card birth block height (int) (fixed after production)
    'tapsigner': True,              # product is TAPSIGNER, not SATSCARD
    'path': [(1<<31)+84, (1<<31), (1<<31)]     # user-defined, will be omitted if not yet setup
    'num_backups': 3,               # counts up, when backup command is used
    'pubkey': (33 bytes)            # public key unique to this card (fixed for card life) aka: card_pubkey
    'card_nonce': (16 bytes),       # random bytes, changed each time we reply to a valid cmd
}
```

## Read Payment Address or Derived Pubkey

To learn the current payment address (or for TAPSIGNER: the derived pubkey),
the app will have to write a CBOR message like this:

```python
{ 
    'cmd': 'read',          # command
    'nonce': (16 bytes),    # provided by app, cannot be all same byte (& should be random)
    'epubkey': (33 bytes)      # (TAPSIGNER only) auth is required
    'xcvc': (6 to 32 bytes),   # e(TAPSIGNER only) auth is requiredncrypted CVC value
}
```

The card will calculate a signature and respond with:

```python
{
    'sig': (64 bytes)          # signature over a bunch of fields using private key of slot
    'pubkey': (33 bytes)       # public key for this slot/derivation
    'card_nonce': (16 bytes)   # new nonce value, for NEXT command (not this one)
}
```

The signature will be created from the digest (SHA256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from read command - 16 bytes)
(slot - 1 byte)
```

The key used to sign this is the active slot's private key. The command
fails if the current slot is empty.

The companion app must verify the signature against the provided
public key. For SATSCARD, it is then mapped to a segwit Bech32 address, and the
leading/final characters verified against the `addr` field.  The
previously unknown middle digits are thus calculated.

For TAPSIGNER, this command operates on the derived pubkey
set earlier. It provides the card knows the private key for indicated
derivation in effect. Authentication is required, and bytes 1 thru 33 of
the pubkey will be XOR'ed with the session key.

Effectively there is a nonce from both parties, so that neither
can replay a previous response: the `card_nonce` from the card,
and the `nonce` from the app.

## SATSCARD: Check Derivation Command

To verify the users' entropy was used in picking the private key,
we can show that entropy and provide our master public key. The `derive`
command can be used, with additional math on the part of the app,
to derive the payment address and verify it follows from the chain code
and master public key.


```python
{ 
    'cmd': 'derive',        # command
    'nonce': (16 bytes),    # provided by app, cannot be all same byte (& should be random)
}
```

The card would provide this response, as follows:

```python
{
    'sig': (64 bytes)         # signature over a bunch of fields using private key of slot
    'chain_code': (32 bytes)  # the nonce provided by customer when this slots's privkey was picked
    'master_pubkey': (33 bytes)       # master public key in effect
    'card_nonce': (16 bytes)  # new nonce value, for NEXT command (not this one)
}
```

Note the derivation is fixed as `m/0`, meaning the first non-hardened
derived key. SATSCARD always uses that derived key as the payment address.

The signature will be created from the digest (SHA256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from command - 16 bytes)
(chain_code - 32 bytes)
```

The signature is signed by by what we call the `master_pubkey` for the slot.

To complete the verification process, the app must verify the
`master_pubkey` using the signature. Using that pubkey, and the
chain code, the app can reconstruct a BIP32 "xpub" (extended public key).

The payment address shared by the card (ie. the slot's `pubkey`)
must equal the BIP-32 derived key (`m/0`) constructed from that
xpub.

## TAPSIGNER: Perform Subkey Derivation Command

The `derive` command on the TAPSIGNER is used to perform hardened
BIP-32 key derivation. We expect wallets to use it to derive the
BIP-44/48/84 prefix of the path, and that value is captured and
stored long term. You can view this as calculating the XPUB to be
used on the mobile wallet.


```python
{ 
    'cmd': 'derive',        # command
    'path': [...],          # derivation path, can be empty list for `m` case (a no-op)
    'nonce': (16 bytes),    # provided by app, cannot be all same byte (& should be random)
    'epubkey': (33 bytes)      # app's ephemeral public key
    'xcvc': (6 to 32 bytes),   # encrypted CVC value
}
```
The card would will calculate the derived key and provide a response, as follows:

```python
{
    'sig': (64 bytes)         # signature over a bunch of fields using derived private key
    'chain_code': (32 bytes)  # chain code of derived subkey
    'master_pubkey': (33 bytes)       # master public key in effect (`m`)
    'pubkey': (33 bytes)       # derived public key for indicated path
    'card_nonce': (16 bytes)  # new nonce value, for NEXT command (not this one)
}
```

The signature will be created from the digest (SHA256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from command - 16 bytes)
(chain_code - 32 bytes)
```

The wallet app is able to choose the most appropriate derivation
for their design. However, it cannot contain unhardened components.
The derivation path will be remembered and reported in the `status`
command response, but may be changed at will.

The path is provided as a sequence of 32-bit unsigned integers. The
MSB must be set on all these values as only hardened derivations
are supported here.

If not provided, the existing derivation
path is unchanged by this command. Authentication is required.


## Check Authenticity Command

This command is used to verify the card was made by Coinkite and
is not counterfeit. Two requests are needed: first fetch
the certificates and then provide a nonce to be signed.


```python
{ 
    'cmd': 'certs',         # command
}
```

The card would then provide this response:

```python
{
    'cert_chain': (signature, .. )   # list of certificates, from 'batch' to 'root'
}
```

The above response is static for any particular card. The values were captured during
factory setup time. Each entry in the list is a 65-byte signature. The first signature
was used to sign the card's public key, and each following signature signs the public key
used in the previous signature.
(Only planning on 2 levels of signatures here, but could be more.)

Next step is for the app to provide a nonce to be signed.

```python
{ 
    'cmd': 'check',         # command
    'nonce': (16 bytes)     # random value from app
}
```

The card would then provide this response:

```python
{
    'auth_sig': (64 bytes)         # signature using card_pubkey
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

The `auth_sig` value is a signature made using the card's public key (`card_pubkey`).

The signature will be created from the digest (SHA256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from check command - 16 bytes)
```

To prove it is talking to a genuine Coinkite card, the app
must verify this signature, and check public key used was the
`card_pubkey`.  Then the signatures in each element of the certificate
chain must be verified by recovering the pubkey at each step.  We
are checking the batch cert is signing the card's pubkey, and that
the root cert is signing the batch cert's key (and so on). The
expected pubkey of the root certificate must be shared out-of-band
and known to the app beforehand.

### Notes

- the first byte of each signature is the `rec_id` encoded accordance
to [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
- if it's in range 39..42, subtract 39 to get `rec_id` in range [0..3]
- if it's in range 27..30, subtract 27 to get `rec_id` in range [0..3]
- other values should not occur

## Authenticated Commands (with CVC)

To prove the caller knows the CVC value, we will require the CVC
to be sent with each command that requires authentication. The value
itself is encrypted using the pubkey of the specific card, as follows:

- app picks an ephemeral key-pair (on secp256k1)
- reads pubkey of card (fixed value, shared everytime) and current `card_nonce` value (see status command)
- multiply ephemeral private key by the card's pubkey, hash result with SHA256
    - this is normal [ECDH key agreement](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
    - which yields a shared secret key (point on curve)
    - in this applicaiton, the hashing step, includes a byte for the Y parity,
      see [libp256k1 code here](https://github.com/bitcoin-core/secp256k1/blob/185a6af22792531a629959834fff9257e396abb5/src/modules/ecdh/main_impl.h#L13-L24) and some libraries may hash
      only the X component which will not work.
    - result is the `session_key` (32 bytes)
- take the CVC value provided by user and XOR with (`session_key` XOR sha256(`card_nonce` + `command_name`))
    - CVC will be serialized as ASCII, and for the SATSCARD the factory chooses
      a 6-digit CVC, so leading 6 bytes will be the result in `xcvc`
    - `command_name` is the command being authenticated (short string, like `unseal`)
- the app's ephemeral public key, and encrypted CVC value are sent with
  each request that needs it.
- the app cannot reuse both values on subsequent requests because the `card_nonce`
  changes, affecting `xcvc`. However, it's free to re-use the `session_key`,
  if it provides the same `epubkey` value again, provided the same command is being executed.

Authenticated commands will have these two fields in addition to any
other parameters needed for the command:

```python
{
    'epubkey': (33 bytes)      # app's ephemeral public key
    'xcvc': (6 to 32 bytes),   # encrypted CVC value
}
```

A new `card_nonce` will be provided in the response. That's the nonce needed for
subsequent commands, not the one underway.

### CVC Length & Content

For the SATSCARD, the CVC will be 6 numeric digits. However,
in subsequent versions, we may expand this up to 32 bytes, and the bytes could
be ASCII or other values. Please treat the CVC as a byte sequence of 6 to 32 bytes.
The length of `xcvc` (encrypted CVC) must match the length of the CVC defined at
the factory setup time (and printed on back of card).

For TAPSIGNER, the initial CVC is printed on the back of the card,
but can be changed in the field. It can be any length from 6 to 32
bytes as prefered by the user.

### Authentication Failures

If the wrong CVC value is provided your command will fail with error 401 (bad auth).
You may immediately retry with a different CVC value 2 more times. After that
you will need to wait 15 seconds between attempts, as any attempt will fail
and return 429 (rate limited) error. See the status value `auth_delay`
to know how much more waiting is required using the `wait` command.
Once the delay has been provided, you 
may try the CVC value again, and if correct, normal operation proceeds. If
incorrect, you will again need to wait 15 seconds before your next attempt.

## New Slot

On the SATSCARD, to pick a new private key and start using a fresh
slot, you need this command. It cannot be performed if the current
slot is still sealed.

For the TAPSIGNER, this command is used one-time only.

```python
{ 
    'cmd': 'new',             # command
    'slot': 3                 # (optional: default zero) slot to be affected, must equal currently-active slot number
    'chain_code': (32 bytes)  # app's entropy share to be applied to new slot (optional on SATSCARD)
    'epubkey': (33 bytes)     # app's ephemeral public key
    'xcvc': (6 bytes),        # encrypted CVC value
}
```

The slot number is included in the request to prevent command replay. 

At this point:

- if no new slots available, abort and fail command.
- a new key-pair is picked and stored into new slot
    - the `chain_code` must be used in that process, and stored
    - card will using TRNG to pick a new `master_pubkey` (pair)

The new values take effect immediately, so some fields of the
next status response will have new values.

Response will be as follows:

```python
{
    'slot': 3                      # slot just made
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

There is a very, very small (`1 in 2**127`) chance of arriving at an invalid
private key. If that occurs, error 205 (unlucky number) is returned and you can
retry immediately. Also buy a lottery ticket immediately.

For the SATSCARD, the derived address will always be generated based
on `m/0` and on the TAPSIGNER, the default derivation path of
`m/84h/0h/0h` is used. In either case `status` and `read` commands
will be required to learn the details of the new address/key.

## Unseal Slot (SATSCARD Only)

To unseal the current slot, send this data:

```python
{ 
    'cmd': 'unseal',          # command
    'slot': 3                 # slot to be unsealed, must equal currently-active slot number
    'epubkey': (33 bytes)     # app's ephemeral public key
    'xcvc': (6 bytes),        # encrypted CVC value
}
```

Note the slot number is included in the request to prevent command replay. Only the current
slot can be unsealed.

The response will be as follows:

```python
{
    'slot': 3               # slot just unsealed
    'privkey': (32 bytes)   # private key for spending
    'pubkey': (33 bytes)    # slot's pubkey (convenience, since could be calc'd from privkey)
    'master_pk': (32 bytes)      # card's master private key
    'chain_code': (32 bytes)     # nonce provided by customer
    'card_nonce': (16 bytes)     # new nonce value, for NEXT command (not this one)
}
```

`chain_code` and `master_pk` were established much earlier when the privkey for this 
slot was picked. `chain_code` was picked by customer (or previous slot's chain
code is recycled). `master_pk` is the entropy added by the card.

The private key is encrypted by XOR with the session key. The other values are shared unencrypted.

After a slot is unsealed, state is updated but no new key is picked
yet. You must do the `new` command to start using the card again.
Active slot number is increased by one, and unless the card is fully
consumed, points at the next unused slot.

## Data Dump (SATSCARD Only)

Reveals details of all previous slots at once. Does not affect current slot.
This is a no-op in terms of response content if no slots yet, or if slot is
not yet unsealed (ie. an empty list). It can be used by the factory to verify
the CVC value is printed correctly without side effects.

```python
{ 
    'cmd': 'dump',              # command
    'slot': 0,                  # which slot to dump, must be unsealed.
    'epubkey': (33 bytes)       # app's ephemeral public key (optional)
    'xcvc': (6 bytes),          # encrypted CVC value (optional)
}
```

If the `epubkey` or `xcvc` is absent, the command still works, but the only
information shared about an unsealed slot is status (sealed/unused/used).

Incorrect auth values for `xcvc` should fail as normal.

Response for a slot that is used, and if XCVC is provided, would be:

```python
{
    'slot': 0,                     # which slot is being dumped
    'privkey': (32 bytes)          # private key for spending (for addr)
    'chain_code': (32 bytes)       # nonce provided by customer originally
    'master_pk': (32 bytes)        # master private key for this slot (was picked by card)
    'tampered': (bool)             # flag that slots unsealed for unusual reasons (absent if false)
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

The private keys are encrypted by XOR with the session key. The other
values are shared unencrypted.

The `tampered` field will only be present (and True) if the slot
became unsealed due to confusion or uncertainity about its status.
In other words, if the card unsealed itself rather than via a
successful `unseal` command.

If the XCVC (and/or `epubkey`) is not provided, then the response contains 
the full payment address and indicates that it's been unsealed:

```python
{
    'slot': 0,                     # which slot is being dumped
    'sealed': False,
    'addr': 'bc1qsqkhv..qf735wvl3lh8'   # full payment address
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```


For a slot that is unused, the response is just:

```python
{
    'slot': 0,                     # which slot is being dumped
    'used': False,
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

For the currently-active slot, the response is:

```python
{
    'slot': 3,                     # which slot is being dumped
    'sealed': True,
    'addr': 'bc1qsqu64khv___qf735wvl3lh8'   # payment address, middle chars blanked out with 3 underscores
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

## Read NFC URL

When tapped on a phone that knows how to read NFC tags, the card will
provide a unique, dynamic URL. This command can be used to simulate that
and read the URL directly.

```python
{ 
    'cmd': 'nfc',             # command
}
```

Response is simply the URL needed:

```python
{
    'url': 'example.com/path#dynamicstuff',      # URL 
}
```

You must add `https://` as a prefix to that value. `http` is not
supported. The details required to decode the URL are in `nfc-spec.md`.


## Change CVC (TAPSIGNER only)

Users of the TAPSIGNER may change the CVC from the value printed on the
card. This protects against theft when the owner's wallet is "borrowed".

The new CVC may be 6 to 32 bytes long. It is encrypted (XOR) by the session key.

The card have must been backed-up at least once before this command
is accepted (error code 425).

```python
{ 
    'cmd': 'change',            # command
    'data': (6 to 32 bytes),    # new CVC, encrypted
    'epubkey': (33 bytes)       # app's ephemeral public key (required)
    'xcvc': (6 bytes),          # encrypted CVC value (required)
}
```

Response is simple:

```python
{
    'success': True
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

New value takes effect immediately, and there is no recovery method if forgotten.
The factory-defined CVC is forgotten.

For compatibility between wallets, we recommend using ASCII only
and perhaps only digits. However, if desired, it could be a 32-byte
hash of the true password value instead.


## Dump XPUB (BIP-32 serialized) (TAPSIGNER only)

Provides the current XPUB, either at the top level (master)
or the derived key in use (see 'path' value in status response).

```python
{ 
    'cmd': 'xpub',              # command
    'master': (boolean),        # give master (`m`) XPUB, otherwise derived XPUB
    'epubkey': (33 bytes)       # app's ephemeral public key (required)
    'xcvc': (6 bytes),          # encrypted CVC value (required)
}
```

Response is simple:

```python
{
    'xpub': (78 bytes)    # BIP-32 serialized, but not yet Base58 encoded
}
```

The response is ready to be used and should not require any processing.
The XFP (extended fingerprint) can be calculted from the public key
at master level: 4 bytes from HASH160(master pubkey).

## Card Backup (TAPSIGNER only)

To protect against loss or destruction of the card, the user may
backup the contents of the master private key. This output is always
AES-128-CTR encrypted using a fixed key that is printed in hexidecimal
on the back of the card.

A counter is updated each time this command is executed, visible
as `num_backups` in the status response.

```python
{ 
    'cmd': 'backup',            # command
    'epubkey': (33 bytes)       # app's ephemeral public key (required)
    'xcvc': (6 bytes),          # encrypted CVC value (required)
}
```

Response is simply the data to save long-term.

```python
{
    'data': (bytes),            # encrypted data to be preserved
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

The 'data' field is a small text file, encrypted by AES-128-CTR
using zero as IV, and the key from the back of the card (128 bits).

Inside the encryption, two lines are defined (so far, additional
lines of data may be exported in future versions):

1. XPRV for master secret encoded in Base58
2. Current derivation path in effect

Example:
```
XPRV.... 
m/84h/0h/0h
```

The data can be viewed with `openssl aes-128-ctr -iv 0 -K HEX-on-back-of-card`.
Future versions of the product may include additional values in this response.

From the master XPRV any key produced by the card can be reconstructed.
The card will also capture the current derivation path (from `derive`
command).  For a complete backup, output scripts, address types
should also be captured, but for standardized usage (ie. BIP
compliant), that can be implied by the derivation path itself.

This command will fail with 406 (invalid state) if no key is yet picked.

There is no "restore" command. To make use of the backed-up data,
you must do the signing external to the card.


## Create Signature

In the SATSCARD, for slots that are already unsealed, it's handy
if we can create an arbitrary signature.  Since the private key is
"known", the app could do this itself, but it's convenient if it
doesn't have to be contaminated with private key information. We
see this being used both for spending and multisig-wallet operations.

On the TAPSIGNER, this is the core feature: signing an arbitrary
message digest based on a tap. Once setup (key picked) it's always
a valid command.

```python
{ 
    'cmd': 'sign',              # command
    'slot': 0,                  # (optional) which slot's to key to use, must be unsealed.
    'subpath': [0, 0],          # (TAPSIGNER only) additional derivation keypath to be used
    'digest': (32 bytes)        # message digest to be signed
    'epubkey': (33 bytes)       # app's ephemeral public key
    'xcvc': (6 bytes),          # encrypted CVC value
}
```

The digest will be encrypted by XOR with `session_key` since modifing that in-flight
would be a big problem.

Response would be:

```python
{
    'slot': 0,                  # which slot was used
    'sig': (64 bytes)           # signature
    'pubkey': (33 bytes)        # public key of this slot
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

The signature is not encrypted. `pubkey` field can be verified against signature.

### Signing Notes

- the signature is non-deterministic (K) and a low-R and low-S value is always provided
- however, to achieve that, multiple K values may be used, and if more than a few
  attempts have been made without success, an error (205=Unlucky Number) is returned.
- you can and should immediately retry the command to start over with better luck
- the odds of this occuring are 1 in 8 (based on 3 retries, internal to the card)

### TAPSIGNER: Subpath values

- `subpath` field is optional (default: empty array) but will typically be used
  to specify the specific sub-address. By convention the first number is 0 or 1, where
  one indicates "change" and zero indicates "deposits". The second component is
  the subkey number and should increase with each key used.
- the subpath derivation is applied only for this signature, and does not affect the
  derivation already in effect.
- you cannot specify a full path here, it must be relative to existing derivation and
  must be unhardened.
- subpath maybe be zero, one or two items long.


## Wait for Unlock Command

Invalid CVC codes will cause 401 errors (bad auth), up to 3 times.
After the third incorrect attempt, a 15-second delay is required,
any further attempts to authenticate will return 429 (rate limited)
until that's completed.

When it's in rate-limiting mode, the status command will return
`auth_delay` field with a positive value.

The `wait` command takes one second to execute, and reduces the
`auth_delay` by one unit. Typically you'll need to execute 15 of
these commands before re-trying a CVC code.

```python
{ 
    'cmd': 'wait',            # command
    'epubkey': (33 bytes)       # app's ephemeral public key (optional)
    'xcvc': (6 bytes),          # encrypted CVC value (optional)
}
```

Response would be:

```python
{
    'success': True             # command result
    'auth_delay': (integer)     # how much more delay is now required.
}
```

If `auth_delay` is already zero, you may provide CVC value, and
they will be tested. This is provided to CVC value can be tested
without side effects.


## Error Responses

We should use the APDU error codes that apps will be expecting.
There is usually no information to be provided anyway. When we can,
then the body that goes along with the response should be a CBOR
dictionary as follows:

```python
{
    'error': 'short message text',       # error message (English)
    'code': 400,                         # integer, 3 digits
}
```

Additional fields can be provided when details are needed for
handling the error but none are presently defined.  Clients should
ignore all other fields if they don't understand the value.  The
error message is useful for debugging, but is not meant for end-users.
Your code should look at the number in `code` in order to decide
what to do.

All succesful commands must return SW of 0x9000 at the ISO-7816
level. Any other return value indicates communications problem or
an issue with some other layer of software.

### List of Errors

Code | Text                  | Meaning
-----|-----------------------|--------
205  | `unlucky number`      | Rare or unlucky value random value was used/occured. Start again.
400  | `bad arguments`       | Invalid/incorrect/incomplete arguments provided to command.
401  | `bad auth`            | Authentication details (CVC/epubkey) are wrong.
403  | `needs auth`          | Command requires auth, and none was provided.
404  | `unknown command`     | The "cmd" field is a command we don't support
405  | `invalid command`     | Command is not valid at this time, no point retrying.
406  | `invalid state`       | You can't do that right now when card is in this state.
417  | `weak nonce`          | Nonce is not unique-looking enough
422  | `bad CBOR`            | Unable to decode CBOR data stream
425  | `backup first`        | Cant change CVC without doing a backup first (TAPSIGNER only)
429  | `rate limited`        | Due to auth failures, delay required.

These codes are similar to HTTP error codes, but only a little.

# Certificates

Opendime USB uses a proper X.509 certificate chain, but in this
product, we will use normal Bitcoin signatures over the indicated
values and not store any more than needed. The chain will be:

- Root factory certificate. Ultra secret. Used offline only to sign batch certificates.
- Each laser-etcher in the factory uses a different batch certificate (potentially each day).
- These batch certs will be rotated, and could be revoked if we had a security issue.
- Each card picks a "card" key-pair and provides the public key to the factory production system
  which will sign that using the current batch certificate.
- Card will sign (some known text) and offer that signature as the lowest level certificate.

It's important the verification steps are implemented in the reference
clients. Experience has shown that devs will not bother to implement
the verification steps. The consequence is that fraudulent devices
can be fielded by third parties when they are used with those weaker apps.

## Comments

- Since creating a signature takes 300ms, I don't want to perform
two signature operations in a single request. If we could, I would
include the auth signature in the "read" response and maybe even force
them to unravel it somehow there.

- The protocol allows a variable number of certificates in the chain. For now
this will be always two: root and batch. Future products might use more however.

# Private Key Picking (SATSCARD Only)

The customer can provide their own 32-bytes of entropy into the key
picking process, called the "chain code". At the factory, we will
use the birth-block hash as this entropy value for the SATSCARD.

The card will use the previous slot's `chain_code` value if no value
is provided by the app when subsequent slots are used. That does
not weaken security since the card always picks fresh random value
for its master private key.

The card picks a new random key-pair for each slot when the slot
is created. There will be no relation between slots of these
"master private key".

The payment address, and the keypair it corresponds to is calculated
in a manner that is compatible with
[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
The user-provided 32-byte value is the chain code, and the slot's
master public key is mixed together using HMAC-SHA512, to derive
the `m/0` subkey. This is the only subkey this project will use.

Unlike previous OPENDIME designs, the customer can be verify their
entropy was used in the private key before unsealing the slot. We are
not using the derivation features of keypaths from BIP32 however.

## Private Key Picking (TAPSIGNER Only)

TAPSIGNER cards ship with no private key picked. The customer must
provide a `chain_code` value (32 bytes) and can verify it was used.

The card picks a new random key-pair using the internal TRNG.

The user is free to change derivation path during the life of the card.

## Invalid Key

In the extremely unlikely case that the BIP-32 derivation process
produces an invalid private key, the card will save the values
discovered and unseal the slot. A unique error code will be provided
to the caller. The odds of this code path being executed are less
than 2^128.

# Notes

## Card Nonce

The purpose of the `card_nonce` value is replay protection. We don't want
commands to be repeated if they are eavesdropped. It's always picked at random
by the card itself, no need to store it long-term.

For commands that "consume" the nonce, a new one is provided in the
response. That nonce is the value that will be used in the _next_
command, not the one that just occurred.

If the app gets confused, it can always do a status command and
re-read the current nonce, which would be needed for following commands.

One concern: if the card is moved in and out of the RF field between
commands, the nonce will change because it's volatile. We consider
that a good thing. The mobile app should probably be doing a sequence
of commands as quickly as possible anyway.

Although apps are free to query the `card_nonce` from the status
response on each command, better-quality apps that use the nonce
provided in the responses will be faster and resist any commands
being inserted into their communications.

## Install-Time Actions (Background Information)

When the java applet is first installed it will:

- pick a key-pair and save forever (the card's pubkey is shared in status response)
- pubkey part of that needs to get signed by factory system, to define `auth_cert` value
- setup as zero slots, with none unsealed yet.

At the factory, we will:

- sign the card pubkey, write certificates for card, batch and factory-root.
- pick a CVC and save it forever
- set the birth height, NFC URL
- for SATSCARD:
    - set birth block hash (used as chain code)
    - choose the first private key (slot zero)
    - calculate the payment address (bech32/segwit) and print the QR for that onto back of card
- for TAPSIGNER: 
    - calculate the `card_ident` value for NFC response
    - pick an AES key for backup file encryption
- CVC and other details written to back side of card.

## Encoding Notes

- all public keys are compressed. First byte is 0x02 or 0x03 to
  indicate the parity of the Y value. That's followed by 32 bytes of X.
- private keys are raw 32 byte values. The are a BE256 value, less than
  order of the curve and not zero.
- although we could support varying length nonce values, we will raise an error
  if a too-short or too-long nonce is provided.
- a nonce value from the app with all bytes the same, is not allowed (raises an error). It
  could still be a hard-coded value, or easily predicted value (counter), which is
  poor design on the part of the mobile app... but it's not practical for us to detect that.
- when blanking a segwit address, three underscores are to be placed in the
  middle, and 12 characters from each end are preserved.
- derivation paths always:
    - are integers in an array not string
    - hardened components have MSB set (`1<<31`)
- all cards (either type) have a unique pubkey, which we map into human-readable hash, thusly:
    - sha256(compressed-pubkey=33-bytes)
    - skip first 8 bytes of that (because that's revealed in NFC URL)
    - base32 and take first 20 chars in four groups of five chars
    - insert dashes between groups
    - result is 23 chars long
    - see `cktap.utils.card_pubkey_to_ident` for code

### Signature Values

- signatures are always 64 bytes: 32 bytes of R and then 32 bytes of S value. Not DER encoded.
- [BIP-62 requirements for "low S" must be met](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures)
- non-deterministic K value will be used in all signatures because these cards cannot do
  [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) signatures.
- high S values are always converted by the card when they occur so they don't cause issues
- for the 'sign' command, we must grind to get a positive R value. This means re-trying
  with a new K value if the signature produces a negative R value (50% chance).
    - but the card only re-tries afew times (3), and then stops with 205 (unlucky number)
    - same command+args can be immediately re-used to continue search
    - one in eight odds of this case happening, so you do have to handle it
    - does not indicate anything other that poor luck! not an error.
- [more about signatures and sizes here](https://b10c.me/blog/006-evolution-of-the-bitcoin-signature-length/)
- signatures used in the "certificate chain" are 65-byte recoverable signatures

## Extensibility

We may add parameters to existing commands, so the card must ignore
any unexpected argument that occurs with an incoming command, to
enable forwards compatibility.

Unknown commands should fail with error 404.

## Security Notes

- all public keys received from outside the card **MUST** be verified as legit
  public keys that are on the right curve.

- failed authentication (ie. CVC provided, but it's wrong) must not be treated the
  same as missing authentication (which is permitted in some commands).


---

# "Tapsigner" Variant

This is a slightly different version/mode of the firmware:

- same CBOR command protocol
- only one slot
- a few additional commands
- different branding: called "TAPSIGNER"
- option to use arbitrary derivation for slot's key, not just `m/0`
- key material can be backed-up off-card via a new command
- no more unsealed/sealed concept 
- only way to get to private key is via backup command

## System Changes

- a single slot:
    - `slots` removed from status command (always would be `(0,1)`)
    - for commands that take a `slot` argument, it is optional and forced to zero
- the "sign digest" command is accepted while the slot is still sealed (CVC required)
- "unseal" command is not implemented
- the factory will not pick first slot, and cards shipped blank in that sense.
- a 16-byte hex value (128-bit key) for AES will be printed on outside of card, and
  programmed at factory (backup file encryption key)
    - XPRV of slot's master key can be exported using AES-128-CTR encrypted w/ that key
- new concept of `card_ident` value
    - simply: `SHA256(card_pubkey)`
    - fixed for lifetime of card
    - verified by NFC response in tap, shown on website
    - effectively the serial number for card, but provable by signature
    - CONCERN: it looks like the aes key and if 256 bits is too long

## New Commands

- "backup"
    - AES key is pre-programmed at factory (and printed in hex on back)
    - backup ccommand returns the `master_pk` and `chain_code`, formated in BIP-32 serialized
      form (ie. XPRV) 
    - contains a few values, CBOR encoded
    - then AES-128-CTR encrypted
    - increments a counter of number of backups (part of status response)
    - resulting response can be decrypted with `openssl aes-128-ctr -iv 0 -K HEX-on-back`
    - command is authorized by CVC code

- "change CVC"
    - just that

- "xpub"
    - dump master or derived XPUB in BIP-32 serialzed format

## Changed Commands

- "sign" command
    - `subkey` field added, and key may be derived during 

- "status"
    - remove "slots", "addr" fields
    - add `num_backups`, `path`, `tapsigner`, fields

- "derive"
    - adds derivation path (subkey) to be derived as an argument
    - authenticated
    - updates with the newly derived key, stores it and path used
    - shared derived pubkey, since no 'read" command

- "new"
    - new derivation path

- "dump"
    - remove completely



