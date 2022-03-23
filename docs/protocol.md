# Coinkite Tap Cards Protocol

This document describes the protocol for both the **SATSCARD<sup>&trade;</sup>** and **TAPSIGNER<sup>&trade;</sup>** products. Despite having different usage and security models, they share much of the same code.


## Table of Contents

- [Background](#background)
  - [Design Principles](#design-principles)
  - [Message Encoding](#message-encoding)
  - [Testnet Support](#testnet-support)
  - [TAPSIGNER Differences (vs. SATSCARD)](#tapsigner-differences-vs-satscard)
  - [Certificates](#certificates)
    - [Certificate Comments](#certificate-comments)
  - [Private Key Picking](#private-key-picking)
    - [SATSCARD Keys](#satscard-keys)
    - [TAPSIGNER Keys](#tapsigner-keys)
    - [Invalid Key](#invalid-key)
- [Commands](#commands)
  - [Authenticating Commands with CVC](#authenticating-commands-with-cvc)
    - [CVC Length & Content](#cvc-length--content)
    - [Authentication Failures](#authentication-failures)
  - [Shared Commands](#shared-commands)
    - [`status`](#status)
      - [TAPSIGNER `status` Differences](#tapsigner-status-differences)
    - [`read`](#read)
    - [`derive`](#derive)
      - [SATSCARD: Checks Payment Address Derivation](#satscard-checks-payment-address-derivation)
      - [TAPSIGNER: Performs Subkey Derivation](#tapsigner-performs-subkey-derivation)
    - [`certs`](#certs)
      - [`rec_id` Notes](#rec_id-notes)
    - [`new`](#new)
    - [`nfc`](#nfc)
    - [`sign`](#sign)
      - [Signing Notes](#signing-notes)
      - [TAPSIGNER: Subpath Values](#tapsigner-subpath-values)
    - [`wait`](#wait)
  - [SATSCARD-Only Commands](#satscard-only-commands)
    - [`unseal`](#unseal)
    - [`dump`](#dump)
  - [TAPSIGNER-Only Commands](#tapsigner-only-commands)
    - [`change`](#change)
    - [`xpub`](#xpub)
    - [`backup`](#backup)
- [Errors](#errors)
  - [Error Responses](#error-responses)
  - [List of Errors](#list-of-errors)
- [Notes](#notes)
  - [Card Nonce](#card-nonce)
  - [Install-Time Actions (Background Information)](#install-time-actions-background-information)
    - [Java Applet Actions](#java-applet-actions)
    - [Factory Actions](#factory-actions)
      - [SATSCARD](#satscard)
      - [TAPSIGNER](#tapsigner)
  - [Encoding Notes](#encoding-notes)
    - [Keys](#keys)
    - [Nonce Values](#nonce-values)
    - [Addresses](#addresses)
    - [Pubkeys](#pubkeys)
    - [Signature Values](#signature-values)
  - [Extensibility](#extensibility)
  - [Security Notes](#security-notes)
- [TAPSIGNER Variant Overview](#tapsigner-variant-overview)
  - [System Changes](#system-changes)
  - [New Commands](#new-commands)
  - [Changed Commands](#changed-commands)


# Background

- Card operation protocol: ISO-7816, emulating an NFC tag
- RF protocol(s): ISO/IEC 7816-4:2020 and/or ISO/IEC 14443-A
- Mobile app sends APDU requests and gets responses
- APDU body: CBOR serialized mappings (as documented here)
- APDU CLA/INS specific to this application: 0x00/0xCB
- NFC response can be dynamic and always contains a single URL (URL prefix is factory-set, cannot be changed in the field. See [nfc-spec](nfc-spec.md).)

## Design Principles

- Session key (XOR) encrypts private keys when sent over the air.
- **SATSCARD:** Not showing the full deposit address forces client apps to run cryptographic functions verifying the card's operation.  
- **TAPSIGNER:** A general purpose, BIP-32 based keysigner. Expected use cases include serving as a multisig cosigner or a hardware wallet-like device.


## Message Encoding

- [CBOR](https://cbor.io/) frames and encodes data in both directions.
- CBOR message is written using an APDU's data field.
  - `CLA=0x00 INS=0xCB`
  - Length varies based on CBOR content.
  - The reply is also CBOR.
- Only one APDU is implemented; all parameters and subcommands are in CBOR data structure.


## Testnet Support

Cards are set to operate on the Bitcoin mainnet by default. However, the factory can mark a card to operate on testnet for development and testing. The factory renders the card with a different human readable part (HRP), affecting the addresses. Testnet addresses start with _tb1_ rather than _bc1_. Testnet cannot be enabled after leaving the factory.    


## TAPSIGNER Differences (vs. SATSCARD)

Differences unique to TAPSIGNER are called out and described throughout the documentation.

See [TAPSIGNER Variant Overview](#tapsigner-variant-overview) for more information.


## Certificates

**OPENDIME<sup>&reg;</sup>** USB uses a proper X.509 certificate chain, but this product uses normal Bitcoin signatures over the indicated values and doesn't store any more than needed. The chain is:

- Root factory certificate. Ultra-secret. Used offline only to sign batch certificates.
- Each laser-etcher in the factory uses a different batch certificate (potentially each day).
- Batch certs are rotated, and could be revoked if a security issue arises.
- Each card picks a "card" key pair and provides the public key to the factory production system which signs it using the current batch certificate.
- Card signs (some known text) and offers that signature as the lowest level certificate.

**NOTE:** It's important to implement the verification steps in the reference clients. Experience has shown that devs will not bother to implement the verification steps. The consequence is that fraudulent devices can be fielded by third parties when they are used with those weaker apps.


### Certificate Comments

> Since creating a signature takes 300 ms, I don't want to perform
two signature operations in a single request. If we could, I would
include the auth signature in the "read" response and maybe even force
them to unravel it somehow there.

> The protocol allows a variable number of certificates in the chain. For now, this will be always two: root and batch. Future products might use more, however.


## Private Key Picking

### SATSCARD Keys

The customer can provide their own 32 bytes of entropy (the chain code) for the key-picking process. The factory uses the birth-block hash as the entropy value for the SATSCARD.

The card picks a new, random key pair for each slot when the slot is created. There is no relation between any of the slots' master key values.

If the app does not provide a value when subsequent slots are used, the card will use the previous slot's `chain_code` value. Security is not compromised since the card always picks a fresh random value for its master private key.

The payment address, and the key pair it corresponds to, are calculated in compliance with
[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
The chain code and the slot's master public key are mixed together with HMAC-SHA512 to derive the `m/0` subkey. This is the _only_ subkey this project will use.

Unlike previous OPENDIME designs, the customer can be verify their
entropy was used for the private key before unsealing the slot. BIP-32 keypath derivation features are not being used, however.


### TAPSIGNER Keys

TAPSIGNER cards ship with no private key picked. The customer _must_
provide a `chain_code` value (32 bytes). Customers can also verify their chain code value was used.  

The card picks a new random key-pair using the internal TRNG.

The user is free to change derivation path during the life of the card.


### Invalid Key

In the extremely unlikely case the BIP-32 derivation process
produces an invalid private key, the card saves the values
discovered and unseals the slot. A unique error code will be provided
to the caller. The odds of this code path being executed are less
than 1 in 2<sup>128</sup>.


# Commands

## Authenticating Commands with CVC

To prove the caller knows the CVC value requires sending the CVC
with each command requiring authentication. The value itself is encrypted using the specific card's pubkey:

1. The app picks an ephemeral key pair on secp256k1.
2. It reads the card's pubkey (fixed value, shared everytime) and current `card_nonce` value (see [Status Response](#status-response)).
3. The ephemeral private key is multiplied by the card's pubkey and the result is hashed (SHA-256), producing the 32-byte `session_key`.
    - This is a normal [ECDH key agreement](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) which yields a shared secret key (a point on the curve).
    - In this application, the hashing step includes a byte for Y parity, see [libp256k1 code](https://github.com/bitcoin-core/secp256k1/blob/185a6af22792531a629959834fff9257e396abb5/src/modules/ecdh/main_impl.h#L13-L24). Some libraries may hash
      only the X component which will not work.
4. The user-supplied CVC value is XORed: (`session_key` XOR sha256(`card_nonce` + `command_name`))
    - CVC is serialized as ASCII. fThe SATSCARD's 6-digit CVC is factory-set; the result in `xcvc` is the six leading bytes.
    - `command_name` is the command being authenticated (short string, like `unseal`)
5. The app's ephemeral public key and encrypted CVC value accompanies each request needing it.

The app cannot reuse both values on subsequent requests because the `card_nonce` changes, affecting `xcvc`. However, the `session_key` may be reused if it gives the same `epubkey` value and if the same command is being executed.

Authenticated commands will have these two fields in addition to any
other parameters needed:

```python
{
    'epubkey': (33 bytes),      # app's ephemeral public key
    'xcvc': (6 to 32 bytes)   # encrypted CVC value
}
```
The response provides a new `card_nonce`; this nonce is needed for later commands, not the current command.


### CVC Length & Content

The SATSCARD's CVC is six numeric digits. The CVC may be expanded up to 32 bytes, with the bytes potentially including ASCII or other values. Please treat the CVC as a byte sequence of 6 to 32 bytes. The encrypted CVC length, `xcvc`, must match the factory-defined CVC length which is printed on the back of the card.

TAPSIGNER's initial CVC is also printed on the card, but can be changed later according to user preference. Any length between 6 and 32 bytes is allowed.


### Authentication Failures

A command with the wrong CVC value will fail, returning error 401 (bad auth). Two more immediate retries are permitted. If those attempts fail, a 15-second delay between attempts takes effect. Attempts before 15 seconds passes will fail and return error 429 (rate limited).

The status value `auth_delay` shows the number of seconds required between attempts. Use the [`wait` command](#wait) to pass the time. Another attempt is allowed after the delay passes. If the CVC value is correct, normal operation begins. If the CVC value is incorrect, the 15-second delay between attempts continues.


## Shared Commands

Although both SATSCARD and TAPSIGNER use these commands, their use is not necessarily identical. Attributes specific to a particular card type (fields, functions, responses, etc.) are explained and demonstrated.


### `status`

To begin, the app must get the current status of the card:

```python
{
    'cmd': 'status'          # command code
}
```

The card replies:

```python
{
    'proto': 1,                     # (int) version of CBOR protocol in use (ie. this document)
    'ver': '1.1.0',                 # firmware version of card itself
    'birth': 700553,                # card birth block height (int) (fixed after production)
    'slots': (0, 10),               # tuple of (active_slot, num_slots)
    'addr': 'bc1qsqu64khv___qf735wvl3lh8'   # payment address, middle chars blanked out with 3 underscores
    'pubkey': (33 bytes),            # public key unique to this card (fixed for card life) aka: card_pubkey
    'card_nonce': (16 bytes)       # random bytes, changed each time we reply to a valid cmd
}
```

This is a CBOR mapping. Keys are simple, short strings to save space. Order is not defined.

A development card will **also** have a `testnet=True` field; if false, the field is not provided.

After a number of authentication failures (i.e., wrong CVC), the `auth_delay` field is added. It holds an integer: the number
of seconds of delay required before any authenticated command can
proceed. Using such commands will fail, giving error code 429 (rate limited), until the delay is consumed using the `wait` command.

The current slot can be `new` (no key picked yet) or `sealed`, but never `unsealed`. When the current slot is `new` (i.e., not yet used), the `addr` field is omitted. When the card is completely consumed, `active_slot == num_slots`.


#### TAPSIGNER `status` Differences

Fields removed:
- `slots`
- `addr`

Fields added:
- `tapsigner=True`
- `path`

`path` is a short array of integers, the subkey derivation currently in effect. It encodes a BIP-32 derivation path, like `m/84h/0h/0h`, which is a typical value for segwit usage, although the value
is controlled by the wallet application. The field is only
present if a master key has been picked (i.e., setup is complete).

Each time the backup command is used, the `num_backups` value
increments (up to a maximum value of 127).

Example response:

```python
{
    'proto': 1,                     # (int) version of CBOR protocol in use (ie. this document)
    'ver': '1.1.0',                 # firmware version of card itself
    'birth': 700553,                # card birth block height (int) (fixed after production)
    'tapsigner': True,              # product is TAPSIGNER, not SATSCARD
    'path': [(1<<31)+84, (1<<31), (1<<31)],     # user-defined, will be omitted if not yet setup
    'num_backups': 3,               # counts up, when backup command is used
    'pubkey': (33 bytes),            # public key unique to this card (fixed for card life) aka: card_pubkey
    'card_nonce': (16 bytes)       # random bytes, changed each time we reply to a valid cmd
}
```


### `read`

Apps need to write a CBOR message to read a SATSCARD's current payment address, or a TAPSIGNER's derived public key.

Example message:

```python
{
    'cmd': 'read',          # command
    'nonce': (16 bytes),    # provided by app, cannot be all same byte (& should be random)
    'epubkey': (33 bytes),      # (TAPSIGNER only) auth is required
    'xcvc': (6 to 32 bytes)   # (TAPSIGNER only) auth is required encrypted CVC value
}
```

The card calculates a signature and responds:

```python
{
    'sig': (64 bytes),          # signature over a bunch of fields using private key of slot
    'pubkey': (33 bytes),       # public key for this slot/derivation
    'card_nonce': (16 bytes)   # new nonce value, for NEXT command (not this one)
}
```

The signature is created from the digest (SHA-256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from read command - 16 bytes)
(slot - 1 byte)
```

The active slot's private key signs this. If the slot is empty, the command fails.

The companion app must verify the signature against the provided
public key. For **SATSCARD**, it maps to a segwit Bech32 address, and the leading/final characters are verified against the `addr` field.  The
previously unknown middle digits are thus calculated.

For **TAPSIGNER**, this command operates on the derived pubkey
set earlier. It assumes the card knows the private key for the indicated derivation in effect. Authentication is required, and bytes 1 through 33 of the pubkey will be XORed with the session key.

There is a nonce from both parties: the `card_nonce` from the card, and the `nonce` from the app, so that neither can replay a previous response.


### `derive`

#### SATSCARD: Checks Payment Address Derivation

To verify a user's entropy was used in picking the private key, SATSCARD can show the entropy and provide the master public key. The `derive` command can be used, with additional math on the part of the app, to derive the payment address and verify it follows from the chain code and master public key.


```python
{
    'cmd': 'derive',        # command
    'nonce': (16 bytes)    # provided by app, cannot be all same byte (& should be random)
}
```

The card responds:

```python
{
    'sig': (64 bytes),         # signature over a bunch of fields using private key of slot
    'chain_code': (32 bytes),  # the nonce provided by customer when this slot`s privkey was picked
    'master_pubkey': (33 bytes),       # master public key in effect
    'card_nonce': (16 bytes)  # new nonce value, for NEXT command (not this one)
}
```

NOTE: the derivation is fixed as `m/0`, meaning the first non-hardened
derived key. SATSCARD always uses that derived key as the payment address.

The signature is created from the digest (SHA-256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from command - 16 bytes)
(chain_code - 32 bytes)
```

The signature is signed by the slot's `master_pubkey`.

To complete the verification process, the app must use the signature to verify the `master_pubkey`. With the pubkey and the chain code, the app reconstructs a BIP-32 XPUB (extended public key).

The payment address the card shares (i.e., the slot's `pubkey`)
must equal the BIP-32 derived key (`m/0`) constructed from that
XPUB.


#### TAPSIGNER: Performs Subkey Derivation

The `derive` command on the TAPSIGNER is used to perform hardened
BIP-32 key derivation. Wallets are expected to use it for deriving the BIP-44/48/84 prefix of the path; the value is captured and stored long term. This is effectively calculating the XPUB to be used on the mobile wallet.


```python
{
    'cmd': 'derive',        # command
    'path': [...],          # derivation path, can be empty list for `m` case (a no-op)
    'nonce': (16 bytes),    # provided by app, cannot be all same byte (& should be random)
    'epubkey': (33 bytes),      # app's ephemeral public key
    'xcvc': (6 to 32 bytes)   # encrypted CVC value
}
```

The card calculates the derived key and provides a response:

```python
{
    'sig': (64 bytes),         # signature over a bunch of fields using derived private key
    'chain_code': (32 bytes),  # chain code of derived subkey
    'master_pubkey': (33 bytes),       # master public key in effect (`m`)
    'pubkey': (33 bytes),       # derived public key for indicated path
    'card_nonce': (16 bytes)  # new nonce value, for NEXT command (not this one)
}
```

The signature is created from the digest (SHA-256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from command - 16 bytes)
(chain_code - 32 bytes)
```

The wallet app chooses the most appropriate derivation
for their design. However, it cannot contain unhardened components.
The derivation path is remembered and reported in the `status`
command response, but may be changed at will.

The path is provided as a sequence of 32-bit unsigned integers. The
MSB must be set on all these values as only hardened derivations
are supported.

If not provided, the existing derivation
path is unchanged by this command. The path can be up to 8 levels deep.
Authentication is required.


### `certs`

This command is used to verify the card was made by Coinkite and
is not counterfeit. Two requests are needed: first, fetch
the certificates, and then provide a nonce to be signed.


```python
{
    'cmd': 'certs'         # command
}
```

The card responds:

```python
{
    'cert_chain': (signature, .. )   # list of certificates, from 'batch' to 'root'
}
```

The response is static for any particular card. The values are captured during factory setup. Each entry in the list is a 65-byte signature. The first signature signs the card's public key, and each following signature signs the public key used in the previous signature. Although two levels of signatures are planned, more are possible.

Next, the app provides a nonce for signing:

```python
{
    'cmd': 'check',         # command
    'nonce': (16 bytes)     # random value from app
}
```

The card's response:

```python
{
    'auth_sig': (64 bytes),         # signature using card_pubkey
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

The `auth_sig` value is a signature made using the card's public key (`card_pubkey`).

The signature is created from the digest (SHA-256) of these bytes:

```
b'OPENDIME' (8 bytes)
(card_nonce - 16 bytes)
(nonce from check command - 16 bytes)
```

The app verifies this signature and checks that the public key in use is the `card_pubkey` to prove it is talking to a genuine Coinkite card. The signatures of each certificate chain element are then verified by recovering the pubkey at each step. This checks that the batch certificate is signing the card's pubkey, that the root certificate is signing the batch certificate's key and so on. The root certificate's expected pubkey must be shared out-of-band and already known to the app.


#### `rec_id` Notes

- The first byte of each signature has `rec_id` encoded according to [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki).
  - If the value is between 39 to 42 [39, 42], subtract 39 to get `rec_id` within the range of 0 to 3 [0, 3].
  - If the value is [27, 30], subtract 27 to get `rec_id` within the range of [0, 3].
  - Other values should not occur.



### `new`

**SATSCARD:** Use this command to pick a new private key and start a fresh slot. The operation cannot be performed if the current slot is sealed.

**TAPSIGNER:** This command is only used once.

```python
{
    'cmd': 'new',             # command
    'slot': 3,                 # (optional: default zero) slot to be affected, must equal currently-active slot number
    'chain_code': (32 bytes),  # app's entropy share to be applied to new slot (optional on SATSCARD)
    'epubkey': (33 bytes),     # app's ephemeral public key
    'xcvc': (6 bytes)        # encrypted CVC value
}
```

The slot number is included in the request to prevent command replay.

At this point:

- No new slots available? Abort and fail command.
- A new key pair is picked and stored into the new slot.
    - The `chain_code` must be used in that process and stored.
    - The card uses TRNG to pick a new `master_pubkey` (pair).

The new values take effect immediately, so some fields of the
next status response will have new values.

Response will be:

```python
{
    'slot': 3,                      # slot just made
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

There is a very, very small &mdash; **1 in 2<sup>128</sup>** &mdash; chance of arriving at an invalid private key. This returns error 205 (unlucky number). Retries are allowed with no delay. Also, buy a lottery ticket immediately.

**SATSCARD:** derived address is generated based on `m/0`.

**TAPSIGNER:** uses the default derivation path of `m/84h/0h/0h`.

In either case, the `status` and `read` commands are required to learn the details of the new address/key.


###  `nfc`

The card provides a unique, dynamic URL when tapped on an NFC-enabled phone. This command simulates that action and reads the URL directly.

```python
{
    'cmd': 'nfc'             # command
}
```

Response is the needed URL:

```python
{
    'url': 'example.com/path#dynamicstuff'      # URL
}
```

`https://` is the required prefix to that value. `http` is not
supported. The details for decoding the URL are in [nfc-spec.md](nfc-spec.md).


### `sign`

**SATSCARD:** Arbitrary signatures can be created for unsealed slots. The app could perform this, since the private key is known, but it's best if the app isn't contaminated with private key information. This could be used for both spending and multisig wallet operations.

**TAPSIGNER:** This is its core feature &mdash; signing an arbitrary message digest with a tap. Once the card is set up (the key is picked), the command will always be valid.

```python
{
    'cmd': 'sign',              # command
    'slot': 0,                  # (optional) which slot's to key to use, must be unsealed.
    'subpath': [0, 0],          # (TAPSIGNER only) additional derivation keypath to be used
    'digest': (32 bytes),        # message digest to be signed
    'epubkey': (33 bytes),       # app's ephemeral public key
    'xcvc': (6 bytes)          # encrypted CVC value
}
```

The digest is encrypted (XOR) with `session_key` since modifying it in-flight would be a big problem.

Response:

```python
{
    'slot': 0,                  # which slot was used
    'sig': (64 bytes),           # signature
    'pubkey': (33 bytes),       # public key of this slot
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

The signature is not encrypted. The `pubkey` field can be verified against the signature.


#### Signing Notes

The signature is non-deterministic (K), and low R- and S-values are always provided. To achieve this, multiple K values may be used. If more than a few attempts are made without success, error 205 (unlucky number) is returned. Immediately retry the command to restart with better luck. The odds of this occurring are 1-in-8, based on three retries internal to the card.


#### TAPSIGNER: Subpath Values

The `subpath` field is optional (default: empty array), but is typically used to specify the specific sub-address. By convention, the first number is 0 or 1, where 1 indicates change, and 0 indicates deposits. The second component is the subkey number and should increase with each key used.

The subpath derivation is applied only for this signature and does not affect the derivation already in effect. A full path cannot be specified here, it must be relative to the existing derivation and must be unhardened. The subpath may be zero, one, or two items long.


### `wait`

Invalid CVC codes return error 401 (bad auth), through the third incorrect attempt. After the third incorrect attempt, a 15-second delay is required. Any further attempts to authenticate will return error 429 (rate limited) until the delay has passed.

In rate-limiting mode, the status command returns the `auth_delay` field with a positive value.

The `wait` command takes one second to execute and reduces the
`auth_delay` by one unit. Typically, 15 `wait` commands need to be executed before retrying a CVC.

```python
{
    'cmd': 'wait',            # command
    'epubkey': (33 bytes),       # app's ephemeral public key (optional)
    'xcvc': (6 bytes)          # encrypted CVC value (optional)
}
```

Response:

```python
{
    'success': True,             # command result
    'auth_delay': (integer)     # how much more delay is now required.
}
```

When `auth_delay` is zero, the CVC can be retried and tested without side effects.


## SATSCARD-Only Commands

### `unseal`

To unseal the current slot, send this data:

```python
{
    'cmd': 'unseal',          # command
    'slot': 3,                 # slot to be unsealed, must equal currently-active slot number
    'epubkey': (33 bytes),     # app's ephemeral public key
    'xcvc': (6 bytes)        # encrypted CVC value
}
```

NOTE: The slot number is included in the request to prevent command replay. Only the current slot can be unsealed.

The response:

```python
{
    'slot': 3,               # slot just unsealed
    'privkey': (32 bytes),   # private key for spending
    'pubkey': (33 bytes),    # slot's pubkey (convenience, since could be calc'd from privkey)
    'master_pk': (32 bytes),      # card's master private key
    'chain_code': (32 bytes),     # nonce provided by customer
    'card_nonce': (16 bytes)     # new nonce value, for NEXT command (not this one)
}
```

`chain_code` and `master_pk` are established when the slot's privkey is picked. `chain_code` is either picked by the customer, or the previous slot's chain code is recycled. `master_pk` is the entropy the card adds.

The private key is encrypted, XORed with the session key, but other values are shared unencrypted.

Unsealing a slot updates the state, but no new key is picked. To use the card again, run the `new` command. The active slot number increases by one and, unless the card is fully consumed, points at the next unused slot.


### `dump`

This reveals the details for all previous slots, all at once. The current slot is not affected. This is a no-op in terms of response content if slots aren't available yet, or if a slot hasn't been unsealed. (i.e., an empty list). The factory uses this to verify the CVC is printed correctly without side effects.

```python
{
    'cmd': 'dump',              # command
    'slot': 0,                  # which slot to dump, must be unsealed.
    'epubkey': (33 bytes),       # app's ephemeral public key (optional)
    'xcvc': (6 bytes)          # encrypted CVC value (optional)
}
```

If the `epubkey` or `xcvc` is absent, the command still works, but the only information shared about an unsealed slot is status (sealed/unused/used).

Incorrect auth values for `xcvc` should fail as normal.

Response for a used slot with XCVC provided:

```python
{
    'slot': 0,                     # which slot is being dumped
    'privkey': (32 bytes),          # private key for spending (for addr)
    'chain_code': (32 bytes),       # nonce provided by customer originally
    'master_pk': (32 bytes),        # master private key for this slot (was picked by card)
    'tampered': (bool),             # flag that slots unsealed for unusual reasons (absent if false)
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

The private keys are encrypted, XORed with the session key, but the other values are shared unencrypted.

The `tampered` field is only present (and True) if the slot was unsealed due to confusion or uncertainty about its status.
In other words, if the card unsealed itself rather than via a
successful `unseal` command.

If the XCVC (and/or `epubkey`) is not provided, then the response contains the full payment address and indicates it is unsealed:

```python
{
    'slot': 0,                     # which slot is being dumped
    'sealed': False,
    'addr': 'bc1qsqkhv..qf735wvl3lh8',   # full payment address
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

The response for an unused slot:

```python
{
    'slot': 0,                     # which slot is being dumped
    'used': False,
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```

For the currently active slot, the response is:

```python
{
    'slot': 3,                     # which slot is being dumped
    'sealed': True,
    'addr': 'bc1qsqu64khv___qf735wvl3lh8',   # payment address, middle chars blanked out with 3 underscores
    'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
}
```


## TAPSIGNER-Only Commands

### `change`

TAPSIGNER users may change the CVC from the value printed on the card. This protects against theft when the owner's wallet is "borrowed."

The new CVC may be 6- to 32-bytes long. It is encrypted (XOR) by the session key.

The card must be backed-up at least once before this command is accepted or error code 425 (backup first) will result.

```python
{
    'cmd': 'change',            # command
    'data': (6 to 32 bytes),    # new CVC, encrypted
    'epubkey': (33 bytes),       # app's ephemeral public key (required)
    'xcvc': (6 bytes)          # encrypted CVC value (required)
}
```

The response:

```python
{
    'success': True,
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

The new value takes effect immediately. There is no recovery method if it is forgotten; the factory-defined CVC is gone.

Use ASCII-only, and perhaps only digits, to maximize compatibility between wallets. If desired, the CVC could be a 32-byte hash of the true password value.


### `xpub`

Provides the current XPUB (BIP-32 Serialized), either at the top level (master)
or the derived key in use (see 'path' value in status response).

```python
{
    'cmd': 'xpub',              # command
    'master': (boolean),        # give master (`m`) XPUB, otherwise derived XPUB
    'epubkey': (33 bytes),       # app's ephemeral public key (required)
    'xcvc': (6 bytes)          # encrypted CVC value (required)
}
```

Response is simple:

```python
{
    'xpub': (78 bytes)    # BIP-32 serialized, but not yet Base58 encoded
}
```

The response is ready to be used and should not require any processing. The XFP (extended fingerprint) can be calculated from the public key at the master level: 4 bytes from HASH160 (master pubkey).


### `backup`

To protect against loss or destruction of the card, a user may back up the contents of the master private key. This output is always
AES-128-CTR encrypted using a fixed key that is printed in hexadecimal
on the back of the card.

A counter is updated each time this command is executed, visible
as `num_backups` in the status response.

```python
{
    'cmd': 'backup',            # command
    'epubkey': (33 bytes),       # app's ephemeral public key (required)
    'xcvc': (6 bytes)          # encrypted CVC value (required)
}
```

The response is simply the data to save long-term:

```python
{
    'data': (bytes),            # encrypted data to be preserved
    'card_nonce': (16 bytes)    # new nonce value, for NEXT command (not this one)
}
```

The `data` field is a small text file, encrypted by AES-128-CTR
using zero as IV, and the key from the back of the card (128 bits).

Inside the encryption, two lines are defined (so far, additional
lines of data may be exported in future versions):

1. XPRV for master secret encoded in Base58
2. Current derivation path in effect

Example:
```
xprv.... 
m/84h/0h/0h
```

The data can be viewed with `openssl aes-128-ctr -iv 0 -K HEX-on-back-of-card`.
Future versions of the product may include additional values in this response,
on subsequent lines.

From the master XPRV, any key produced by the card can be reconstructed.
The card will also capture the current derivation path (from `derive`
command).  For a complete backup, output scripts and address types
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


# Errors

## Error Responses

The APDU error codes that apps expect should be used. Usually, there's no other information to provide. When possible, the body accompanying the response should be a CBOR dictionary:

```python
{
    'error': 'short message text',       # error message (English)
    'code': 400                         # integer, 3 digits
}
```

Additional fields can be provided, when details are needed for handling an error but none are presently defined.  Clients that don't understand the value should ignore all other fields. The error message is useful for debugging, but is not meant for end-users. Code should inspect the number in `code` to make a decision.

All successful commands must return SW of 0x9000 at the ISO-7816
level. Any other return value indicates a communications problem or
an issue with some other layer of software.


## List of Errors

Code | Text                  | Meaning
-----|-----------------------|--------
205  | `unlucky number`      | Rare or unlucky value random value was used/occured. Start again.
400  | `bad arguments`       | Invalid/incorrect/incomplete arguments provided to command.
401  | `bad auth`            | Authentication details (CVC/epubkey) are wrong.
403  | `needs auth`          | Command requires auth, and none was provided.
404  | `unknown command`     | The "cmd" field is an unsupported command.
405  | `invalid command`     | Command is not valid at this time, no point retrying.
406  | `invalid state`       | You can't do that right now when card is in this state.
417  | `weak nonce`          | Nonce is not unique-looking enough.
422  | `bad CBOR`            | Unable to decode CBOR data stream.
425  | `backup first`        | Cant change CVC without doing a backup first (TAPSIGNER only).
429  | `rate limited`        | Due to auth failures, delay required.

These codes are similar to HTTP error codes, but only a little.

---

# Notes

## Card Nonce

The `card_nonce` value provides replay protection. It's important to prevent commands being repeated due to eavesdropping. `card_nonce` is picked at random
by the card, and there's no need to store the value long-term.

For commands that consume the nonce, a new value is provided in the
response. That nonce is the value that will be used in the _next_
command, not the one that just occurred.

If the app gets confused, it can always do a status command and
re-read the current nonce which would be needed for following commands.

NOTE: if the card is moved in and out of the RF field between
commands, the nonce will change because it's volatile. This is a _good thing_. The mobile app should probably run a sequence of commands as quickly as possible, anyway.

Although apps are free to query the `card_nonce` from the status
response on each command, better-quality apps using the nonce
provided in the responses will be faster and will resist any commands
being inserted into their communications.


## Install-Time Actions (Background Information)

### Java Applet Actions

When the java applet is first installed, it:

- Picks a key pair and saves it forever (the card's pubkey is shared in status response).
- Sets up with zero slots, none unsealed.

The pubkey portion of the key pair needs to be signed by the factory system to define the `auth_cert` value.


### Factory Actions

For both cards, the factory:

- Signs the card pubkey and writes certificates for card, batch, and factory root.
- Picks a CVC and saves it forever.
- Sets the birth height and NFC URL.
- Writes CVC and other details on the back of the card.


#### SATSCARD

For SATSCARD, the factory:

- Sets birth-block hash (used as chain code).
- Chooses the first private key (slot zero).
- Calculates the payment address (Bech32/segwit) and prints the QR code on the back of the card.


#### TAPSIGNER

For TAPSIGNER, the factory:

- Calculates the `card_ident` value for NFC response.
- Picks an AES key for backup file encryption.


## Encoding Notes

### Keys

- All public keys are compressed. The first byte is either `0x02` or `0x03` to
  indicate the parity of the Y value, followed by 32 bytes of X.
- Private keys are raw 32-byte values. They are BE256 values, less than
  order of the curve and not zero.


### Nonce Values  

- Although supporting variable-length nonce values is possible, an error will occur if a provided nonce is too short or too long.
- A nonce value from the app with all the same bytes is not allowed (raises an error). It could be a hard-coded value, or a predictable value (counter), which shows poor mobile app design; detecting this is impractical.


### Addresses

- When blanking a segwit address, three underscores are to be placed in the
  middle, and 12 characters from each end are preserved.
- Derivation paths always:
    - Are integers in an array not a string.
    - Have MSB set (`1<<31`) for hardened components.


### Pubkeys

Both types of card have a unique pubkey, mapped into a human-readable hash with this process:

- SHA-256 (compressed pubkey = 33 bytes)
- Skip the first 8 bytes (because that's revealed in the NFC URL)
- Encode as base32 and take the first 20 characters in four groups of five characters
- Insert dashes between the groups.
  - The result is 23 characters long.

See `cktap.utils.card_pubkey_to_ident` for code.


### Signature Values

- Signatures are not DER-encoded and are always 64 bytes:
  - R = 32 bytes
  - S = 32 bytes.  
- [BIP-62 requirements for "low S" must be met.](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures)
- Non-deterministic K value is used in all signatures; the cards cannot do [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) signatures.
- High S values are always converted by the card when they occur so they don't cause issues.

The `sign` command requires grinding for a positive R value. This means re-trying with a new K value if the signature produces a negative R value (50% chance).

- The card retries three times and stops with error 205 (unlucky number) if unsuccessful.
- The same command and arguments can be immediately reused to continue searching.
- Odds of unlucky number are 1 in 8, so this case must be handled.
- Failures only indicate poor luck, not a true error.

Certificate chain signatures are 65-byte recoverable signatures.
[Read more about signatures and sizes.](https://b10c.me/blog/006-evolution-of-the-bitcoin-signature-length/)


## Extensibility

Parameters may be added to existing commands in the future. To ensure forward compatibility, the card must ignore any unexpected argument used with an incoming command.

Unknown commands should fail with error 404 (unknown command).


## Security Notes

- All public keys received from outside the card **MUST** be verified as legit public keys on the correct curve.

- _Failed_ authentication (i.e., incorrect CVC provided) must not be treated the same as _missing_ authentication, which is permitted with some commands.


---

# TAPSIGNER Variant Overview

A slightly different version/mode of the firmware using the same CBOR command protocol with a few additional commands and changes:

- No `slot` command parameter (there's only one slot)
- Option to use arbitrary derivation for slot's key (SATSCARD must be `m/0`)
- Default derived address after `new` command is `m/84h/0h/0h`
- Off-card backup (AES-encrypted) of key material via command
- Single slot mode is either `new` or `sealed`, no `unsealed`    
- Private key only accessible via backup command
- CVC may be changed to any 6- to 32-byte string
- TAPSIGNER branding


## System Changes

Single slot:
  - `slots` removed from status command (would always be `(0,1)`).
  - Commands taking a `slot` argument - it is optional and forced to zero.

The factory does not pick the first slot, the cards are shipped blank in this regard.

A factory-programmed, 16-byte hex value (128-bit key) for AES is printed on the card. This is the backup file encryption key. Use the key with AES-128-CTR to export the slot's master key XPRV.

The `sign digest` command is accepted while the slot is still sealed (CVC required). The `unseal` command is not implemented.

New concept of `card_ident` value:
-  `SHA256(card_pubkey)`
- Does not change for the lifetime of the card
- Verified by NFC response in tap and shows on the website
- Effectively the serial number for card, but provable by signature
- CONCERN: it looks like the AES key and if it is 256 bits, it is too long


## New Commands

`backup`
  - AES key is pre-programmed at the factory (printed in hex on back)
  - Returns the `master_pk` and `chain_code`, formatted in BIP-32 serialized form (i.e., XPRV)
  - Contains a few values, CBOR encoded, and then AES-128-CTR encrypted
  - Increments the number of backups counter, `num_backups`
  - The resulting response can be decrypted with `openssl aes-128-ctr -iv 0 -K HEX-on-back`
  - Authorized by CVC code

`change CVC`
- Does just that

`xpub`
- Dump the master or derived XPUB in BIP-32 serialized format


## Changed Commands

`sign`
- `subkey` field added, and key may be derived during

`status`
- Removed `slots` and `addr` fields
- Added `num_backups`, `path`, and `tapsigner` fields

`derive`
- Adds derivation path (subkey) to be derived as an argument
- Authenticated
- Updates with the newly derived key, stores it and the path used
- Shared derived pubkey, since there is no `read` command

`new`
- Different derivation path

`dump`
- Removed
