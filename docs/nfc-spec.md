# NFC Specification

## Background

When a card taps a phone without a corresponding app installed, the NFC feature should open a web page showing a helper app (i.e., a mobile wallet) to install for interacting with the card.

However, much more than that is possible. For example, we can show a deposit address and display the balance for a **SATSCARD<sup>&trade;</sup>**, something we already do for **OPENDIME<sup>&reg;</sup>** USB products.

Therefore, a dynamic NDEF response is desired.


## NDEF Contents

- A single NDEF record, with a well-known URL type (`https://`).
- The applet on the card knows how to build NDEF record based on the provided prefix.
- The suffix is the dynamic part of the URL; the prefix is hard-coded by the factory.


# URL Details

- Ampersand-separated, key=value pairs
- String: URL-encoded already, needs no percent-escaping
- Keys: Single-letter, values are mostly fixed-width and short
- **SATSCARD:** Uses the current active slot. If the slot is unused (no key, yet) the card uses the previous slot (slot must already be unsealed).
- **TAPSIGNER<sup>&trade;</sup>:** Limited information and identity are provided.

Example: `https://getsatscard.com/start#` + `DYNAMICPART` </br>
The dynamic part is: `u=S&o=3&r=bcajrh2jdk&n=01020304050607&s=fefb...00`


## SATSCARD Keys

- `u` = State: S=sealed, U=unsealed, E=error/tamper
- `o` = Displayed slot's slot number
- `r` = Address's right-most 8 characters
- `n` = Card-selected nonce, in hex, 8 bytes (16 when hex-encoded)
- `s` = Signature, 64 bytes (non-recoverable style), hex-encoded


### Notes

- If more than ten slots are supported, and the current slot number is greater than ten, then it's possible the message is variable-length as `o` could be `o=23`.
- The `s` field _must_ be last, no other order is required.


## TAPSIGNER Keys

- `t` = `1`: TAPSIGNER mode is active
- `u` = State: S=sealed, U=unused (no key defined yet), E=error/tamper
- `c` = 8 bytes, called `card_ident`, in hex (16 chars when hex-encoded)
- `n` = Card-selected nonce, in hex, 8 bytes (16 when hex-encoded)
- `s` = Signature, 64 bytes (non-recoverable style), hex-encoded


### Notes

- The signature is done using the card private key (not based on the contents of any slot).
- The `s` field _must_ be last, no other order is required.


#### `card_ident`

- `card_ident` is `SHA256(card_pubkey)[0:8]`.
- The full version is on the back of the card, so it can be revealed via the link-decoding process.
- It is truncated and then encoded further into base32 groups.


## Message to be Signed

The dynamic portion is the message being signed. It consists of everything up to and including the `s=`.

- Digest (from the example): SHA256(`u=S&o=3&r=bcajrh2jdk&n=01020304050607&s=`)


## Special States

- Provide `u=E` if a slot or card is tampered with.
- Use contents of slot zero for other components, if it's not safe to use a normal, obvious slot.


## Nonce

- It is _critical_ to use a fresh nonce for each NFC read (we do this).
- On the server side, a duplicate nonce will show the customer a fatal error.


# Decoding URL

On the server side (or caller's Javascript, in-browser if possible), we will recover the public key by brute-forcing up to 4 possible values for the public key compared to the bech32 address fragment (or TAPSIGNER: pubkey hash) provided.

For SATSCARD, if the bech32 address is on testnet, additional
comparisons may be required as the URL does not encode testnet
status explicitly.


## CBOR Command

- We provide the `url` command which can be used to read the dynamic URL as if a tap had occurred.


## Code For Decoding

From `../cktap`, see file [`verify_link.py`](../cktap/verify_link.py) which
implements full decode and verification, including address recovery or
card ident recovery.

```python
>>> from cktap.verify_link import url_decoder
>>> sc='u=S&o=0&r=vekusqj5&n=8334bd83e0bb7b25&s=4d868754a6e22172977ded6b12fbf05c0b8fe16194159373125e247f4f27811d6e6fe17ef65a050799e138305239ddcb97ad124cf1ae47c45ed8dd7f875626fe'
>>> url_decoder(sc)
{'addr': 'bc1q7h0u5yn8y4pajn94ze4gnhz487c8ysvekusqj5',
 'is_tapsigner': False,
 'nonce': '8334bd83e0bb7b25',
 'sealed': True,
 'slot_num': 0,
 'state': 'Sealed',
 'tampered': False
}

>>> from cktap.utils import card_pubkey_to_ident
>>> card_pubkey_to_ident(b'\x02'*33)
'YTIZ2-MQZZZ-XPA2D-I5OGH'

```
