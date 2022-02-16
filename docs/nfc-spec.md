# NFC Specification

## Background

When tapped by a phone that does not have our companion app installed,
we want the NFC feature to take the user to an page that allows them
to install the app.

However, we can do more than that. We can show the deposit address and display
balance for the SATSCARD. We're doing this already for OPENDIME USB products.

Therefore, we want a dynamic NDEF response.

## NDEF Contents

- a single NDEF record, with well-known type for URL (`https://`)
- applet on card knows how to build NDEF record based on provided prefix
- suffix is dynamic part of the URL, prefix is hard-coded by factory

# URL Details

- it is ampersand-separated, key=value pairs
- string is URL-encoded already and needs no percent-escaping
- keys are single-letter, values are mostly fixed-width and short
- SATSCARD: the current active slot is used, but if it's unused (no key yet) then
  previous slot is used (and it must have been unsealed).
- TAPSIGNER: limited information and identity is provided
- example: `https://getsatscard.com/start#` + `DYNAMICPART`
- dynamic part is: `u=S&o=3&r=bcajrh2jdk&n=01020304050607&s=fefb...00`

## SATSCARD Keys

- `u` = state: S=sealed, U=unsealed, E=error/tamper
- `o` = slot number of slot being shown here
- `r` = right most 8 characters of the address
- `n` = nonce picked by card, in hex, 8 bytes (16 when hex encoded)
- `s` = signature, 64 bytes (non-recoverable style), hex-encoded

Notes

- if more than ten slots are supported, and current slot is more than ten, then
  it's possible the message is variable length as `o` could be `o=23`
- the 's' field must be last, but otherwise a specific order is not required

## TAPSIGNER Keys

- `t` = `1`: Tapsigner mode active
- `u` = state: S=sealed, U=unused (no key defined yet), E=error/tamper
- `c` = 8 bytes called `card_ident` in hex (16 chars when hex encoded)
- `n` = nonce picked by card, in hex, 8 bytes (16 when hex encoded)
- `s` = signature, 64 bytes (non-recoverable style), hex-encoded

Notes

- `card_ident` is `SHA256(card_pubkey)[0:8]`. 
- full version of that will be on back of card, so it can be revealed via the link decoding process
- we truncate and then encode it further into base32 groups
- signature is done using the card private key (not based on contents of any slot)
- the 's' field must be last, but otherwise a specific order is not required

## Message to be signed

The dynamic portion is the message being signed. Everything up and
including the `s=` is included.

- from example above, digest is SHA256(`u=S&o=3&r=bcajrh2jdk&n=01020304050607&s=`)

## Special states

- if any slot or card is tampered, provide `u=E`
- use contents of slot zero for other components, if not safe to normal obvious slot (huh?)

## Nonce

- it is critical a fresh nonce is used every time an NFC read is done (and we do)
- on the server-side, any duplicate nonce is a fatal error that will be shown to customer

# Decoding URL

On the server side (or caller's Javascript, in-browser if we are
able), we will recover the public key by brute-forcing up to 4
possible values for the public key compared to the bech32 address
fragment (or TAPSIGNER: pubkey hash) provided.

For SATSCARD, if the bech32 address is on testnet, additional
comparisons may be required as the URL does not encode testnet
status explicitly.

## CBOR Command

- we also provide the `url` command which can be used to read the dynamic URL
  as if a tap had occured.

## Code For Decoding

From the `../cktap`, see file [`verify_link.py`](../cktap/verify_link.py).

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
