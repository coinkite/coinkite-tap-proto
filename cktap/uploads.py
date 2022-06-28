#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Specs and details related to SATSCHIP data uploads to our server.
#
# File contents:
# CBOR sequence of 3 items:
#   (META_VERSION, body_cbor, signature)
# - body_cbor is serialized CBOR, with
#     - mapping of field values, see below
#
# To verify, sha256(sha256(check body_cbor)) is digest, pubkey is body_cbor.pubkey
#  - but also verify certificate chain inside
#  - and our server requires fresh NFC tap URL w/ new nonce there as well
#
# Card is free to use any pub/priv key to sign, but for privacy reasons, 
# we are using this path that is unlikely to be used on-chain.
#
#   m/84h/0h/0h/420/69
#
# Fields inspired somewhat by:
#   <https://support.google.com/culturalinstitute/partners/answer/7574684>


META_VERSION = 'SATSCHIP_META_v1'

MAX_IMG_SIZE = 2*1024*1024

meta_fields = [
    ( 'image', 'Image file' ),          # bytes encoding an image, up to 2MB (jpeg would be best)
    ( 'creator', 'Creator (artist)' ),
    ( 'creator_url', 'Creator\'s Homepage' ),
    ( 'title', 'Title of Work' ),
    ( 'title_url', 'Link for title (for more info about work itself)'),
    ( 'description', 'Description' ),
    ( 'date_created', 'Creation date (free text)' ),
    ( 'medium', 'Medium (oil on canvas)' ),
    ( 'rarity', 'Rarity (3 of 100)' ),
    ( 'owner', 'Owner' ),
    ( 'owner_url', 'URL for Owner'),
    ( 'is_public', 'Show in public gallery'),
]

all_fields = [a for a,_ in meta_fields] + [
    'is_public',                    # ok to show to randos?
    'created_at', 'updated_at',     # timeline
    'pubkey',                       # pubkey used for sig
    'card_ident',                   # = card.card_ident
    'applet_version',               # string, like '0.9.1'
    'birth_height',                 # integer, block height
    'certs',            # dict(chain=[pubkeys to root CK key], nonce=(16 bytes), sig=signature)
]


# Generally, Field values:
# - endswith _at => datetime in UTC
# - endswith _url => optional link for matching text value w/ same prefix
# - startswith is_ => boolean value
# - otherwise probably text
