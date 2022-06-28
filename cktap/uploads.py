#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Specs and details related to SATSCHIP data uploads to our server.
#
# File contents:
# CBOR sequence of 5 items:
#   (META_VERSION, body_cbor, signature, card_nonce, cert_sig)
# - body_cbor is serialized CBOR, with
#     - mapping of field values, see below
# - cert_sig/card_nonce are needed for verification against card_pubkey
#
# To verify:
#       md = sha256(sha256(body_cbor))
#  - verify md is signed by body_cbor.pubkey ('signature' value)
#  - but also verify certificate chain inside:
#       - cert_sig is signed by card_pubkey, over msg w/ "my_nonce" truncated from same md
#       - and chain leads back to a CK factory key
#  - and our server requires fresh NFC tap URL w/ new nonce there as well
#
# Card is free to use any pub/priv key to sign, but for privacy reasons, 
# we are using this path that is unlikely to be used on-chain.
#
#   m/84h/0h/0h/420/69
#
# Metadata fields inspired somewhat by:
#   <https://support.google.com/culturalinstitute/partners/answer/7574684>
#

META_VERSION = 'SATSCHIP_META_v1'

MAX_IMG_SIZE = 2*1024*1024

META_FIELDS = [
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

ALL_FIELDS = [a for a,_ in META_FIELDS] + [
    'is_public',                    # ok to show to randos?
    'created_at', 'updated_at',     # timeline
    'pubkey',                # pubkey used for sig
    'card_ident',            # human label for card (base32 groups)
    'card_pubkey',           # implies card_ident value
    'applet_version',        # string, like '0.9.1'
    'birth_height',          # integer, block height
    'cert_chain',            # list of certs; response from 'certs' command
]


# Generally, Field values:
# - endswith _at => datetime in UTC
# - endswith _url => optional link for matching text value w/ same prefix
# - startswith is_ => boolean value
# - otherwise probably text
