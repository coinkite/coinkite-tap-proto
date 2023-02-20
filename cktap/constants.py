#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# System constants.
#

# Number of key slots in SATSCARD
NUM_SLOTS = 10

# the "CVC" is the spending code on back of card.
# - see also many text messages to user about this
# - for TAPSIGNER, this is a minimum length (max 32)
CVC_LENGTH = 6

# no need to scan the blockchain before this point in time, since product didn't exist yet
# - March 25/2022
PROJECT_EPOC_TIME_T = 1648215566

# length from start/end of bech32 address that is provided
# - center part will be replaced with three underscores
ADDR_TRIM = 12

# require nonce sizes (bytes)
CARD_NONCE_SIZE = 16
USER_NONCE_SIZE = 16

# published Coinkite factory root keys
FACTORY_ROOT_KEYS = { 
    bytes.fromhex('03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1'):
        'Root Factory Certificate',

    # obsolete dev value, but keeping for a little while longer
    bytes.fromhex('027722ef208e681bac05f1b4b3cc478d6bf353ac9a09ff0c843430138f65c27bab'):
        'Root Factory Certificate (TESTING ONLY)',
}

# our cards will provide this answer to reset (ATR)
CARD_ATR = [59, 136, 128, 1] + list(b'Coinkite') + [49]

# our Javacard applet has this APP ID
APP_ID = bytes.fromhex('f0436f696e6b697465434152447631')

# APDU CLA and INS fields for our one APDU, which uses CBOR data
CBOR_CLA = 0x00
CBOR_INS = 0xCB

# Correct ADPU response from all commands: 90 00 
SW_OKAY = 0x9000

# path lengths (depth) is limited 8 components in derive command - check docs/limitations.md
DERIVE_MAX_BIP32_PATH_DEPTH = 8

RFC_SIGNATURE_TEMPLATE = '''\
-----BEGIN BITCOIN SIGNED MESSAGE-----
{msg}
-----BEGIN BITCOIN SIGNATURE-----
{addr}
{sig}
-----END BITCOIN SIGNATURE-----
'''
# EOF
