#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# System constants.
#

# Number of key slots in SATSCARD
NUM_SLOTS = 10

# the "CVC" is the spending code on back of card.
# - see also many text messages to user about this
CVC_LENGTH = 6

# no need to scan the blockchain before this point in time, since product didn't exist yet
# TODO: update to a date closer to product launch
PROJECT_EPOC_TIME_T = 1637600000

# length from start/end of bech32 address that is provided
# - center part will be replaced with three underscores
ADDR_TRIM = 12

# require nonce sizes (bytes)
CARD_NONCE_SIZE = 16
USER_NONCE_SIZE = 16

# published Coinkite factory root keys
FACTORY_ROOT_KEYS = { 
    bytes.fromhex('027722ef208e681bac05f1b4b3cc478d6bf353ac9a09ff0c843430138f65c27bab'):
        'Root Factory Certificate (TESTING)',
}

# our cards will provide this answer to reset (ATR)
CARD_ATR = [59, 136, 128, 1] + list(b'Coinkite') + [49]

# our Javacard applet has this APP ID
APP_ID = bytes.fromhex('f0436f696e6b697465534154537631')

# APDU CLA and INS fields for our one APDU, which uses CBOR data
CBOR_CLA = 0x00
CBOR_INS = 0xCB

# EOF
