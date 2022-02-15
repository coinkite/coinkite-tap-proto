#
# Test encoding/serializations from utils.py
# 

from utils import card_pubkey_to_ident

def test_card_pubkey_to_ident():
    assert card_pubkey_to_ident(bytes(33)) == 'P6OJ4-MNMQJ-LMULZ-FQWB5'

