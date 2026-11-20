from unittest.mock import Mock

import pytest

from cktap.bip32 import PrvKeyNode, PubKeyNode
from cktap.proto import CKTapCard
from cktap.utils import str2path


@pytest.fixture(params=[False, True], ids=['mainnet', 'testnet'])
def card_and_key(request):
    key = PrvKeyNode.master_key(bytes(range(32)), testnet=request.param)
    card = CKTapCard.__new__(CKTapCard)
    card.is_tapsigner = True
    card.is_testnet = request.param
    card.auth_delay = 0
    card._set_derivation = Mock()
    card.get_xpub = Mock(return_value=key.extended_public_key())
    card.get_pubkey = Mock(return_value=key.sec())
    return card, key


@pytest.mark.parametrize('suffix', ['', '/0/5'])
def test_authenticated_xpub(card_and_key, suffix):
    card, key = card_and_key
    result = card.derive_xpub_at_path('123456', 'm/84h/0h/0h' + suffix)
    expected = key.get_extended_pubkey_from_path(str2path(suffix))
    assert result == expected.extended_public_key()
    card._set_derivation.assert_called_once_with(path=str2path('84h/0h/0h'), cvc='123456')
    card.get_xpub.assert_called_once_with('123456')
    card.get_pubkey.assert_called_once_with('123456')


@pytest.mark.parametrize('suffix', ['', '/0/5'])
def test_substituted_xpub_rejected_before_derivation(card_and_key, suffix, monkeypatch):
    card, _ = card_and_key
    attacker = PrvKeyNode.master_key(b'attacker seed', testnet=card.is_testnet)
    card.get_xpub.return_value = attacker.extended_public_key()
    derive = Mock(side_effect=AssertionError('Must reject before deriving suffix'))
    monkeypatch.setattr(PubKeyNode, 'get_extended_pubkey_from_path', derive)
    with pytest.raises(ValueError, match='XPUB verification failed'):
        card.derive_xpub_at_path('123456', 'm/84h/0h/0h' + suffix)
    derive.assert_not_called()


def test_address_rejects_substituted_xpub(card_and_key, monkeypatch):
    from click.testing import CliRunner
    from cktap import cli

    card, _ = card_and_key
    attacker = PrvKeyNode.master_key(b'attacker seed', testnet=card.is_testnet)
    card.get_xpub.return_value = attacker.extended_public_key()
    monkeypatch.setattr(cli, 'get_card', lambda: card)
    result = CliRunner().invoke(cli.main, ['address', '--path', 'm/84h/0h/0h/0/5', '123456'])
    assert result.exit_code == 1
    assert result.output == 'FAILURE: XPUB verification failed\n'
