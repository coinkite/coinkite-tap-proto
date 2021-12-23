import pytest

def pytest_addoption(parser):
    parser.addoption("--cvc", action="store", type=str,
                     default=None, help="CVC for card under test")

@pytest.fixture(scope='session')
def dev():
    # a connected card (via USB to NFC reader) .. or the emulator
    # use command line flag to pick device/emulation method

    from cktap.transport import CKTapDeviceBase, find_cards

    for c in find_cards():
        assert isinstance(c, CKTapDeviceBase)
        return c
    else:
        raise pytest.fail('no card / emulator found')

@pytest.fixture(scope='session')
def known_cvc(request):
    # some tests require "--cvc 123456" arg on pytest cmd line
    rv = request.config.getoption("--cvc")
    if rv is None:
        raise pytest.skip("need CVC for this test")
    return rv

# EOF
