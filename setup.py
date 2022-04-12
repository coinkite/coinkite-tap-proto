#
# Coinkite Tap protocol and python support library
#

# To use this command to install and yet be able to edit the code (here). Great for dev:
#
#   pip install --editable .
#
# with cli dependencies
#
#   pip install --editable '.[cli]'
#
# with test dependencies
#
#   pip install --editable '.[test]'
#
# On Windows, this can be useful:
#
#   pip install -U --force-reinstall coinkite_tap_protocol-*.whl[cli]
#
#
from setuptools import setup

# these minimum versions are tested, some earlier values would probably work too.
requirements = [
    'cbor2>=5.4.1',
    'bech32>=1.2.0',
    'pyscard>=2.0.2',
    'ecdsa>=0.13',
]

requests_socks = 'requests[socks]>=2.26.0'

cli_requirements = [
    'click>=8.0.3',
    'pyqrcode>=1.2.1',
    'pypng>=0.0.21',
    requests_socks,
]

test_requirements = [
    'pytest',
    requests_socks,
]

with open("README.md", "r") as fh:
    long_description = fh.read()

from cktap.version import __version__

setup(
    name='coinkite-tap-protocol',
    version=__version__,
    packages=[ 'cktap' ],
    python_requires='>3.6.0',
    install_requires=requirements,
    extras_require={
        'cli': cli_requirements,
        'test': test_requirements,
    },
    url='https://github.com/coinkite/coinkite-tap-proto',
    author='Coinkite Inc.',
    author_email='support@coinkite.com',
    description="Communicate with your TAPSIGNER or SATSCARD using Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points='''
        [console_scripts]
        cktap=cktap.cli:main
    ''',
    classifiers=[
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
    ],
)

