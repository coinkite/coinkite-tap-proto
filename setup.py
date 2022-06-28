#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
#
# Coinkite Tap protocol and python support library
#

from cktap import __version__

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
    'pyscard>=2.0.2',
]

# for servers that work w/ offline data and dont have NFC readers
offline_requirements = [r in requirements if 'pyscard' not in r]

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

# only for developers playing with crypto libraries - cross library comparisons
test_plus_requirements = [
    'coincurve>=15.0.1',
    'wallycore>=0.8.2',
    # needs libsecp256k1 installed (check project README.md)
    #'python-secp256k1@git+https://github.com/scgbckbone/python-secp256k1.git',
] + test_requirements

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='coinkite-tap-protocol',
    version=__version__,
    packages=[ 'cktap' ],
    python_requires='>3.6.0',
    install_requires=requirements,
    extras_require={
        'cli': cli_requirements,
        'test': test_requirements,
        'test_plus': test_plus_requirements,
        'offline': offline_requirements,
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

