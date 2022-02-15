#
# Coinkite Tap protocol and python support library
#

# To use this command to install and yet be able to edit the code (here). Great for dev:
#
#   pip install --editable .
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
    'base58>=2.1.1',
    'pyscard>=2.0.2',
]

if 1:
    # We support wallycore or coincurve; both of which
    # ultimately call libsecp256k1 
    #
    # - but I could not compile wallycore on windows
    # - prolly because coincurve has 500+ lines of setup.py code
    # - sorry I could not make this file detect O/S automatically?!
    #
    requirements.extend([
        'coincurve>=15.0.1',
        'bip32>=2.1',
    ])
else:
    requirements.extend([
        'wallycore>=0.8.2',
    ])

cli_requirements = [
    'click>=8.0.3',
    'pyqrcode>=1.2.1',
    'pypng>=0.0.21',
    'requests[socks]>=2.26.0',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

from cktap import __version__

setup(
    name='coinkite-tap-protocol',
    version=__version__,
    packages=[ 'cktap' ],
    python_requires='>3.6.0',
    install_requires=requirements,
    extras_require={
        'cli': cli_requirements,
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

