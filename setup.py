#
# Coinkite Tap protocol and python support library
#

# To use this command, during dev, install and yet be able to edit the code:
#
#   pip install --editable .
#

from setuptools import setup

# these minimum versions are untested, some earlier values would probably work too.
requirements = [
    'cbor2>=5.4.1',
    'bech32>=1.2.0',
    'coincurve>=15.0.1',
    #'secp256k1>=0.14.0',
    'bip32>=2.1',
]

cli_requirements = [
    'click>=8.0.3',
    'pyqrcode>=1.2.1',
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

