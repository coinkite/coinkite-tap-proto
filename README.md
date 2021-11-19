# Coinkite Tap Protocol and Helper Program

This python library will make it easy to talk to the TAPSIGNER and SATSCARD.

This repo includes:

1. The protocol specification
2. Python library for speaking the protocol
3. (maybe) Examples/libraries in other languages

# Protocol Spec

See files in <./docs>.

# Install

This is the python code and command-line utilities you need to communicate with it over USB.

## Setup For Everyday Use

- `pip install 'coinkite-tap-proto[cli]'`

This installs a single helpful command line program: `cktap`

If you just want the python library, use:

- `pip install coinkite-tap-proto`


## Setup If You Might Change the Code

- do a git checkout
- probably make a fresh virtual env
- run:

```
pip install -r requirements.txt
pip install --editable '.[cli]'
```

## Requirements

- python 3.6 or higher
- ``pyscard` for acceess to smartcard readers
- a supported smart-card reader:
    - "ACS ACR122U" is recommended
    - but most smartcard USB class-compliant devices should work.
- see `requirements.txt` file for more details.

# CLI Examples

## Command Arguments

