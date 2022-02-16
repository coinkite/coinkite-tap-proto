# Emulator

A python emulator of a single card.

- the CVC is: 123456
- for TAPSIGNER, AES key is: 41414141414141414141414141414141
- precise error codes will differ from real product
- completely insecure
- uses wallycore for Bitcoin math
- this code is independant of `cktap` and is stand-alone.
- no attempt to make it portable: might be MacOS only

## Usage

```
Usage: ecard.py [OPTIONS] COMMAND [ARGS]...

Options:
  -q, --quiet             Less debugging
  -t, --testnet           Operate on testnet3 rather than mainnet
  -r, --rng-seed integer  Seed value for (not) RNG
  --help                  Show this message and exit.

Commands:
  emulate    Emulate a card which has just powered on after CAP loaded.
  satscard   Build a SATSCARD and do the basics with it.
  tapsigner  Build a TAPSIGNER card and do the basics with it.
```

Command usage:

```shell
# emulate a factory-fresh card
% ./ecard.py emulate -f
```

```shell
# emulate a SATSCARD with first slot populated, certificate chain installed
% ./ecard.py emulate
```

```shell
# emulate a TAPSIGNER with no key picked yet
% ./ecard.py emulate -t
```

When emulating a card, commands can be sent to the Unix domain pipe
at `/tmp/ecard-pipe` as CBOR objects. Responses are CBOR to be decoded.

