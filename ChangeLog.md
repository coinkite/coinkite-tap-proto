# 1.2.1
- enhancement: take advantage of v1.0.3 on SATSCARD which shares pubkey on unsealed slots
- enhancement: add optional slot number to `cktap address` command 
- enhancement: export pubkey using `cktap address --pubkey` argument
- bugfix: `cktap open` (no slot number) would fail

# 1.2.0
- fix: `wif` cli command to properly handle last slot
- workaround: last slot bug - check `docs/limitations.md`
- cli: changed numbering system in UX (cli.py) from 0..9 to 1..10 and implemented internal conversion
  to 0..9 as backend still operates on sane indexes
- emulator: `ecard.py` fixed active_slot off by one error

# 1.1.0

- support for v1.0.0 cards
- rename `CKTapCard.address()` to `CKTapCard.get_address()`, but old name still works
- for SATSCARDS version 1.0.0 or later, when verifying the factory certficate, the
  pubkey for the current sealed slot (if any) is needed, and the card attests to it.
    - new 'pubkey' argument to `check_certs()`, which can be None for other cases
    - flow inside `get_address()` is different, so that it has the pubkey when needed
- `get_pubkey()` expanded to support SATSCARD where it returns pubkey of current sealed slot
    - `cvc` argument now optional (for SATSCARD usage only)
    - will return None if no key at this point, not an error
- cli: global arguments for providing a different root factory certificate (for emulator usage)
- emulator: `ecard.py` reworked to emulate v0.9.0 or v1.0.0 and SATSCHIP support, etc

# 1.0.5
- add ability to derive non hardened derivations with library (not possible with card - card can only derive hardened path components)
- 'sign_digest' accepts new 'fullpath' parameter where full bip 32 string path can be passed
- support for SATSCHIP v1.0.0 product
- shell output for backup command improved
- adds `card.product_name` string

# 1.0.4

- remove pyscard as hard requirement, so possible to use library on web servers
- reworks contents of upload file for SATSCHIP
- refactor `verify_certs()`

# 1.0.3

- new 'offline' subset of requirements, for things like servers w/o NFC

# 1.0.2

- changes to support SATSCHIP, including upload of metadata and artwork.

# 1.0.1

- tiny change to support production needs, where ATR value is in transition.

# 1.0.0

- default crypto library is now pure python and in library itself, which means there is no need to have any crypto library dependency. However we provide wrappers for coincurve, wallycore and pysecp256k1 if one wants to use them.
- added wrapper for pysecp256k1 library
- new `cktap --version` command to get cktap library version during runtime
- remove all objects but `__version__` from `cktap.__init__`, before one was able to import `find_first` and `find_cards` from cktap directly, now you need to import from transport like this `from cktap.transport import find_cards, find_first`
- minor bug fixes and improvements

# 0.9.1

- minor bug fixes

# 0.9.0

- first public release

