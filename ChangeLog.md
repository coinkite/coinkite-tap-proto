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

