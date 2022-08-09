
## Known Limitations

### Path Related (TS)

- path lengths (depth) is limited 8 components in `derive` command
- path array, at CBOR serialized level, must be a definate size, not indefinite size
- in backup file, path components bigger that 32768 will be rendered as hex values
    - for example: `m/12345h/123456h/12345678h` will render as `m/12345h/0x0001e240h/0x00bc614eh`
    - standard paths do not have this property, and typically consist of 1 or 2-digit numbers
    - look for `0x` prefix, and decode as hex if needed

### XFP (Extended Fingerprint) of Derived XPUB Values

- when deriving XPUB values the TAPSIGNER does not calculate the parent's XFP values and instead
  puts in zero as a placeholder value into the XPUB it returns.

### CBOR

- we assume the correct type is provided for the arguments we expect
    - so future commands can add arguments, but not change type of existing ones
    - cannot pass `None` for a integer field; card may or may not work
- card's output CBOR may not be always as concise as possible

### LAST SLOT ISSUE (SC)
- internal off-by-one error on all cards prior to and including version `1.0.0`
- if SATSCARD have all 10 slots UNSEALED, `get_address` function returns None, None
  instead of pubkey and address
- in `cktap` version `1.1.1` workaround was introduced where one can get pubkey and corresponding address
  with `get_address` but has to provide `cvc` (a.k.a. spending code) as named parameter to `get_address`

