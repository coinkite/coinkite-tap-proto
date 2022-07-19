
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
  puts in zero as a placeholder value into the XPUB it returns. The correct parent-XFP value cannot
  be calculated by the clients (when depth>1), nor validated by them, so this value is somewhat
  of a placeholder in any case.

### CBOR

- we assume the correct type is provided for the arguments we expect
    - so future commands can add arguments, but not change type of existing ones
    - cannot pass `None` for a integer field; card may or may not work
- card's output CBOR may not be always as concise as possible

