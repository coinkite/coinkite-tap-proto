
# Changes Between Versions

The "applet" reports a version number in the status field.

This document explains differences between versions.

## 1.0.0 - July 2022

- Bugfix: In some situations, a new `card_nonce` was picked, and
not reported to the caller because an error code (unrelated) was
being reported.  This required an extra call to `status` command
to recover (to learn the updated nonce). In most cases this was
harmless because only error paths had this issue. However, during
the `sign` command, a valid request can fail due to bad luck
(205: unlucky number), and it's easier if we could re-try the verbatim
command immediately with no extra steps. In version 1.0.0 and later,
the `card_nonce` will only be updated if the new value is provided
in a reponse. No change is required to operate with this version,
but efficiencies can be had if considered.

- Bugfix: Invalid arguments to a specific command could
set the tampered flag and brick the SATSCARD. Fixed.

- Bugfix: The 'certs' command included the `card_nonce` but that
was not called for in the protocol spec, and isn't needed. Removed.

- Bugfix: Nonce values provided have to be "non weak", meaning that
all bytes cannot be the same. The code that checks this on the card
had a bug and would reject as "weak" some cases that do satify the
requirement. Very slim odds of hitting this bug if you pick nonces
randomly.

- SATSCHIP model: this product variant is a TAPSIGNER in all respects,
except, as of v1.0.0: `num_backups` in status field is omitted, and
a flag `satschip=True` will be present instead. The "backup" command
is not supported and will fail with 404 error.

## 0.9.0 - March 2022

- First public version.

