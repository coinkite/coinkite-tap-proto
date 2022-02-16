# Developer's Guide and Usage Hints for TAPSIGNER

### Setup Sequence

- verify legit card (certificate check), and empty
- do "new" command to pick secret
- "derive" your favourite path, if it's not "84h/0h/0h"
- capture a backup (do not prompt for AES key, ever)
- get new PIN code from user
- set PIN

### Usage

- take the hardened parts of your favourite subkey
- use "derive" command once to set it
- use "sign" command with non-hardened (0/0... 1/0, 0/99, etc) parts
- remember to retry sign command if you are unlucky


