# Best Practices

## Overall

1. Never store a CVC (PIN code). Just prompt when needed, and keep in memory
during operation. You should associate it with the `card_ident` (card pubkey)
and if a different card is seen, assume a new CVC is needed.

2. Always verify the factory certificate of the card before trusting
any data from it. Otherwise, your users will be tricked by cloned
or emulated cards.

3. Verify that when the card picks a key it uses BIP-32 chain code you gave it.
Take the `chain_code` your code provided, and check that the public key it
gives after picking is derived using that `chain_code`. This check applies to
both the SATSCARD, where the path is always `m/0` and also the TAPSIGNER,
where you may control the derivation path. On the TAPSIGNER, the `xpub`
command should return the same chain code as you proided.

4. You can safely assume the PIN code (CVC) is all-numeric and provide
your users with a digits-only on-screen keyboard.


## SATSCARD

1. Do not prompt for CVC (PIN code) unless you truly need it. For example, if you
are showing the "balance" there is no need for the code. If the user is verifying
someone else's card (for example, before a business transaction is completed),
then you've risked the funds involved if the CVC is required. In many cases,
if you can make the CVC
**optional** you've got the best of all worlds: owners of the card, who
trust your app, can make use of the CVC and others do not need to.

2. Highlight when the first slot is unsealed. It is not bad or
wrong, but it means that the QR code printed on the card back should
no longer be used. The assumption is once a slot is unsealed, the
private key is public.

3. Not all SATSCARD will have a printed QR on the back. For now,
all cards will have the first slot picked at factory, but we may ship
a SATSCARD someday with the first slot unused. In that case, the `chain_code`
argument to `setup` must be provided by your app (32-byte nonce).

4. When unsealing a slot, you should probably setup the next slot in the
same operation. And yet, please handle cards which have no ready-to-use
slot: setup the next slot on request.

5. Although the protocol and library number slots from zero, as
programmers prefer, when communicating with users, the slots should
start at number one. So externally, they are 1..10 and internally
0..9. When possible, it's best to say "the first slot" when talking
about the QR code on the back and the default settings.


## TAPSIGNER

1. Set the derivation path once, then just add the final two components
(change/not change, and index) when signing digests (see `subpath` argument).

2. Do not try to do anything special with a SATSCHIP if you detect it, just
operate like it was a normal TAPSIGNER (because it is, with the exception of
the backup command).

3. Never prompt your user for the AES key printed on the card. It's
for emergencies only and once used, the TAPSIGNER is no longer
secure. For backup purposes, capture the data and save it as binary.

4. Encourage users to change the CVC from factory default.


## SATSCHIP

1. Treat it just like a TAPSIGNER.

2. Remember it cannot be backed-up and the keys are known only to the card itself, so
consider long and hard before you put big sats under its sole signature.

