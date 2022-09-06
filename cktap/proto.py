#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# proto.py
#
# Implement the higher-level protocol for cards, both TAPSIGNER and SATSCARD.
#
#
from .bip32 import PubKeyNode
from cktap.utils import *
from cktap.constants import *
from cktap.exceptions import CardRuntimeError
from cktap.compat import hash160, CT_sig_verify
from cktap.base58 import encode_base58_checksum

class CKTapCard:
    #
    # Protocol/wrapper for cards. Call methods on this instance to get work done.
    #
    # MAYBE: split into TAPSIGNER vs. SATSCARD subclasses and then some methods
    # which aren't appropriate would not exist in the instance. Seems pointless.
    #
    def __init__(self, transport):
        self.tr = transport
        self.first_look()

    def __repr__(self):
        kk = getattr(self, 'card_ident', '???')
        ty = 'TAPSIGNER' if getattr(self, 'is_tapsigner', False) else 'SATSCARD'
        return '<%s %s via %s: %s> ' % (self.__class__.__name__, ty, self.tr.name, kk)

    def close(self):
        # optional? cleanup connection
        self.tr.close()
        del self.tr

    def send(self, cmd, raise_on_error=True, **args):
        # Send a command, get response, but also catch some card state
        # changes and mirror them in our state.
        # - command is a short string, such as "status"
        # - see the protocol spec for arguments here
        stat_word, resp =  self.tr.send(cmd, **args)

        if stat_word != SW_OKAY:
            # Assume error if ANY bad SW value seen; promote for debug purposes
            if 'error' not in resp:
                resp['error'] = "Got error SW value: 0x%04x" % stat_word
            resp['stat_word'] = stat_word


        if 'card_nonce' in resp:
            # many responses provide an updated card_nonce needed for
            # the *next* comand. Track it.
            # - only changes when "consumed" by commands that need CVC
            self.card_nonce = resp['card_nonce']

        if raise_on_error and 'error' in resp:
            msg = resp.pop('error')
            code = resp.pop('code', 500)
            raise CardRuntimeError(f'{code} on {cmd}: {msg}', code, msg)

        return resp

    def first_look(self):
        # Call this at end of __init__ to load up details from card
        # - can be called multiple times

        st = self.send('status')
        assert 'error' not in st, 'Early failure: ' + repr(st)
        assert st['proto'] == 1, "Unknown card protocol version"
        if st.get('tampered'):
            print("WARNING: Card has set tampered flag!")

        self.card_pubkey = st['pubkey']
        self.card_ident = card_pubkey_to_ident(self.card_pubkey)

        self.applet_version = st['ver']
        self.birth_height = st.get('birth', None)
        self.is_testnet = st.get('testnet', False)
        self.auth_delay = st.get('auth_delay', 0)

        self.is_tapsigner = st.get('tapsigner', False)
        self.is_satschip = self.is_tapsigner and ('num_backups' not in st)      # v1.0.0 required
        if self.is_satschip:
            self.product_name = 'SATSCHIP'
        elif self.is_tapsigner:
            self.product_name = 'TAPSIGNER'
        else:
            self.product_name = 'SATSCARD'

        self.active_slot, self.num_slots = st.get('slots', (0,1))
        assert self.card_nonce      # self.send() will have captured from first status req

        # certs will not verify on emulator, and expensive to do more than once in
        # normal cases too
        self._certs_checked = bool(self.tr.is_emulator)

    def send_auth(self, cmd, cvc, **args):
        # Take CVC and do ECDH crypto and provide the CVC in encrypted form
        # - returns session key and usual auth arguments needed
        # - skip if CVC is None and just do normal stuff (optional auth on some cmds)
        # - for commands w/ encrypted arguments, you must provide to this function

        if cvc:
            session_key, auth_args = calc_xcvc(cmd, self.card_nonce, self.card_pubkey, cvc)
            args.update(auth_args)
        else:
            session_key = None

        # A few commands take an encrypted argument (most are returning encrypted
        # results) and the caller didn't know the session key yet. So xor it for them.
        if cmd == 'sign':
            args['digest'] = xor_bytes(args['digest'], session_key)
        elif cmd == 'change':
            args['data'] = xor_bytes(args['data'], session_key[0:len(args['data'])])

        return session_key, self.send(cmd, **args)


    #
    # Wrappers and Helpers
    #
    def get_address(self, faster=False, incl_pubkey=False, slot=None, cvc=None):
        # Get current payment address for card
        # - does 100% full verification by default
        # - returns a bech32 address as a string, or tuple(compressed_pubkey, bech32),
        assert not self.is_tapsigner

        LAST_SLOT = NUM_SLOTS - 1
        # card firmware <= 1.0.2 contains off by one bug
        # to get pubkey of last slot one has to provide cvc
        # if incl_pubkey=True and (slot=9 or (slot=None and cur_slot=9)) and cvc=None
        # then pubkey is None and only address is returned
        # with correct cvc specified both pubkey bytes and corresponding address string are returned
        # NOT a security issue

        st = self.send('status')
        cur_slot = st['slots'][0]
        if slot is None:
            slot = cur_slot

        if ('addr' not in st) and (cur_slot == slot) and slot != 9: # last slot is exception
            # Current slot is not yet setup.
            return (None, None) if incl_pubkey else None

        if slot == cur_slot == LAST_SLOT:  # last slot (all UNSEALED)
            rr = self.send('dump', slot=slot)
            addr = rr["addr"]
            if incl_pubkey:
                if 'pubkey' in rr:
                    # v1.0.3 and later: pubkey is provided in un-auth reply
                    return rr['pubkey'], addr

                # before v1.0.3, auth will be needed for this case
                ses_key, rr = self.send_auth('dump', cvc=cvc, slot=slot)
                pubkey = rr.get("pubkey")
                # exit is needed here in this special case as we cannot reach verification - would fail
                # certificate verification fails if slot pubkey is used instead of None
                # additional verification fail with invalid state error
                return pubkey, addr
            return addr

        if slot != cur_slot:
            # Use the unauthenticated "dump" command.
            rr = self.send('dump', slot=slot)

            if incl_pubkey:
                if 'pubkey' in rr:
                    # after v1.0.3 pubkey is provided in un-auth reply
                    return rr['pubkey'], rv['addr']

                raise RuntimeError('can only get pubkey for current slot')

            return rr['addr']

        # Use special-purpose "read" command for current (sealed) slot.
        n = pick_nonce()
        rr = self.send('read', nonce=n)

        pubkey, addr = recover_address(st, rr, n)

        # check certificate chain
        if not self._certs_checked and not faster:
            self.certificate_check(None if slot == LAST_SLOT else pubkey)

        if not faster:
            # additional check: did card include chain_code in generated private key?
            my_nonce = pick_nonce()
            card_nonce = self.card_nonce
            rr = self.send('derive', nonce=my_nonce)
            master_pub = verify_master_pubkey(rr['master_pubkey'], rr['sig'],
                                                rr['chain_code'], my_nonce, card_nonce)
            derived_addr,_ = verify_derive_address(rr['chain_code'], master_pub,
                                                        testnet=self.is_testnet)
            if derived_addr != addr:
                raise ValueError("card did not derive address as expected")

        if incl_pubkey:
            return pubkey, addr

        return addr

    address = get_address       # older member name

    def _get_derivation(self) -> List[int]:
        # TAPSIGNER only: what's the current derivation path, which might be
        # just empty (aka 'm').
        assert self.is_tapsigner
        st = self.send('status')
        path = st.get('path', None)
        if path is None:
            raise RuntimeError("No private key picked yet.")
        return path

    def get_derivation(self) -> str:
        return path2str(self._get_derivation())

    def _set_derivation(self, path: List[int], cvc):
        # TAPSIGNER only: what's the current derivation path, which might be
        # just empty (aka 'm').
        assert self.is_tapsigner

        if self._get_derivation() == path:
            # we are already at desired path - NOOP
            return

        if len(path) > DERIVE_MAX_BIP32_PATH_DEPTH:
            raise ValueError(f"No more than {DERIVE_MAX_BIP32_PATH_DEPTH} path components allowed.")

        if not all_hardened(path):
            raise ValueError("All path components must be hardened")

        _, resp = self.send_auth('derive', cvc, path=path, nonce=pick_nonce())

        # XPUB would be better result here, but caller can use get_xpub() next

        return len(path), resp['chain_code'], resp['pubkey']

    def set_derivation(self, path: str, cvc):
        return self._set_derivation(path=str2path(path), cvc=cvc)

    def get_xfp(self, cvc):
        # fetch master xpub, take pubkey from that and calc XFP
        assert self.is_tapsigner
        _, st = self.send_auth('xpub', cvc, master=True)
        xpub = st['xpub']
        return hash160(xpub[-33:])[0:4]

    def get_xpub(self, cvc, master=False):
        # fetch XPUB, either derived or master one
        # - result is BIP-32 serialized and base58-check encoded
        assert self.is_tapsigner
        _, st = self.send_auth('xpub', cvc, master=master)
        xpub = st['xpub']
        return encode_base58_checksum(xpub)

    def get_pubkey(self, cvc=None, subpath:str=None):
        # TAPSIGNER: Get the public key for current derived path
        # SATSCARD: Get pubkey of current slot which must be sealed, else return None
        # - on TS, it's an authenticated command: 'read'
        # - equiv. to get_xpub(master=False) and looking at part of that value
        # - if subpath is provided, fetch the xpub (derived on-card)
        #   and apply further bip32 (unhardened) derivation off-card (here)
        # - in any case, return None if no keypair defined yet for current slot
        st = self.send('status')

        if self.is_tapsigner:
            if 'path' not in st:
                return None

            if not subpath:
                n = pick_nonce()
                ses_key, rr = self.send_auth('read', cvc, nonce=n)

                return recover_pubkey(st, rr, n, ses_key)
            else:
                xpub = self.get_xpub(cvc, master=False)
                hd = PubKeyNode.parse(xpub, testnet=self.is_testnet)
                sk = hd.get_extended_pubkey_from_path(str2path(subpath))

                return sk.sec()
        else:
            # Use special-purpose "read" command, which is unauthenticated
            # - will return error if current slot is unused (meaning no key picked)
            n = pick_nonce()
            try:
                rr = self.send('read', nonce=n)
            except CardRuntimeError as exc:
                if exc.code == 406:     # 'bad state'
                    # current slot is not yet setup w/ private key (ie. unused or unsealed)
                    return None
                raise

            pubkey, _ = recover_address(st, rr, n)

            return pubkey

    def derive_xpub_at_path(self, cvc, fullpath: str):
        # TAPSIGNER: Returns xpub for given full path.
        # - possible side-effect: it may need to change subpath stored on card
        assert self.is_tapsigner

        hardened, non_hardened = split_bip32_path(str2path(fullpath))
        self._set_derivation(path=hardened, cvc=cvc)

        xpub = self.get_xpub(cvc)
        if not non_hardened:
            return xpub

        hd = PubKeyNode.parse(xpub, testnet=self.is_testnet)
        # now derive subpath
        hd0 = hd.get_extended_pubkey_from_path(non_hardened)
        return hd0.extended_public_key()


    def make_backup(self, cvc):
        # read the backup file; gives ~100 bytes to be kept long term
        assert self.is_tapsigner
        _, st = self.send_auth('backup', cvc)
        return st['data']

    def change_cvc(self, old_cvc, new_cvc):
        # Change CVC. Note: can be binary or ascii or digits, 6..32 long
        assert 6 <= len(new_cvc) <= 32
        _, st = self.send_auth('change', old_cvc, data=force_bytes(new_cvc))

    def certificate_check(self, pubkey=None):
        # Verify the certificate chain and the public key of the card
        # - assures this card was produced in Coinkite factory
        # - does not relate to payment addresses or slot usage
        # - raises on errors/failed validation
        # - 'pubkey' is expected key of the sealed slot (or None)
        st = self.send('status')
        certs = self.send('certs')

        n = pick_nonce()
        check = self.send('check', nonce=n)

        rv = verify_certs(st, check, certs, n, pubkey)
        self._certs_checked = True

        return rv

    def get_status(self):
        # read current status
        return self.send('status')

    def unseal_slot(self, cvc):
        # Unseal the current slot (can only be one)
        # - returns (privkey, slot_num)
        assert not self.is_tapsigner

        # only one possible value for slot number
        target = self.active_slot

        # but that slot must be used and sealed (note: unauthed req here)
        resp = self.send('dump', slot=target)

        if resp.get('used', None) == False:
            raise RuntimeError(f"Slot has not been used yet. Use 'setup' cmd first.")

        if resp.get('sealed', None) == False:
            raise RuntimeError(f"Slot has already been unsealed.")

        ses_key, resp = self.send_auth('unseal', cvc, slot=target)

        pk = xor_bytes(ses_key, resp['privkey'])

        return pk, target

    def get_nfc_url(self):
        # Provide the (dynamic) URL that you'd get if you tapped the card.
        return self.send('nfc').get('url')

    def get_privkey(self, cvc, slot):
        # Provide the private key of an already-unsealed slot (32 bytes)
        assert not self.is_tapsigner
        ses_key, resp = self.send_auth('dump', cvc, slot=slot)

        if 'privkey' not in resp:
            if resp.get('used', None) == False:
                raise RuntimeError(f"That slot ({slot}) is not yet used (no key yet)")
            if resp.get('sealed', None) == True:
                raise RuntimeError(f"That slot ({slot}) is not yet unsealed.")

            # unreachable?
            raise RuntimeError(f"Not sure of the key for that slot ({slot}).")

        return xor_bytes(ses_key, resp['privkey'])

    def get_slot_usage(self, slot, cvc=None):
        # Get address and status for a slot, CVC is optional
        # returns:
        #   (addr, status, detail_map) 
        assert not self.is_tapsigner
        session_key, here = self.send_auth('dump', cvc, slot=slot)

        addr = here.get('addr', None)
        if here.get('sealed', None) == True:
            status = 'sealed'
            if slot == self.active_slot:
                addr = self.get_address(faster=True)
        elif (here.get('sealed', None) == False) or ('privkey' in here):
            status = 'UNSEALED'
            if 'privkey' in here:
                pk = xor_bytes(session_key, here['privkey'])
                addr = render_address(pk, self.is_testnet)
        elif here.get('used', None) == False:
            status = "unused"
        else:
            # unreachable.
            raise ValueError(repr(here))

        addr = addr or here.get('addr')

        return (addr, status, here)

    def sign_digest(self, cvc: str, digest: bytes, slot: int=0, subpath: str=None, fullpath: str=None) -> bytes:
        """
        Sign 32 bytes digest and return 65 bytes long recoverable signature.

        Uses derivation path based on current set derivation on card plus optional
        subpath parameter which if provided, will be added to card derivation path.
        subpath can only be of length 2 and non-hardened components only.
        if subpath is specified -> use current derivation + derive subpath
        if fullpath is specified -> subpath is ignored and derivation goes from root

        Returns non-deterministic, recoverable signature (header[1b], r[32b], s[32b])
        """
        if len(digest) != 32:
            raise ValueError("Digest must be exactly 32 bytes")

        if not self.is_tapsigner and (subpath or fullpath):
            raise ValueError(f"Cannot use 'subpath/fullpath' option for {self.product_name}")

        if fullpath:
            # ignore subpath if fullpath is provided
            hardened, sub = split_bip32_path(str2path(fullpath))
            self._set_derivation(path=hardened, cvc=cvc)
        else:
            sub = str2path(subpath) if subpath else []

        if len(sub) > 2:
            raise ValueError(f"Length of subpath {path2str(sub)[2:]} is greater than 2")

        if not none_hardened(sub):
            raise ValueError(f"subpath {path2str(sub)[2:]} contains hardened components")

        if self.is_tapsigner:
            slot = 0

        for _ in range(5):
            try:
                if self.is_tapsigner:
                    ses_key, resp = self.send_auth('sign', cvc, slot=slot, digest=digest, subpath=sub)
                else:
                    # Important: do not pass subpath argument to a SATSCARD
                    # where it is not applicable and triggers a bug in early versions.
                    ses_key, resp = self.send_auth('sign', cvc, slot=slot, digest=digest)

                expect_pub = resp['pubkey']
                sig = resp['sig']
                if not CT_sig_verify(expect_pub, digest, sig):
                    continue
                rec_sig = make_recoverable_sig(digest, sig, addr=None, expect_pubkey=expect_pub,
                                               is_testnet=self.is_testnet)
                return rec_sig
            except CardRuntimeError as err:
                if err.code == 205:  # unlucky number
                    if self.applet_version == '0.9.0':
                        # workaround: get status to update card's nonce
                        self.send('status')
                    continue
                raise

        # probability that we get here is very close to zero
        msg = "Failed to sign digest after 5 retries. Try again."
        raise CardRuntimeError(f'500 on sign: {msg}', 500, msg)

    # TODO
    # - 'wait' command which does delay needed, if any (but has no UX)

# EOF
