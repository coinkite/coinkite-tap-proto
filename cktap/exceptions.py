#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Exceptions
#

class CardRuntimeError(RuntimeError):
    def __init__(self, msg, code, raw_msg):
        self.code = code
        self.raw_msg = msg
        super().__init__(msg)

# EOF
