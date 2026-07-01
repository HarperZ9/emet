# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""emet - a small external witness for AI oversight.

Re-derive the bytes, get one of three verdicts (MATCH / DRIFT / UNVERIFIABLE),
trust nothing in-band. SPEC.md is the normative contract; this package is the
Python reference implementation. Importing the package has no side effects.
"""
__version__ = "1.0.0"
