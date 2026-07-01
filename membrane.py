#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Back-compat shim. The EMET Python reference now lives in the emet/ package;
this keeps `python membrane.py ...` and `python conformance/run.py membrane.py`
working byte-for-byte. The real implementation is emet/membrane.py (which is the
selftest artifact-of-record, hashed with its sibling core modules)."""
from emet.membrane import main

if __name__ == "__main__":
    main()
