# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Back-compat shim. The closed verdict lattice now lives in emet/verdict.py.
Re-exported here so `import verdict` keeps working for out-of-package consumers."""
from emet.verdict import *  # noqa: F401,F403
from emet.verdict import (  # noqa: F401
    governed, VerdictError, LATTICE, COHERENCE, CORROBORATE, AUDIT,
    MONITOR_FILE, MONITOR_BASELINE, PERCEPTION, REVERT, FORBIDDEN,
)
