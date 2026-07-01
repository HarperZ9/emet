# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Back-compat shim. The shared marker-corpus loader now lives in emet/corpus.py.
Re-exported here so `import corpus` (and importlib.reload on it) keeps working;
corpus_path() reads EMET_CORPUS at call time, so behaviour is unchanged."""
from emet.corpus import *  # noqa: F401,F403
from emet.corpus import (  # noqa: F401  (explicit re-export for importlib.reload consumers)
    CorpusError, corpus_path, load, scan, count, matches_at, REPL, DEFAULT_NAME,
)
