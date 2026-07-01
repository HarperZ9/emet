# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Enables `python -m emet ...`, equivalent to the `emet` console script."""
from .cli import main

if __name__ == "__main__":
    main()
