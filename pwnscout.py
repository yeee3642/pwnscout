#!/usr/bin/env python3
"""Zero-install launcher: `python3 pwnscout.py scan 10.0.0.0/24`.

Lets you run the tool straight from a cloned repo without `pip install`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwnscout.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
