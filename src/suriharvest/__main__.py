"""python -m suriharvest (used by the ./suriharvest launcher)."""

import sys

from suriharvest.cli import main

sys.argv[0] = "suriharvest"
main()
