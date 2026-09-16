"""PyInstaller entry point for ThreatLens.exe.

Kept separate from the package so PyInstaller has a concrete script to analyse. Running the
executable with no arguments opens the live dashboard (handled in ``threatlens.cli.main``);
any arguments are the normal CLI.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    from threatlens.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    multiprocessing.freeze_support()  # harmless; guards if any dependency spawns processes
    sys.exit(main())
