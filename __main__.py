"""Entry point for running the flat distribution's ``__main__.py``.

A ``__main__`` module can be executed without installing a console script,
which matters in the environments this tool targets: analysts often copy the
project onto an air-gapped host and run it from a checkout rather than through
``pip``.

The module does nothing but delegate to :func:`firmware_auditor.cli.main` and
forward its exit code, so both invocation styles behave identically::

    python __main__.py rootfs/
    python -m cli rootfs/
    firmware-auditor rootfs/          # after installation (console_scripts)

Exit codes are documented in :mod:`firmware_auditor.cli` (``0`` clean, ``1``
gate tripped, ``2`` error, ``130`` interrupted).
"""

from __future__ import annotations

from cli import main

if __name__ == "__main__":
    raise SystemExit(main())
