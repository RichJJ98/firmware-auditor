"""firmware-auditor: static security posture auditing for embedded Linux images.

The package inspects an **already extracted** firmware rootfs (SquashFS, ext4,
UBIFS, ...) and reports security-relevant misconfigurations. It is strictly
static and read-only: nothing is executed, mounted, chrooted or modified.

Typical programmatic use::

    from pathlib import Path
    from firmware_auditor.analyzers import build_analyzers

    for analyzer in build_analyzers():
        for finding in analyzer.run(Path("rootfs")):
            print(finding.severity.label, finding.file_path, finding.title)

The command line interface lives in :mod:`firmware_auditor.cli`; the concurrent
orchestrator and the JSON/SARIF reporters live under :mod:`firmware_auditor.core`.
"""

from __future__ import annotations

from analyzers.base import (
    AnalyzerConfig,
    AnalyzerError,
    BaseAnalyzer,
    Finding,
    Severity,
)

__version__ = "1.0.0"
__author__ = "firmware-auditor contributors"
__license__ = "MIT"

__all__ = [
    "AnalyzerConfig",
    "AnalyzerError",
    "BaseAnalyzer",
    "Finding",
    "Severity",
    "__version__",
]
