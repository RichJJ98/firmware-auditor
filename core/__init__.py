"""Core services: analysis orchestration and report generation.

This package is the glue between the analyzer plugins and the outside world:

* :mod:`firmware_auditor.core.pipeline` -- validation, execution of the
  registered analyzers with error isolation, and the :class:`ScanResult` object
  that holds everything a reporter needs.
* :mod:`firmware_auditor.core.reporter` -- rendering that result as a terminal
  summary, as JSON, or as SARIF v2.1.0 for GitHub Advanced Security.

Typical use::

    from pathlib import Path

    from firmware_auditor.core import Pipeline, Reporter, OutputFormat

    result = Pipeline().run(Path("rootfs"))
    print(Reporter(color=True).render(result, OutputFormat.CONSOLE))
    Reporter().write(result, Path("report.sarif"), OutputFormat.SARIF)

The command line interface (:mod:`firmware_auditor.cli`) is a thin wrapper over
these two components; it adds argument parsing, exit codes and stdout encoding
handling, but no analysis or formatting logic of its own.
"""

from __future__ import annotations

from core.pipeline import (
    AnalyzerReport,
    Pipeline,
    RootfsError,
    ScanError,
    ScanResult,
    TOOL_NAME,
    TOOL_VERSION,
)
from core.reporter import (
    OutputFormat,
    Reporter,
    SARIF_SCHEMA,
    SARIF_VERSION,
    SUPPORTED_FORMATS,
)

__all__ = [
    # Orchestration.
    "AnalyzerReport",
    "Pipeline",
    "RootfsError",
    "ScanError",
    "ScanResult",
    "TOOL_NAME",
    "TOOL_VERSION",
    # Reporting.
    "OutputFormat",
    "Reporter",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SUPPORTED_FORMATS",
]
