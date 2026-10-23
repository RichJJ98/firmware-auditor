"""Command line interface for ``firmware-auditor``.

The CLI is intentionally thin: it parses arguments, wires them onto
:class:`~firmware_auditor.core.pipeline.Pipeline` and
:class:`~firmware_auditor.core.reporter.Reporter`, and translates the outcome
into an exit code. No analysis or formatting logic lives here.

Exit codes
----------
=========  ==================================================================
Code       Meaning
=========  ==================================================================
``0``      The audit completed and no finding reached ``--fail-on``.
``1``      At least one finding reached ``--fail-on`` (CI gate tripped).
``2``      Invalid arguments, unusable rootfs, unwritable output, or an
           analyzer failed (the report is then incomplete and must not pass).
``130``    Interrupted with ``Ctrl+C``.
=========  ==================================================================

A failed analyzer deliberately maps to ``2``, never ``1``: a gate that cannot
tell "clean image" from "one analyzer crashed" would silently approve firmware
that was never actually audited.

Severity filtering and the gate
-------------------------------
``--min-severity`` controls what is *reported*; ``--fail-on`` controls what
*exits non-zero*. Suppressing findings that the gate depends on would make the
gate unsound, so the pipeline is always run with the **lower** of the two
thresholds. In practice, ``--min-severity critical --fail-on high`` still shows
the high findings -- they are the ones deciding the exit code.

Output routing
--------------
* No ``--output``: the rendered payload goes to stdout.
* ``--output`` with ``console``: the table goes to stdout *and* the file.
* ``--output`` with ``json``/``sarif``: the payload goes to the file only, and a
  one-line confirmation goes to stderr, keeping stdout free for piping.
* ``--quiet``: stdout is never written; only the exit code (and ``--output``)
  matter.

Encoding
--------
``sys.stdout``/``sys.stderr`` are reconfigured with ``errors="replace"`` so a
legacy Windows code page can never raise :class:`UnicodeEncodeError` mid-report.
Machine-readable payloads are additionally written as UTF-8 bytes through the
underlying buffer, so a JSON or SARIF document is never degraded by the console
code page.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Final, Sequence

from analyzers import (
    AnalyzerConfig,
    Severity,
    available_analyzers,
    build_analyzers,
)
from analyzers.base import GLOBAL_EXCLUDES
from core import (
    OutputFormat,
    Pipeline,
    Reporter,
    RootfsError,
    ScanResult,
    SUPPORTED_FORMATS,
    TOOL_NAME,
    TOOL_VERSION,
)

__all__ = [
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "build_parser",
    "cli",
    "main",
]

#: The audit ran and nothing reached the gate.
EXIT_OK: Final[int] = 0

#: Findings reached the ``--fail-on`` threshold.
EXIT_FINDINGS: Final[int] = 1

#: Usage error, unusable rootfs, unwritable output, or an analyzer failure.
EXIT_ERROR: Final[int] = 2

#: Interrupted by the operator (``128 + SIGINT``, the shell convention).
EXIT_INTERRUPTED: Final[int] = 130

#: Sentinel accepted by ``--fail-on`` to disable the gate entirely.
GATE_NONE: Final[str] = "none"

#: Displayed in ``--help``; ``info`` is permissive, ``critical`` is strict.
_SEVERITY_CHOICES: Final[tuple[str, ...]] = tuple(severity.value for severity in Severity)

#: ``--fail-on`` additionally accepts ``none`` to never exit non-zero.
_GATE_CHOICES: Final[tuple[str, ...]] = (*_SEVERITY_CHOICES, GATE_NONE)

_EPILOG: Final[str] = """\
exit codes:
  0    audit completed and no finding reached --fail-on
  1    findings reached --fail-on (CI gate tripped)
  2    invalid arguments, unusable rootfs, or an analyzer failed
  130  interrupted

The effective severity filter is the lower of --min-severity and --fail-on:
findings that decide the exit code are never hidden from the report.

examples:
  firmware-auditor rootfs/
  firmware-auditor rootfs/ --min-severity medium --format console
  firmware-auditor rootfs/ --format sarif --output firmware.sarif --fail-on high
  firmware-auditor rootfs/ --analyzers filesystem_hygiene --jobs 4
  python -m cli rootfs/ --format json --output report.json --quiet
"""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Returns:
        A parser configured with every supported option and the exit-code
        documentation in its epilog.
    """
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Static security posture auditor for extracted firmware rootfs images. "
            "Read-only: nothing is executed, mounted or modified."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "rootfs",
        nargs="?",
        type=Path,
        metavar="ROOTFS",
        help=(
            "directory containing the extracted firmware filesystem "
            "(e.g. squashfs-root). Required unless --list-analyzers is used."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
        help="show the tool version and exit",
    )
    parser.add_argument(
        "--list-analyzers",
        action="store_true",
        help="list the available analyzers and exit",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=SUPPORTED_FORMATS,
        default=OutputFormat.CONSOLE.value,
        help="report format (default: %(default)s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="PATH",
        default=None,
        help="write the report to PATH (UTF-8, LF line endings) in addition to stdout",
    )
    parser.add_argument(
        "-m",
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default=Severity.INFO.value,
        help="lowest severity included in the report (default: %(default)s)",
    )
    parser.add_argument(
        "--fail-on",
        choices=_GATE_CHOICES,
        default=Severity.HIGH.value,
        help=(
            "severity that makes the command exit with code 1, for CI gating; "
            "'none' never fails (default: %(default)s)"
        ),
    )

    parser.add_argument(
        "-a",
        "--analyzers",
        action="append",
        metavar="NAME[,NAME...]",
        default=None,
        help="run only these analyzers (repeatable, comma-separated; default: all)",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        action="append",
        metavar="GLOB",
        default=None,
        help="skip paths matching GLOB (repeatable), on top of the built-in excludes",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="run N analyzers concurrently; 0 selects an automatic value (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="overall wall-clock budget for the analyzer phase (default: unbounded)",
    )

    parser.add_argument(
        "--group",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="group console findings by rule with counts and sample paths (default: on)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=50,
        metavar="N",
        help="maximum console rows before summarising the remainder (default: %(default)s)",
    )
    parser.add_argument(
        "--color",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force ANSI colours on or off (default: auto-detect a TTY)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="include exception tracebacks in error reports (repeatable)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress stdout entirely; rely on the exit code and --output",
    )

    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject inconsistent argument combinations before doing any work.

    Validation happens here rather than inside the pipeline so the user gets an
    ``argparse``-style message (usage line included) and exit code 2 for what is
    really a usage problem.

    Args:
        parser: Parser used to raise the error.
        args: Parsed namespace.
    """
    if args.list_analyzers:
        return

    if args.rootfs is None:
        parser.error("the following arguments are required: ROOTFS")

    if args.max_rows < 1:
        parser.error("--max-rows must be at least 1")

    if args.jobs < 0:
        parser.error("--jobs must be 0 (automatic) or a positive number")

    if args.timeout is not None and args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")

    if args.output is not None:
        if args.output.exists() and args.output.is_dir():
            parser.error(f"--output is an existing directory: {args.output}")
        parent = args.output.parent
        if str(parent) and not parent.exists():
            parser.error(f"--output directory does not exist: {parent}")


def _parse_gate(parser: argparse.ArgumentParser, value: str) -> Severity | None:
    """Translate ``--fail-on`` into a severity threshold.

    Args:
        parser: Parser used to raise the error.
        value: One of the ``_GATE_CHOICES`` spellings.

    Returns:
        The threshold severity, or ``None`` when the gate is disabled.
    """
    if value == GATE_NONE:
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:  # pragma: no cover - guarded by argparse choices
        parser.error(str(exc))
        raise AssertionError("unreachable") from exc


def _resolve_analyzer_names(args: argparse.Namespace) -> list[str] | None:
    """Flatten and split the ``--analyzers`` values.

    Supports both ``-a a,b`` and ``-a a -a b``.

    Args:
        args: Parsed namespace.

    Returns:
        The requested names, or ``None`` when every analyzer should run.
    """
    if args.analyzers is None:
        return None
    names: list[str] = []
    for chunk in args.analyzers:
        names.extend(part.strip() for part in chunk.split(",") if part.strip())
    return names or None


def _effective_min_severity(min_severity: Severity, gate: Severity | None) -> Severity:
    """Return the lower of the reporting and gating thresholds.

    The pipeline filters findings once, so running it at the reporting threshold
    would discard the very findings ``--fail-on`` needs to inspect.

    Args:
        min_severity: Threshold requested for display.
        gate: Threshold that decides the exit code, or ``None`` when disabled.

    Returns:
        The threshold to hand to the pipeline.
    """
    if gate is None:
        return min_severity
    return min_severity if min_severity.weight <= gate.weight else gate


# ---------------------------------------------------------------------------
# Stream handling
# ---------------------------------------------------------------------------


def _configure_streams() -> None:
    """Make stdout/stderr encoding-tolerant.

    A firmware audit reports arbitrary file names, so a strict ``cp1252`` console
    must degrade characters rather than abort a finished scan with
    :class:`UnicodeEncodeError`.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):  # pragma: no cover - detached or closed stream
            continue


def _emit(payload: str) -> None:
    """Write a report payload to stdout.

    Report payloads are emitted as UTF-8 bytes through the underlying buffer so
    JSON and SARIF documents are never degraded by the console code page. When no
    buffer is available (an in-memory stream in tests, for example) the text is
    written directly.

    Args:
        payload: Complete document, already newline-terminated.
    """
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(payload.encode("utf-8"))
        buffer.flush()
        return
    sys.stdout.write(payload)
    sys.stdout.flush()


def _status(message: str) -> None:
    """Write a progress/confirmation line to stderr.

    Status goes to stderr so that stdout stays a clean machine-readable channel.

    Args:
        message: Text to print.
    """
    sys.stderr.write(f"{TOOL_NAME}: {message}\n")
    sys.stderr.flush()


def _error(message: str) -> None:
    """Write an error line to stderr.

    Args:
        message: Text to print.
    """
    sys.stderr.write(f"{TOOL_NAME}: error: {message}\n")
    sys.stderr.flush()


def _use_color(requested: bool | None) -> bool:
    """Decide whether ANSI colour should be emitted.

    Args:
        requested: ``True``/``False`` from ``--color``/``--no-color``, or ``None``
            to auto-detect.

    Returns:
        ``True`` when colour should be used.
    """
    if requested is not None:
        return requested
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


# ---------------------------------------------------------------------------
# Exit code policy
# ---------------------------------------------------------------------------


def _exit_code(result: ScanResult, gate: Severity | None) -> int:
    """Map a finished scan onto a process exit code.

    Args:
        result: Outcome of the pipeline run.
        gate: Threshold that trips the gate, or ``None`` when disabled.

    Returns:
        :data:`EXIT_ERROR` when any analyzer failed, :data:`EXIT_FINDINGS` when a
        finding reached the gate, :data:`EXIT_OK` otherwise.
    """
    if not result.successful:
        for error in result.errors:
            _error(f"{error.analyzer} failed: {error.error_type}: {error.message}")
            if error.traceback_text:
                sys.stderr.write(error.traceback_text)
                if not error.traceback_text.endswith("\n"):
                    sys.stderr.write("\n")
        _error(
            f"the audit is incomplete: {len(result.errors)} analyzer(s) failed, "
            "so its results cannot be trusted as a pass"
        )
        return EXIT_ERROR

    if gate is None:
        return EXIT_OK

    tripped = sum(1 for finding in result.findings if finding.severity.meets(gate))
    if tripped:
        _status(
            f"gate tripped: {tripped} finding(s) at or above "
            f"'{gate.value}' (exit {EXIT_FINDINGS})"
        )
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------


def _print_analyzers() -> None:
    """Print the analyzer catalogue to stdout."""
    rows: list[tuple[str, str, str]] = []
    for analyzer_class in available_analyzers().values():
        prototype = analyzer_class()
        rows.append((prototype.name, prototype.version, prototype.description or ""))
    width = max((len(name) for name, _version, _description in rows), default=0)

    lines = ["Available analyzers:", ""]
    for name, version, description in rows:
        lines.append(f"  {name.ljust(width)}  {version.ljust(8)}  {description}")
    lines.extend(
        [
            "",
            "Select a subset with --analyzers NAME[,NAME...].",
        ]
    )
    _emit("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface.

    Args:
        argv: Argument list excluding the program name. ``None`` uses
            :data:`sys.argv`.

    Returns:
        The process exit code: ``0`` clean, ``1`` gate tripped, ``2`` error,
        ``130`` interrupted.

    Raises:
        SystemExit: For ``--version``/``--help`` and for argument errors, which
            ``argparse`` raises with the conventional code ``2``.
    """
    _configure_streams()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    _validate_args(parser, args)

    if args.list_analyzers:
        _print_analyzers()
        return EXIT_OK

    if args.rootfs is None:  # pragma: no cover - _validate_args already rejected it
        parser.error("the following arguments are required: ROOTFS")

    gate = _parse_gate(parser, args.fail_on)
    min_severity = Severity.parse(args.min_severity)
    exclude_globs = tuple(GLOBAL_EXCLUDES) + tuple(args.exclude or ())
    config = AnalyzerConfig(exclude_globs=exclude_globs)

    try:
        analyzers = build_analyzers(_resolve_analyzer_names(args), config)
        pipeline = Pipeline(
            analyzers,
            config=config,
            max_workers=args.jobs,
            min_severity=_effective_min_severity(min_severity, gate),
            timeout_seconds=args.timeout,
            capture_traceback=args.verbose > 0,
        )
    except ValueError as exc:
        parser.error(str(exc))
        raise AssertionError("unreachable") from exc

    try:
        result = pipeline.run(args.rootfs)
    except RootfsError as exc:
        _error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error("interrupted")
        return EXIT_INTERRUPTED
    except OSError as exc:  # pragma: no cover - filesystem race or permission
        _error(f"the audit could not read the rootfs: {exc}")
        return EXIT_ERROR

    output_format = OutputFormat.parse(args.format)
    # Two renderers on purpose: a saved console report must not contain ANSI
    # escapes, which would poison diffs, patches and log parsers. The screen
    # keeps colour; the file is always plain.
    screen_reporter = Reporter(
        color=_use_color(args.color),
        group_by_rule=args.group,
        max_console_rows=args.max_rows,
    )
    file_reporter = Reporter(
        color=False,
        group_by_rule=args.group,
        max_console_rows=args.max_rows,
    )

    try:
        payload = screen_reporter.render(result, output_format)
    except (TypeError, ValueError) as exc:  # pragma: no cover - internal invariant
        _error(f"failed to render the report: {exc}")
        return EXIT_ERROR

    if args.output is not None:
        try:
            file_reporter.write(result, args.output, output_format)
        except OSError as exc:
            _error(f"cannot write {args.output}: {exc}")
            return EXIT_ERROR

    if not args.quiet:
        if args.output is None or output_format is OutputFormat.CONSOLE:
            _emit(payload)
        else:
            _status(
                f"report written to {args.output} "
                f"({result.total_findings} finding(s), {output_format.value})"
            )

    return _exit_code(result, gate)


def cli() -> None:
    """``console_scripts`` entry point: exit with :func:`main`'s code."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
