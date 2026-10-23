"""Analyzer orchestration: validation, execution, error isolation and ordering.

The pipeline is the only component that decides *when* analyzers run; the
analyzers themselves stay ignorant of each other and of the reporting layer.

Design contract
---------------
* **Validation first.** The rootfs is resolved and probed before any analyzer is
  touched, so an unusable path fails with :class:`RootfsError` instead of
  producing a report full of "no findings" that looks like a clean image.
* **Errors never destroy results.** Each analyzer runs inside its own guarded
  call. An analyzer that crashes (missing dependency, unparsable firmware oddity,
  third-party plugin bug) is recorded as a :class:`ScanError` and the remaining
  analyzers still run. A partial report plus an explicit error beats no report.
* **Output is deterministic.** Reports and findings are sorted regardless of
  completion order, so two runs over the same image produce byte-identical JSON
  and SARIF. Reproducible artifacts are what makes a CI gate trustworthy.
* **Threads, not processes.** The workload is I/O-bound (walking a tree,
  reading headers), findings are small picklable records, and the analyzers hold
  no cross-run state. Threads avoid the spawn cost and the pickling constraints
  that a process pool would impose on Windows and on user-supplied plugins.

Concurrency model
-----------------
``max_workers = 1`` runs one analyzer at a time and is the default: it keeps
memory flat and output trivially reproducible. Values above one run analyzers
concurrently on a thread pool; ``0`` (or a negative value) selects
``min(analyzers, cpus, DEFAULT_MAX_AUTO_WORKERS)``.

``timeout_seconds`` is an **overall** wall-clock budget for the analyzer phase,
not a per-analyzer limit. Python cannot interrupt a running thread, so when the
budget expires the pending analyzers are reported as timed out and their workers
are abandoned rather than killed. A runaway analyzer can therefore keep its
thread alive until the process exits; the deadline bounds the report, not the
CPU. This is stated plainly because pretending otherwise would be a lie in a
security tool.

Usage::

    from pathlib import Path
    from firmware_auditor.core.pipeline import Pipeline

    result = Pipeline(max_workers=2).run(Path("rootfs"))
    if not result.successful:
        for error in result.errors:
            print("error:", error.analyzer, error.message)
    for finding in result.findings:
        print(finding.severity.label, finding.file_path, finding.title)
"""

from __future__ import annotations

import os
import time
import traceback
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeoutError,
    as_completed,
)
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Sequence

try:
    from firmware_auditor import __version__ as TOOL_VERSION
except ModuleNotFoundError:
    # The flat-module installation exposes ``core`` without the source
    # directory's package name.
    TOOL_VERSION = "1.0.0"

from analyzers import build_analyzers
from analyzers.base import AnalyzerConfig, AnalyzerError, BaseAnalyzer, Finding, Severity

__all__ = [
    "AnalyzerReport",
    "Pipeline",
    "RootfsError",
    "ScanError",
    "ScanResult",
    "TOOL_NAME",
]

#: Tool identity written into every JSON/SARIF report.
TOOL_NAME: Final[str] = "firmware-auditor"

#: Upper bound applied when the caller asks for automatic worker selection.
#: Beyond this the analyzers are I/O-bound on the same tree and extra threads
#: only add page-cache contention.
DEFAULT_MAX_AUTO_WORKERS: Final[int] = 4


# ---------------------------------------------------------------------------
# Errors and per-analyzer records
# ---------------------------------------------------------------------------


class RootfsError(ValueError):
    """Raised when the supplied rootfs path cannot be audited.

    The CLI maps this to exit code 2 (usage error) rather than 1 (findings), so a
    broken invocation is never mistaken for a failed security gate.
    """


@dataclass(frozen=True, slots=True)
class ScanError:
    """A non-fatal failure that occurred while running one analyzer.

    Attributes:
        analyzer: Name of the analyzer that failed.
        error_type: Exception class name, e.g. ``FileNotFoundError``.
        message: Human-readable description.
        traceback_text: Full traceback, captured only when explicitly requested
            (``--verbose``); omitted from default reports to keep them small.
    """

    analyzer: str
    error_type: str
    message: str
    traceback_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the error."""
        payload: dict[str, Any] = {
            "analyzer": self.analyzer,
            "error_type": self.error_type,
            "message": self.message,
        }
        if self.traceback_text is not None:
            payload["traceback"] = self.traceback_text
        return payload


@dataclass(frozen=True, slots=True)
class AnalyzerReport:
    """Execution metadata for one analyzer.

    Attributes:
        name: Analyzer identifier.
        version: Rule-pack version reported by the analyzer.
        duration_seconds: Wall-clock time spent inside the analyzer.
        findings: Number of findings it produced (before severity filtering).
        skipped: ``True`` when :meth:`BaseAnalyzer.supports` declined the rootfs.
        error: Populated when the analyzer failed; ``None`` on success.
        stats: Analyzer-specific counters (files scanned, binaries parsed, ...),
            captured through the optional ``stats.as_dict()`` convention.
    """

    name: str
    version: str
    duration_seconds: float
    findings: int
    skipped: bool = False
    error: ScanError | None = None
    stats: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        """Return ``True`` when the analyzer completed without an error."""
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the report."""
        payload: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings": self.findings,
            "skipped": self.skipped,
            "ok": self.ok,
        }
        if self.stats is not None:
            payload["stats"] = self.stats
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        return payload


@dataclass(slots=True)
class ScanResult:
    """The complete outcome of one pipeline run.

    This object is the single input every reporter needs: it carries the
    findings, the per-analyzer execution metadata and the scan envelope
    (timestamps, worker count, applied filter) so that a JSON or SARIF document
    can describe itself without consulting the CLI.

    Attributes:
        rootfs: Resolved rootfs path that was scanned.
        findings: Severity-filtered, deterministically sorted findings.
        reports: Per-analyzer execution records, in declaration order.
        started_at: UTC timestamp taken before validation.
        finished_at: UTC timestamp taken after collection.
        duration_seconds: Total wall-clock duration.
        min_severity: Threshold applied to ``findings``.
        filtered_out: Findings dropped by the threshold (kept for transparency:
            a report that hides items must say how many).
        workers: Number of worker threads actually used.
        complete: ``False`` when an analyzer failed or traversal coverage was
            truncated. Incomplete scans are never considered successful.
    """

    rootfs: Path
    findings: list[Finding]
    reports: list[AnalyzerReport]
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    min_severity: Severity
    filtered_out: int
    workers: int

    @property
    def total_findings(self) -> int:
        """Number of findings that survived filtering."""
        return len(self.findings)

    @property
    def errors(self) -> list[ScanError]:
        """Errors collected from every analyzer that failed."""
        return [report.error for report in self.reports if report.error is not None]

    @property
    def successful(self) -> bool:
        """Return ``True`` when every analyzer completed without error."""
        return not self.errors

    @property
    def severity_counts(self) -> dict[str, int]:
        """Finding counts per severity, ordered ``critical`` -> ``info``.

        Every severity is present, including zeros, so report consumers can rely
        on a stable set of keys.
        """
        counts = {severity.value: 0 for severity in reversed(list(Severity))}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        """Highest severity present, or ``None`` for a clean scan."""
        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda s: s.weight)

    def to_dict(self) -> dict[str, Any]:
        """Return the full scan envelope as a JSON-serialisable mapping.

        The shape is deliberately stable: reporters and CI consumers may rely on
        ``tool``, ``scan``, ``summary``, ``findings`` and ``errors`` being present.
        """
        return {
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "scan": {
                "rootfs": self.rootfs.as_posix(),
                "started_at": _isoformat(self.started_at),
                "finished_at": _isoformat(self.finished_at),
                "duration_seconds": round(self.duration_seconds, 3),
                "workers": self.workers,
                "min_severity": self.min_severity.value,
                "filtered_out": self.filtered_out,
                "complete": self.successful,
                "analyzers": [report.to_dict() for report in self.reports],
            },
            "summary": {
                "total": self.total_findings,
                **self.severity_counts,
                "errors": len(self.errors),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
        }


def _isoformat(moment: datetime) -> str:
    """Format a UTC timestamp as ISO-8601 with a ``Z`` suffix.

    Args:
        moment: Timezone-aware datetime.

    Returns:
        A string such as ``2024-05-01T12:00:00Z``.
    """
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Run a set of analyzers over one rootfs and collect their findings.

    Args:
        analyzers: Analyzer instances to run. ``None`` builds every analyzer from
            the registry::

                Pipeline()                          # everything
                Pipeline(build_analyzers(["binary_hardening"]))
                Pipeline(max_workers=4, min_severity=Severity.HIGH)

        config: Configuration used when ``analyzers`` is ``None``. When explicit
            analyzers are supplied, their own configuration wins and this value is
            ignored (it is kept for introspection only).
        max_workers: ``1`` (default) runs analyzers sequentially. ``0`` or a
            negative value selects an automatic pool sized
            ``min(analyzers, cpus, DEFAULT_MAX_AUTO_WORKERS)``.
        min_severity: Findings below this threshold are dropped before reporting
            and counted in :attr:`ScanResult.filtered_out`. Accepts a
            :class:`Severity` or its string spelling.
        timeout_seconds: Overall wall-clock budget for the analyzer phase. ``None``
            disables the deadline. See the module docstring for the precise
            (advisory) semantics.
        capture_traceback: Record full tracebacks on errors. Useful for
            ``--verbose``; left off so reports do not embed host paths.

    Raises:
        ValueError: If no analyzer is configured, if a duplicate name is present,
            or if ``min_severity`` cannot be parsed.
    """

    def __init__(
        self,
        analyzers: Sequence[BaseAnalyzer] | None = None,
        *,
        config: AnalyzerConfig | None = None,
        max_workers: int = 1,
        min_severity: Severity | str = Severity.INFO,
        timeout_seconds: float | None = None,
        capture_traceback: bool = False,
    ) -> None:
        self._config = config or AnalyzerConfig()
        self._analyzers: list[BaseAnalyzer] = (
            list(analyzers)
            if analyzers is not None
            else build_analyzers(config=self._config)
        )
        if not self._analyzers:
            raise ValueError("the pipeline needs at least one analyzer")

        seen: set[str] = set()
        for analyzer in self._analyzers:
            if analyzer.name in seen:
                raise ValueError(f"duplicate analyzer {analyzer.name!r} in the pipeline")
            seen.add(analyzer.name)

        self._max_workers = max_workers
        self._min_severity = (
            min_severity
            if isinstance(min_severity, Severity)
            else Severity.parse(min_severity)
        )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive when set")
        self._timeout_seconds = timeout_seconds
        self._capture_traceback = capture_traceback

    # -- introspection -----------------------------------------------------

    @property
    def analyzers(self) -> tuple[BaseAnalyzer, ...]:
        """The analyzers this pipeline will run, in execution order."""
        return tuple(self._analyzers)

    @property
    def config(self) -> AnalyzerConfig:
        """Configuration used when the analyzer list was built automatically."""
        return self._config

    @property
    def max_workers(self) -> int:
        """Requested worker count (``0`` means automatic)."""
        return self._max_workers

    @property
    def min_severity(self) -> Severity:
        """Severity threshold applied to the collected findings."""
        return self._min_severity

    @property
    def timeout_seconds(self) -> float | None:
        """Overall analyzer-phase budget, or ``None`` when unbounded."""
        return self._timeout_seconds

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        names = ", ".join(analyzer.name for analyzer in self._analyzers)
        return f"<Pipeline analyzers=[{names}] min_severity={self._min_severity.value}>"

    # -- public API --------------------------------------------------------

    def run(self, rootfs_path: Path | str) -> ScanResult:
        """Execute every analyzer over ``rootfs_path``.

        Args:
            rootfs_path: Directory containing the extracted firmware rootfs.

        Returns:
            A :class:`ScanResult` with sorted, filtered findings and per-analyzer
            reports.

        Raises:
            RootfsError: If the path is missing, not a directory or unreadable.
            ValueError: If ``rootfs_path`` is empty.
        """
        started_at = datetime.now(timezone.utc)
        clock_start = time.perf_counter()

        rootfs = self._validate_rootfs(rootfs_path)
        workers = self._resolve_workers(len(self._analyzers))
        outcomes = self._execute(rootfs, workers)

        # Completion order is non-deterministic in concurrent mode; the report
        # order must not be. Sort by the analyzer's declaration index.
        outcomes.sort(key=lambda outcome: outcome[0])
        reports = [report for _index, report, _findings in outcomes]
        produced = [
            finding for _index, _report, findings in outcomes for finding in findings
        ]

        kept = [finding for finding in produced if finding.severity.meets(self._min_severity)]
        kept.sort(key=lambda finding: finding.sort_key)

        return ScanResult(
            rootfs=rootfs,
            findings=kept,
            reports=reports,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            duration_seconds=time.perf_counter() - clock_start,
            min_severity=self._min_severity,
            filtered_out=len(produced) - len(kept),
            workers=workers,
        )

    # -- execution ---------------------------------------------------------

    def _execute(
        self, rootfs: Path, workers: int
    ) -> list[tuple[int, AnalyzerReport, list[Finding]]]:
        """Run all analyzers on the pool and collect per-index outcomes.

        Args:
            rootfs: Validated rootfs path.
            workers: Worker count to use.

        Returns:
            ``(declaration_index, report, findings)`` triples in completion order.
        """
        outcomes: list[tuple[int, AnalyzerReport, list[Finding]]] = []
        collected: set[Future[Any]] = set()

        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="firmware-auditor")
        try:
            futures: dict[Future[Any], tuple[int, BaseAnalyzer]] = {
                pool.submit(self._run_one, analyzer, rootfs): (index, analyzer)
                for index, analyzer in enumerate(self._analyzers)
            }
            try:
                for future in as_completed(futures, timeout=self._timeout_seconds):
                    collected.add(future)
                    index, analyzer = futures[future]
                    outcomes.append(self._collect(future, index, analyzer))
            except FuturesTimeoutError:
                # Deadline hit: harvest whatever finished and mark the rest.
                for future, (index, analyzer) in futures.items():
                    if future in collected:
                        continue
                    if future.done():
                        outcomes.append(self._collect(future, index, analyzer))
                    else:
                        outcomes.append((index, self._timeout_report(analyzer), []))
        finally:
            # Do not block on a runaway analyzer; its result was already dropped.
            pool.shutdown(wait=False, cancel_futures=True)

        return outcomes

    def _run_one(
        self, analyzer: BaseAnalyzer, rootfs: Path
    ) -> tuple[AnalyzerReport, list[Finding]]:
        """Run a single analyzer with full error isolation.

        Args:
            analyzer: Analyzer to execute.
            rootfs: Validated rootfs path.

        Returns:
            Its report and findings. Failures produce an error report, never an
            exception, so one broken plugin cannot abort the scan.
        """
        clock_start = time.perf_counter()
        try:
            if not analyzer.supports(rootfs):
                return (
                    AnalyzerReport(
                        name=analyzer.name,
                        version=analyzer.version,
                        duration_seconds=0.0,
                        findings=0,
                        skipped=True,
                        stats=self._collect_stats(analyzer),
                    ),
                    [],
                )

            analyzer.prepare(rootfs)
            findings = self._coerce_findings(analyzer, analyzer.run(rootfs))
            stats = self._collect_stats(analyzer)
            if stats is not None and stats.get("truncated") is True:
                return (
                    AnalyzerReport(
                        name=analyzer.name,
                        version=analyzer.version,
                        duration_seconds=time.perf_counter() - clock_start,
                        findings=len(findings),
                        error=ScanError(
                            analyzer=analyzer.name,
                            error_type="AuditIncompleteError",
                            message=(
                                "filesystem traversal exceeded max_filesystem_entries; "
                                "audit coverage is incomplete"
                            ),
                        ),
                        stats=stats,
                    ),
                    findings,
                )
            return (
                AnalyzerReport(
                    name=analyzer.name,
                    version=analyzer.version,
                    duration_seconds=time.perf_counter() - clock_start,
                    findings=len(findings),
                    stats=stats,
                ),
                findings,
            )
        except Exception as exc:  # noqa: BLE001 - isolation boundary by design
            return (
                self._error_report(analyzer, exc, time.perf_counter() - clock_start),
                [],
            )

    def _collect(
        self, future: Future[Any], index: int, analyzer: BaseAnalyzer
    ) -> tuple[int, AnalyzerReport, list[Finding]]:
        """Retrieve a finished future, converting unexpected failures to reports.

        Args:
            future: Completed future returned by :meth:`_run_one`.
            index: Declaration index of the analyzer.
            analyzer: The analyzer the future belongs to.

        Returns:
            A ``(index, report, findings)`` triple.
        """
        try:
            report, findings = future.result()
        except Exception as exc:  # noqa: BLE001 - second safety net
            report = self._error_report(analyzer, exc, 0.0)
            findings = []
        return index, report, findings

    # -- report builders ---------------------------------------------------

    def _error_report(
        self, analyzer: BaseAnalyzer, exc: BaseException, duration: float
    ) -> AnalyzerReport:
        """Build an error report for a failed analyzer.

        Args:
            analyzer: The analyzer that failed.
            exc: The exception raised.
            duration: Seconds spent before failing.

        Returns:
            A report flagged ``ok=False`` with a populated :class:`ScanError`.
        """
        return AnalyzerReport(
            name=analyzer.name,
            version=analyzer.version,
            duration_seconds=duration,
            findings=0,
            error=ScanError(
                analyzer=analyzer.name,
                error_type=type(exc).__name__,
                message=str(exc) or repr(exc),
                traceback_text=traceback.format_exc() if self._capture_traceback else None,
            ),
            stats=self._collect_stats(analyzer),
        )

    def _timeout_report(self, analyzer: BaseAnalyzer) -> AnalyzerReport:
        """Build the report used for analyzers abandoned at the deadline.

        Args:
            analyzer: The analyzer that did not finish.

        Returns:
            A report flagged as timed out; its findings are discarded because a
            partially walked tree would yield misleading coverage claims.
        """
        budget = self._timeout_seconds or 0.0
        return AnalyzerReport(
            name=analyzer.name,
            version=analyzer.version,
            duration_seconds=budget,
            findings=0,
            error=ScanError(
                analyzer=analyzer.name,
                error_type="TimeoutError",
                message=(
                    f"analyzer did not finish within the {budget:g}s budget; its results were "
                    "discarded and its worker abandoned"
                ),
            ),
        )

    @staticmethod
    def _coerce_findings(analyzer: BaseAnalyzer, produced: object) -> list[Finding]:
        """Validate that an analyzer returned ``Finding`` instances.

        A plugin returning plain dictionaries would silently break the
        reporters, which rely on the typed contract, so the mismatch is promoted
        to an analyzer error instead of being coerced or dropped.

        Args:
            analyzer: The analyzer being validated.
            produced: Whatever ``run()`` returned.

        Returns:
            The findings as a list.

        Raises:
            AnalyzerError: If the return value is ``None``, not iterable, or
                contains a non-``Finding`` item.
        """
        if produced is None:
            raise AnalyzerError(analyzer.name, "run() returned None instead of a list of findings")
        findings: list[Finding] = []
        try:
            iterator = iter(produced)  # type: ignore[arg-type]
        except TypeError:
            raise AnalyzerError(
                analyzer.name,
                f"run() returned {type(produced).__name__}; expected an iterable of Finding",
            ) from None
        for position, item in enumerate(iterator):
            if not isinstance(item, Finding):
                raise AnalyzerError(
                    analyzer.name,
                    f"run() returned {type(item).__name__} at position {position}; "
                    "every analyzer must return Finding instances",
                )
            findings.append(item)
        return findings

    @staticmethod
    def _collect_stats(analyzer: BaseAnalyzer) -> dict[str, Any] | None:
        """Snapshot an analyzer's optional ``stats.as_dict()`` counters.

        Collected with ``getattr`` so that a plugin without instrumentation — or
        one whose counters raise — never breaks the run.

        Args:
            analyzer: The analyzer to inspect.

        Returns:
            The counters, or ``None`` when the analyzer exposes none.
        """
        stats = getattr(analyzer, "stats", None)
        if stats is None:
            return None
        as_dict = getattr(stats, "as_dict", None)
        if not callable(as_dict):
            return None
        try:
            payload = as_dict()
        except Exception:  # noqa: BLE001 - telemetry must never fail a scan
            return None
        return dict(payload) if isinstance(payload, dict) else None

    # -- environment -------------------------------------------------------

    def _resolve_workers(self, analyzer_count: int) -> int:
        """Clamp the requested worker count to something meaningful.

        Args:
            analyzer_count: Number of analyzers about to run.

        Returns:
            At least 1 and at most ``analyzer_count``; more threads than analyzers
            would sit idle.
        """
        requested = self._max_workers
        if requested <= 0:
            requested = min(
                analyzer_count,
                os.cpu_count() or 1,
                DEFAULT_MAX_AUTO_WORKERS,
            )
        return max(1, min(requested, analyzer_count))

    @staticmethod
    def _validate_rootfs(rootfs_path: Path | str) -> Path:
        """Resolve and probe the rootfs before any analyzer touches it.

        Args:
            rootfs_path: Candidate path.

        Returns:
            The resolved absolute directory.

        Raises:
            RootfsError: If the path is empty, missing, not a directory, or not
                listable by the current user.
            ValueError: If ``rootfs_path`` is blank.
        """
        if rootfs_path is None or (isinstance(rootfs_path, str) and not rootfs_path.strip()):
            raise ValueError("rootfs_path must be a non-empty path")

        candidate = Path(rootfs_path).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise RootfsError(f"rootfs path does not exist: {candidate}") from exc

        if not resolved.is_dir():
            raise RootfsError(f"rootfs path is not a directory: {resolved}")

        try:
            with os.scandir(resolved) as scanner:
                next(scanner, None)
        except OSError as exc:
            detail = exc.strerror or str(exc)
            raise RootfsError(
                f"rootfs directory is not readable: {resolved} ({detail})"
            ) from exc

        return resolved
