"""Report rendering: terminal summary, JSON export and SARIF v2.1.0 export.

The reporter is a pure function of a :class:`~firmware_auditor.core.pipeline.ScanResult`:
it never touches the filesystem, never re-runs an analyzer and never filters
(findings are already filtered and sorted by the pipeline). That keeps the three
output formats mutually consistent -- the same scan rendered as console text, as
JSON and as SARIF always describes the same set of findings.

Formats
-------
``console``
    Human-readable summary: scan header, severity histogram, per-rule findings
    table. ASCII only, so it renders correctly on a Windows console using
    ``cp850``/``cp1252`` as well as on a UTF-8 terminal. Findings are grouped by
    rule by default, because a firmware image with 300 binaries otherwise
    produces thousands of nearly identical rows.

``json``
    The complete machine-readable envelope produced by
    :meth:`ScanResult.to_dict`, serialised with ``indent=2`` so it diffs well in
    version control.

``sarif``
    SARIF v2.1.0 for GitHub Advanced Security and any other SARIF consumer. Tool
    driver, per-rule metadata, per-result locations, stable partial fingerprints
    and execution notifications for failed analyzers are all populated.

Severity mapping
----------------
SARIF has four result levels and GitHub maps a numeric ``security-severity``
property onto its own buckets, so the mapping is explicit rather than implicit:

==========  =========  ==================  =====================
Severity    SARIF      ``security-severity``  GitHub bucket
==========  =========  ==================  =====================
CRITICAL    ``error``  ``9.5``             critical
HIGH        ``error``  ``8.0``             high
MEDIUM      ``warning``  ``5.5``           medium
LOW         ``note``   ``3.0``             low
INFO        ``note``   ``0.0``             none
==========  =========  ==================  =====================

Encoding note
-------------
Console output is ASCII by design, but file paths can still carry non-ASCII bytes.
The CLI is responsible for configuring ``sys.stdout`` with
``errors="replace"``; the reporter never writes to a stream itself.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Final, Sequence
from urllib.parse import quote

from analyzers.base import Finding, Severity
from core.pipeline import TOOL_NAME, TOOL_VERSION, AnalyzerReport, ScanResult

__all__ = [
    "OutputFormat",
    "Reporter",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SUPPORTED_FORMATS",
]

#: SARIF schema identifier understood by GHAS, VS Code and the OASIS validators.
SARIF_SCHEMA: Final[str] = "https://json.schemastore.org/sarif-2.1.0.json"

#: SARIF specification version emitted by this reporter.
SARIF_VERSION: Final[str] = "2.1.0"

#: URI base id under which every artifact location is expressed, so a SARIF
#: consumer can resolve ``etc/shadow`` against the scanned rootfs.
SARIF_BASE_ID: Final[str] = "%SRCROOT%"

#: Key used for SARIF ``partialFingerprints``; the version suffix lets a future
#: release change the algorithm without silently reusing old identities.
FINGERPRINT_KEY: Final[str] = "firmwareAuditor/v1"

#: Severity to SARIF result level.
_SARIF_LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: Severity to GitHub's numeric ``security-severity`` score (0.0 - 10.0).
_SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}

#: ANSI colours used only when ``Reporter(color=True)``.
_ANSI_COLORS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "\x1b[1;31m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_ANSI_RESET: Final[str] = "\x1b[0m"


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------


class OutputFormat(str, Enum):
    """Supported report formats.

    Inherits from :class:`str` so a member compares equal to its spelling and
    serialises directly, which keeps ``--format`` handling trivial in the CLI.
    """

    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"

    @classmethod
    def parse(cls, value: "OutputFormat | str") -> "OutputFormat":
        """Coerce a CLI/JSON value into an :class:`OutputFormat`.

        Args:
            value: A member or its case-insensitive spelling.

        Returns:
            The matching format.

        Raises:
            ValueError: If the value is not a supported format; the message
                lists the accepted spellings.
        """
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"output format must be a string, got {type(value).__name__}")
        key = value.strip().lower()
        try:
            return cls(key)
        except ValueError:
            options = ", ".join(member.value for member in cls)
            raise ValueError(f"unknown output format {value!r} (expected one of: {options})") from None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


#: Format spellings accepted by ``--format``.
SUPPORTED_FORMATS: Final[tuple[str, ...]] = tuple(member.value for member in OutputFormat)


# ---------------------------------------------------------------------------
# Small formatting helpers
# ---------------------------------------------------------------------------


def _truncate(value: str, width: int, *, ellipsis: str = "...") -> str:
    """Fit ``value`` into ``width`` printable characters.

    Args:
        value: Text to shorten.
        width: Maximum length in characters.
        ellipsis: Marker appended when the text is cut.

    Returns:
        The original text, or a prefix terminated by ``ellipsis``.
    """
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= len(ellipsis):
        return value[:width]
    return value[: width - len(ellipsis)] + ellipsis


def _format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    max_widths: Sequence[int] | None = None,
    right_align: frozenset[int] = frozenset(),
    colorize: Callable[[int, str], str] | None = None,
) -> list[str]:
    """Render an ASCII table with per-column truncation and alignment.

    Column widths are the widest cell (or header) capped by ``max_widths``. The
    final column is never padded, so no line carries trailing whitespace, and
    colour is applied to already-padded cells so ANSI escapes cannot shift the
    alignment.

    Args:
        headers: Column titles.
        rows: Body rows; each row must have one cell per header.
        max_widths: Optional per-column width ceiling.
        right_align: Indices of columns to right-align (numeric ones).
        colorize: Optional ``(column_index, padded_text) -> str`` hook.

    Returns:
        The table as a list of lines, header first, separator second.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(cell))
    if max_widths is not None:
        widths = [
            min(width, limit) for width, limit in zip(widths, max_widths)
        ]

    def render_row(cells: Sequence[str], *, use_color: bool) -> str:
        parts: list[str] = []
        last_index = len(cells) - 1
        for index, cell in enumerate(cells):
            text = _truncate(cell, widths[index])
            if index < last_index:
                text = text.rjust(widths[index]) if index in right_align else text.ljust(widths[index])
            if use_color and colorize is not None:
                text = colorize(index, text)
            parts.append(text)
        return "  ".join(parts)

    separator = "  ".join("-" * width for width in widths)
    lines = [render_row(headers, use_color=False), separator]
    lines.extend(render_row(row, use_color=True) for row in rows)
    return lines


def _bar(count: int, total: int, *, width: int = 24) -> str:
    """Build a proportional ASCII bar for the severity histogram.

    Args:
        count: Value for this row.
        total: Sum used as the 100% reference.
        width: Maximum bar length in characters.

    Returns:
        A string of ``#`` characters, empty when ``count`` is zero.
    """
    if count <= 0 or total <= 0:
        return ""
    filled = max(1, round(count / total * width))
    return "#" * min(filled, width)


def _artifact_uri(file_path: str) -> str:
    """Convert a rootfs-relative path into a SARIF artifact URI.

    Args:
        file_path: POSIX path relative to the rootfs.

    Returns:
        A percent-encoded relative URI with forward slashes.
    """
    normalized = file_path.replace("\\", "/").lstrip("/")
    return quote(normalized, safe="/")


def _root_uri(root: Path) -> str:
    """Return ``root`` as a ``file://`` URI suitable for ``originalUriBaseIds``.

    SARIF requires a base id URI to end with ``/`` so that relative artifact URIs
    resolve as children of the directory rather than as siblings.

    Args:
        root: Absolute rootfs path.

    Returns:
        A ``file://`` URI with a trailing slash.
    """
    uri = root.as_uri()
    return uri if uri.endswith("/") else uri + "/"


def _fingerprint(finding: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    The hash covers identity fields only (rule, path, line, title) and never the
    description, which may embed counts or formatting that legitimately change
    between runs. A stable fingerprint is what lets a SARIF consumer recognise
    "the same issue" across builds instead of reopening it.

    Args:
        finding: The finding to fingerprint.

    Returns:
        A 32-character lowercase hexadecimal digest.
    """
    payload = "\x00".join(
        (
            finding.rule_id,
            finding.file_path,
            str(finding.line or ""),
            finding.title,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _utc_timestamp(moment: datetime) -> str:
    """Format a datetime as SARIF/ISO-8601 UTC with a ``Z`` suffix.

    Args:
        moment: Timezone-aware datetime.

    Returns:
        A string such as ``2024-05-01T12:00:00Z``.
    """
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sarif_rule_name(rule_id: str) -> str:
    """Derive a SARIF-legal rule ``name`` from a rule identifier.

    SARIF constrains ``name`` to ``^[A-Za-z][A-Za-z0-9]*$``, while this project's
    rule ids are dash-separated (``FWK-KEY-001``).

    Args:
        rule_id: Internal rule identifier.

    Returns:
        An identifier-safe name such as ``FWKKEY001``.
    """
    candidate = "".join(character for character in rule_id if character.isalnum())
    if not candidate or not candidate[0].isalpha():
        return f"Rule{candidate}"
    return candidate


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class Reporter:
    """Render a :class:`ScanResult` as console text, JSON or SARIF.

    Args:
        color: Emit ANSI colour escapes on the console severity column. Defaults
            to ``False`` so redirected output and log collectors stay clean; the
            CLI enables it only when stdout is a TTY.
        group_by_rule: Console only -- collapse findings that share a rule into a
            single row with a count and sample locations. Defaults to ``True``.
        max_console_rows: Console only -- maximum rows rendered before the
            remainder is summarised. Console output is a triage aid, not the
            authoritative record; JSON/SARIF always carry everything.
        examples_per_rule: Console only -- sample locations printed per rule when
            grouping is enabled.
        json_indent: Indentation for JSON/SARIF output; ``None`` emits a single
            compact line.

    Raises:
        ValueError: If ``max_console_rows`` or ``examples_per_rule`` is negative.
    """

    def __init__(
        self,
        *,
        color: bool = False,
        group_by_rule: bool = True,
        max_console_rows: int = 50,
        examples_per_rule: int = 3,
        json_indent: int | None = 2,
    ) -> None:
        if max_console_rows < 1:
            raise ValueError("max_console_rows must be at least 1")
        if examples_per_rule < 1:
            raise ValueError("examples_per_rule must be at least 1")
        if json_indent is not None and json_indent < 0:
            raise ValueError("json_indent must be non-negative or None")
        self._color = color
        self._group_by_rule = group_by_rule
        self._max_console_rows = max_console_rows
        self._examples_per_rule = examples_per_rule
        self._json_indent = json_indent

    # -- public API --------------------------------------------------------

    def render(self, result: ScanResult, output_format: OutputFormat | str) -> str:
        """Render ``result`` in the requested format.

        Args:
            result: Outcome of a pipeline run.
            output_format: Format member or its spelling.

        Returns:
            The rendered document, always terminated by a newline.

        Raises:
            ValueError: If the format is unknown.
        """
        resolved = OutputFormat.parse(output_format)
        if resolved is OutputFormat.JSON:
            return self.to_json(result)
        if resolved is OutputFormat.SARIF:
            return self.to_sarif_json(result)
        return self.to_console(result)

    def write(
        self,
        result: ScanResult,
        destination: Path | str,
        output_format: OutputFormat | str,
    ) -> Path:
        """Render and write a report to disk as UTF-8 with LF line endings.

        LF is forced so a report produced on Windows is byte-identical to one
        produced on Linux, which keeps SARIF uploads reproducible.

        Args:
            result: Outcome of a pipeline run.
            destination: Target file; its parent directory must exist.
            output_format: Format member or its spelling.

        Returns:
            The path that was written.

        Raises:
            ValueError: If the format is unknown.
            OSError: If the destination cannot be written.
        """
        path = Path(destination)
        path.write_text(self.render(result, output_format), encoding="utf-8", newline="\n")
        return path

    # -- console -----------------------------------------------------------

    def to_console(self, result: ScanResult) -> str:
        """Render the human-readable terminal summary.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            The report text, terminated by a newline.
        """
        blocks: list[str] = [
            f"{TOOL_NAME} {TOOL_VERSION}",
            self._console_header(result),
        ]
        if result.errors:
            blocks.append(self._console_errors(result))
        blocks.append(self._console_summary(result))
        blocks.append(self._console_findings(result))
        return "\n\n".join(blocks) + "\n"

    def _console_header(self, result: ScanResult) -> str:
        """Render the scan identification block.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            Aligned ``key : value`` lines.
        """
        lines = [
            f"{'rootfs':<11}: {result.rootfs.as_posix()}",
            f"{'duration':<11}: {result.duration_seconds:.3f}s (workers={result.workers})",
        ]
        threshold = f">= {result.min_severity.value}"
        if result.filtered_out:
            threshold += f" ({result.filtered_out} finding(s) filtered out)"
        lines.append(f"{'severity':<11}: {threshold}")

        analyzer_lines = [self._analyzer_line(report) for report in result.reports]
        if analyzer_lines:
            lines.append(f"{'analyzers':<11}: {analyzer_lines[0]}")
            for extra in analyzer_lines[1:]:
                lines.append(f"{'':<11}  {extra}")
        return "\n".join(lines)

    @staticmethod
    def _analyzer_line(report: AnalyzerReport) -> str:
        """Summarise one analyzer report on a single line.

        Args:
            report: Per-analyzer execution record.

        Returns:
            A line such as ``binary_hardening 1.0.0 ok (42 finding(s), 1.234s)``.
        """
        identity = f"{report.name} {report.version}"
        if report.skipped:
            return f"{identity} skipped (not applicable to this rootfs)"
        if report.error is not None:
            return (
                f"{identity} FAILED ({report.error.error_type}: {report.error.message})"
            )
        return f"{identity} ok ({report.findings} finding(s), {report.duration_seconds:.3f}s)"

    @staticmethod
    def _console_errors(result: ScanResult) -> str:
        """Render the failed-analyzer block.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            A block warning that the report is incomplete.
        """
        lines = [f"ERRORS ({len(result.errors)}) -- this report is INCOMPLETE"]
        for error in result.errors:
            lines.append(f"  [{error.analyzer}] {error.error_type}: {error.message}")
        return "\n".join(lines)

    def _console_summary(self, result: ScanResult) -> str:
        """Render the severity histogram.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            A table with one row per severity plus a total.
        """
        counts = result.severity_counts
        total = result.total_findings
        rows: list[list[str]] = [
            [severity.label, str(counts[severity.value]), _bar(counts[severity.value], total)]
            for severity in reversed(list(Severity))
        ]
        rows.append(["TOTAL", str(total), ""])
        lines = ["SUMMARY BY SEVERITY", ""]
        lines.extend(
            _format_table(
                ("SEVERITY", "COUNT", "DISTRIBUTION"),
                rows,
                max_widths=(10, 6, 24),
                right_align=frozenset({1}),
                colorize=self._colorize_severity,
            )
        )
        return "\n".join(lines)

    def _console_findings(self, result: ScanResult) -> str:
        """Render the findings block, grouped by rule or flat.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            The findings block, or a short "clean" message.
        """
        if not result.findings:
            return (
                "No findings at or above the selected severity.\n"
                "Re-run with a lower --min-severity to include informational findings."
            )
        if self._group_by_rule:
            return self._console_grouped(result)
        return self._console_flat(result)

    def _console_grouped(self, result: ScanResult) -> str:
        """Render findings collapsed into one row per rule.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            A table of rules with counts and sample locations.
        """
        groups: dict[tuple[Severity, str], list[Finding]] = {}
        order: list[tuple[Severity, str]] = []
        for finding in result.findings:
            key = (finding.severity, finding.rule_id)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(finding)

        rows: list[list[str]] = []
        for severity, rule_id in order[: self._max_console_rows]:
            items = groups[(severity, rule_id)]
            samples = "; ".join(
                item.file_path for item in items[: self._examples_per_rule]
            )
            remaining = len(items) - self._examples_per_rule
            if remaining > 0:
                samples += f"; (+{remaining} more)"
            rows.append(
                [severity.label, rule_id, str(len(items)), samples, items[0].title]
            )

        lines = [
            f"FINDINGS BY RULE ({len(order)} rule(s), {result.total_findings} finding(s))",
            "",
        ]
        lines.extend(
            _format_table(
                ("SEVERITY", "RULE", "COUNT", "LOCATION SAMPLE", "TITLE"),
                rows,
                max_widths=(10, 16, 6, 54, 46),
                right_align=frozenset({2}),
                colorize=self._colorize_severity,
            )
        )
        hidden = len(order) - len(rows)
        if hidden > 0:
            lines.append(f"... and {hidden} more rule(s) not shown")
        lines.append("")
        lines.append("Full detail: --format json or --format sarif.")
        return "\n".join(lines)

    def _console_flat(self, result: ScanResult) -> str:
        """Render one row per finding, truncated to the row budget.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            A table of individual findings.
        """
        rows: list[list[str]] = []
        for finding in result.findings[: self._max_console_rows]:
            location = finding.file_path
            if finding.line is not None:
                location = f"{location}:{finding.line}"
            rows.append(
                [finding.severity.label, finding.rule_id, location, finding.title]
            )

        lines = [
            f"FINDINGS ({result.total_findings} shown up to {self._max_console_rows})",
            "",
        ]
        lines.extend(
            _format_table(
                ("SEVERITY", "RULE", "LOCATION", "TITLE"),
                rows,
                max_widths=(10, 16, 58, 58),
                colorize=self._colorize_severity,
            )
        )
        hidden = result.total_findings - len(rows)
        if hidden > 0:
            lines.append(f"... and {hidden} more finding(s) not shown")
        return "\n".join(lines)

    def _colorize_severity(self, column: int, text: str) -> str:
        """Colour the first table column when it holds a severity label.

        Args:
            column: Column index being rendered.
            text: Already-padded cell text.

        Returns:
            The cell text, wrapped in ANSI escapes when applicable.
        """
        if not self._color or column != 0:
            return text
        label = text.strip()
        for severity in Severity:
            if severity.label == label:
                return f"{_ANSI_COLORS[severity]}{text}{_ANSI_RESET}"
        return text

    # -- json --------------------------------------------------------------

    def to_json(self, result: ScanResult) -> str:
        """Serialise the scan envelope as JSON.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            UTF-8 JSON text terminated by a newline; non-ASCII characters are kept
            literal so paths remain readable.
        """
        return self._dumps(result.to_dict())

    # -- sarif -------------------------------------------------------------

    def to_sarif(self, result: ScanResult) -> dict[str, Any]:
        """Build the SARIF v2.1.0 document for ``result``.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            A JSON-serialisable SARIF log with a single run.
        """
        rules, rule_index = self._sarif_rules(result)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "semanticVersion": TOOL_VERSION,
                    "rules": rules,
                    "properties": {
                        "analyzerCount": len(result.reports),
                        "analyzers": [report.name for report in result.reports],
                    },
                }
            },
            "invocations": [self._sarif_invocation(result)],
            "originalUriBaseIds": {SARIF_BASE_ID: {"uri": _root_uri(result.rootfs)}},
            "results": [self._sarif_result(finding, rule_index) for finding in result.findings],
            "properties": {
                "minSeverity": result.min_severity.value,
                "filteredOut": result.filtered_out,
                "workers": result.workers,
                "durationSeconds": round(result.duration_seconds, 3),
            },
        }

        artifacts = self._sarif_artifacts(result)
        if artifacts:
            run["artifacts"] = artifacts

        return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}

    def to_sarif_json(self, result: ScanResult) -> str:
        """Serialise the SARIF document as text.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            JSON text terminated by a newline.
        """
        return self._dumps(self.to_sarif(result))

    def _sarif_rules(
        self, result: ScanResult
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Build the rule metadata array and its index.

        Rules are emitted once each, sorted by id, because SARIF identifies a rule
        by ``ruleId`` and expects ``ruleIndex`` to point at that unique entry. The
        severity recorded on the rule is the highest one seen for it, since a
        finding list is already sorted by descending severity.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            ``(rules, rule_id -> index)``.
        """
        by_id: dict[str, Finding] = {}
        for finding in result.findings:
            by_id.setdefault(finding.rule_id, finding)

        ordered_ids = sorted(by_id)
        rules = [self._sarif_rule(by_id[rule_id]) for rule_id in ordered_ids]
        index = {rule_id: position for position, rule_id in enumerate(ordered_ids)}
        return rules, index

    @staticmethod
    def _sarif_rule(finding: Finding) -> dict[str, Any]:
        """Build one SARIF ``reportingDescriptor`` entry.

        Args:
            finding: The first (highest severity) finding for this rule.

        Returns:
            The rule metadata object.
        """
        references = list(finding.references)
        help_text = finding.mitigation
        if references:
            help_text += "\n\nReferences:\n" + "\n".join(f"- {url}" for url in references)

        properties: dict[str, Any] = {
            "tags": ["security", finding.category or "firmware-auditor"],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "severity": finding.severity.value,
        }
        if finding.category:
            properties["category"] = finding.category

        rule: dict[str, Any] = {
            "id": finding.rule_id,
            "name": _sarif_rule_name(finding.rule_id),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": help_text, "markdown": help_text},
            "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
            "properties": properties,
        }
        if references:
            rule["helpUri"] = references[0]
        return rule

    @staticmethod
    def _sarif_result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
        """Build one SARIF ``result`` entry.

        Args:
            finding: The finding to convert.
            rule_index: Mapping from rule id to its position in ``tool.driver.rules``.

        Returns:
            The result object.
        """
        physical: dict[str, Any] = {
            "artifactLocation": {
                "uri": _artifact_uri(finding.file_path),
                "uriBaseId": SARIF_BASE_ID,
            }
        }
        if finding.line is not None and finding.line > 0:
            physical["region"] = {"startLine": finding.line}

        properties: dict[str, Any] = {"severity": finding.severity.value}
        if finding.category:
            properties["category"] = finding.category
        if finding.description:
            properties["description"] = finding.description
        if finding.mitigation:
            properties["mitigation"] = finding.mitigation
        if finding.evidence:
            properties["evidence"] = finding.evidence

        markdown = f"**{finding.title}**\n\n{finding.description}"
        if finding.mitigation:
            markdown += f"\n\n**Mitigation:** {finding.mitigation}"

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.title, "markdown": markdown},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {FINGERPRINT_KEY: _fingerprint(finding)},
            "properties": properties,
        }

        # ``ruleIndex`` is optional, but when present it must be a non-negative
        # index into ``tool.driver.rules``. Emitting ``-1`` for an unexpected
        # rule would be invalid SARIF, so the key is simply omitted instead.
        position = rule_index.get(finding.rule_id)
        if position is not None:
            result["ruleIndex"] = position

        return result

    @staticmethod
    def _sarif_invocation(result: ScanResult) -> dict[str, Any]:
        """Build the ``invocations`` entry describing this run.

        A failed analyzer becomes a ``toolExecutionNotification`` and flips
        ``executionSuccessful`` to ``False``, so a consumer can tell a clean image
        apart from an audit that silently lost an analyzer.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            The invocation object.
        """
        invocation: dict[str, Any] = {
            "executionSuccessful": result.successful,
            "startTimeUtc": _utc_timestamp(result.started_at),
            "endTimeUtc": _utc_timestamp(result.finished_at),
            "workingDirectory": {"uri": _root_uri(result.rootfs)},
        }
        notifications = [
            {
                "level": "error",
                "message": {
                    "text": f"{error.analyzer}: {error.error_type}: {error.message}"
                },
                "descriptor": {"id": error.analyzer},
                "properties": {
                    "analyzer": error.analyzer,
                    "errorType": error.error_type,
                },
            }
            for error in result.errors
        ]
        if notifications:
            invocation["toolExecutionNotifications"] = notifications
        return invocation

    @staticmethod
    def _sarif_artifacts(result: ScanResult) -> list[dict[str, Any]]:
        """List the files referenced by the findings.

        Args:
            result: Outcome of a pipeline run.

        Returns:
            One artifact entry per distinct finding location, sorted by path.
        """
        paths = sorted({finding.file_path for finding in result.findings})
        return [
            {
                "location": {"uri": _artifact_uri(path), "uriBaseId": SARIF_BASE_ID},
                "roles": ["analysisTarget"],
            }
            for path in paths
        ]

    # -- serialisation -----------------------------------------------------

    def _dumps(self, payload: dict[str, Any]) -> str:
        """Serialise ``payload`` with the configured indentation.

        Args:
            payload: JSON-serialisable mapping.

        Returns:
            The encoded document, terminated by a newline.
        """
        if self._json_indent is None:
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        return json.dumps(payload, ensure_ascii=False, indent=self._json_indent) + "\n"
