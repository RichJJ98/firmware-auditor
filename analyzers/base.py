"""Core contracts shared by every analyzer.

This module defines the three primitives the whole framework is built on:

* :class:`Severity` -- an ordered enumeration of finding severities, so that
  ``--min-severity`` filtering is a numeric comparison instead of string
  matching.
* :class:`Finding` -- an immutable, typed replacement for ``Dict[str, Any]``.
  Analyzers never build raw dictionaries: they build ``Finding`` objects and
  serialise them with :meth:`Finding.to_dict` at the very edge (reporter).
* :class:`BaseAnalyzer` -- the abstract plugin interface. Every rule pack
  lives in a subclass and is discovered through :data:`REGISTRY`
  (see :mod:`firmware_auditor.analyzers`).

The module also hosts the filesystem-walking helpers used by analyzers. They
are deliberately defensive: emblematic firmware rootfs images contain cyclic
symlinks, unreadable nodes (no ``CAP_DAC_READ_SEARCH`` on the extraction
host), sockets, FIFOs and device nodes. A walk must never raise, never block
on a FIFO and never follow a symlink loop.

Path convention
---------------
Every ``Finding.file_path`` is a **POSIX path relative to the rootfs** (e.g.
``etc/shadow``, ``usr/sbin/dropbear``). This keeps reports portable between
the extraction host and the CI consumer, and matches SARIF's expectation of
repository-relative URIs.
"""

from __future__ import annotations

import enum
import fnmatch
import os
import stat
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

__all__ = [
    "Severity",
    "Finding",
    "AnalyzerConfig",
    "AnalyzerError",
    "BaseAnalyzer",
    "EntryKind",
    "TraversalStats",
    "GLOBAL_EXCLUDES",
    "is_elf",
    "iter_entries",
    "read_text_lossy",
    "relative_posix",
    "walk_directories",
    "walk_files",
]


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, enum.Enum):
    """Ordered finding severity.

    Inherits from :class:`str` so that instances serialise directly to JSON and
    compare equal to their plain-string spelling (``Severity.HIGH == "high"``).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Numeric rank, ``INFO`` is 0 and ``CRITICAL`` is 4."""
        return _SEVERITY_WEIGHT[self]

    @property
    def label(self) -> str:
        """Upper-case label used by the console reporter."""
        return self.value.upper()

    def meets(self, threshold: "Severity") -> bool:
        """Return ``True`` when this severity is at least ``threshold``."""
        return self.weight >= threshold.weight

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        """Coerce a CLI/JSON value into a :class:`Severity`.

        Accepts case-insensitive names, the enum itself and common aliases
        (``warn`` -> ``medium``, ``moderate`` -> ``medium``, ``error`` ->
        ``high``). Raises :class:`ValueError` with an actionable message.
        """
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"severity must be a string, got {type(value).__name__}")
        key = value.strip().lower()
        alias = _SEVERITY_ALIASES.get(key)
        if alias is not None:
            return alias
        try:
            return cls(key)
        except ValueError:
            allowed = ", ".join(s.value for s in reversed(list(cls)))
            raise ValueError(f"unknown severity {value!r} (expected one of: {allowed})") from None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    def __format__(self, spec: str) -> str:  # pragma: no cover - trivial
        return format(self.value, spec)


_SEVERITY_WEIGHT: Final[Mapping[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_ALIASES: Final[Mapping[str, Severity]] = {
    "warn": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "error": Severity.HIGH,
    "err": Severity.HIGH,
    "crit": Severity.CRITICAL,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security observation produced by an analyzer.

    The five mandatory fields mirror the framework contract; the remaining
    fields are optional metadata that the SARIF/JSON reporters exploit
    (stable rule identity, line number, evidence snippet, references).

    Attributes:
        title: Short, human-readable summary (``"Binary built without PIE"``).
        severity: Impact classification, see :class:`Severity`.
        file_path: POSIX path **relative to the scanned rootfs**.
        description: What was observed and why it matters.
        mitigation: Concrete remediation guidance.
        rule_id: Stable identifier (``FWK-PIE-001``) used for SARIF rule
            deduplication and for suppressions in CI.
        category: Analyzer name that emitted the finding.
        line: 1-based line number when the finding is anchored to text.
        evidence: Raw snippet that justifies the finding (truncated).
        references: Documentation URLs for the underlying weakness.
    """

    title: str
    severity: Severity
    file_path: str
    description: str
    mitigation: str
    rule_id: str = ""
    category: str = ""
    line: int | None = None
    evidence: str | None = None
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the finding."""
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "file_path": self.file_path,
            "description": self.description,
            "mitigation": self.mitigation,
        }
        if self.line is not None:
            payload["line"] = self.line
        if self.evidence is not None:
            payload["evidence"] = self.evidence
        if self.references:
            payload["references"] = list(self.references)
        return payload

    @property
    def sort_key(self) -> tuple[int, str, str, str]:
        """Deterministic ordering key: severity first, then location."""
        return (-self.severity.weight, self.file_path, self.rule_id, self.title)

    def with_path(self, file_path: str) -> "Finding":
        """Return a copy with ``file_path`` rewritten (used for path rebasing)."""
        return replace(self, file_path=file_path)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"[{self.severity.label}] {self.file_path}: {self.title}"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AnalyzerError(RuntimeError):
    """Raised when an analyzer cannot complete a scan.

    The pipeline catches this (and any other :class:`Exception`) and records it
    as a non-fatal :class:`~firmware_auditor.core.pipeline.ScanError`, so one
    broken plugin never discards the findings of the others.
    """

    def __init__(self, analyzer: str, message: str) -> None:
        self.analyzer = analyzer
        self.message = message
        super().__init__(f"{analyzer}: {message}")


# ---------------------------------------------------------------------------
# Analyzer configuration
# ---------------------------------------------------------------------------

#: Directories that are never walked to completion: kernel pseudo-filesystems
#: and volatile mounts are meaningless (or dangerous, e.g. ``/proc`` FIFOs) in
#: a *static* rootfs audit.
GLOBAL_EXCLUDES: Final[tuple[str, ...]] = (
    "proc",
    "sys",
    "dev",
    "run",
    "tmp/.X11-unix",
)


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    """Runtime knobs shared by all analyzers.

    Attributes:
        exclude_globs: Glob patterns matched against the rootfs-relative POSIX
            path; matching entries (files or directories) are skipped.
        max_file_bytes: Files larger than this are not parsed (prevents a
            multi-gigabyte blob from exhausting memory).
        max_filesystem_entries: Hard cap on walked entries per analyzer, a
            safety valve for malformed or adversarially deep trees.
    """

    exclude_globs: tuple[str, ...] = ()
    max_file_bytes: int = 512 * 1024 * 1024
    max_filesystem_entries: int = 2_000_000

    def is_excluded(self, relative_path: str) -> bool:
        """Return ``True`` when ``relative_path`` matches an exclude glob."""
        for pattern in self.exclude_globs:
            if fnmatch.fnmatch(relative_path, pattern):
                return True
            # A bare directory name should exclude its whole subtree.
            if fnmatch.fnmatch(Path(relative_path).name, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# BaseAnalyzer
# ---------------------------------------------------------------------------


class BaseAnalyzer(ABC):
    """Abstract base class for every analyzer plugin.

    Subclasses implement :meth:`run` and expose a stable :attr:`name`. They must
    be side-effect free with respect to the scanned rootfs: this framework is
    **strictly read-only and static** -- no chroot, no execution, no mounts.

    Class attributes:
        description: One-line description shown by ``--list-analyzers``.
        version: Rule-pack version, surfaced in the JSON/SARIF tool metadata.
        rule_prefix: Prefix for generated ``rule_id`` values.
    """

    description: str = ""
    version: str = "1.0.0"
    rule_prefix: str = "FWK"

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self._config = config or AnalyzerConfig()
        self._findings: list[Finding] = []

    # -- identity ----------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable, machine-readable analyzer identifier (e.g. ``binary_hardening``)."""

    # -- execution ---------------------------------------------------------

    @abstractmethod
    def run(self, rootfs_path: Path) -> list[Finding]:
        """Analyze ``rootfs_path`` and return the findings produced.

        Implementations must never mutate the rootfs and should tolerate
        unreadable/corrupt entries by skipping them rather than aborting.

        Args:
            rootfs_path: Absolute path of an extracted firmware rootfs.

        Returns:
            The findings, unsorted; the pipeline sorts and filters them.
        """

    def prepare(self, rootfs_path: Path) -> None:  # noqa: ARG002 - hook
        """Optional hook invoked once before :meth:`run`.

        Override to validate prerequisites or reset incremental state. The
        default implementation does nothing.

        Args:
            rootfs_path: Absolute path of the rootfs about to be scanned.
        """

    def supports(self, rootfs_path: Path) -> bool:  # noqa: ARG002 - hook
        """Return whether this analyzer is applicable to ``rootfs_path``.

        The default implementation always returns ``True``; an analyzer may
        override it to skip work when, for example, no ELF binary is present.

        Args:
            rootfs_path: Absolute path of the rootfs about to be scanned.
        """
        return True

    # -- helpers -----------------------------------------------------------

    @property
    def config(self) -> AnalyzerConfig:
        """The configuration this instance was built with."""
        return self._config

    def make_finding(
        self,
        *,
        title: str,
        severity: Severity,
        file_path: str,
        description: str,
        mitigation: str,
        rule_id: str = "",
        line: int | None = None,
        evidence: str | None = None,
        references: Sequence[str] = (),
    ) -> Finding:
        """Build a :class:`Finding` pre-filled with this analyzer's identity.

        Args:
            title: Short summary of the observation.
            severity: Impact classification.
            file_path: Rootfs-relative POSIX path the finding refers to.
            description: Detailed explanation of the weakness.
            mitigation: Remediation guidance.
            rule_id: Rule identifier; falls back to ``<prefix>-<NAME>-000``.
            line: Optional 1-based line number.
            evidence: Optional snippet justifying the finding.
            references: Optional documentation URLs.

        Returns:
            A frozen :class:`Finding` tagged with ``self.name``.
        """
        effective_rule = rule_id or f"{self.rule_prefix}-{self.name.upper()}-000"
        return Finding(
            title=title,
            severity=severity,
            file_path=file_path,
            description=description,
            mitigation=mitigation,
            rule_id=effective_rule,
            category=self.name,
            line=line,
            evidence=evidence,
            references=tuple(references),
        )

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<{type(self).__name__} name={self.name!r} version={self.version!r}>"


# ---------------------------------------------------------------------------
# Filesystem helpers (defensive traversal)
# ---------------------------------------------------------------------------


def relative_posix(root: Path, path: Path) -> str:
    """Return ``path`` relative to ``root`` using forward slashes.

    Falls back to the absolute path when ``path`` is not under ``root`` (this
    only happens for unexpected inputs and is never hidden from the report).

    Args:
        root: The scanned rootfs.
        path: A path inside ``root``.

    Returns:
        A POSIX-style relative path such as ``etc/ssh/ssh_host_rsa_key``.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_elf(path: Path) -> bool:
    """Return ``True`` when ``path`` starts with the ``\\x7fELF`` magic.

    Reading four bytes is enough and avoids trusting the executable bit, which
    is frequently mangled when a rootfs travels through a squashfs -> tar ->
    zip chain.

    Args:
        path: File to probe; must be a regular file.

    Returns:
        ``True`` if the ELF magic is present.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def read_text_lossy(path: Path, *, max_bytes: int = 4 * 1024 * 1024) -> str | None:
    """Read a text file tolerantly.

    Firmware configuration files are routinely ISO-8859-1, truncated or
    sprinkled with NUL bytes. Decoding must never abort an audit.

    Args:
        path: File to read.
        max_bytes: Maximum number of bytes to read.

    Returns:
        The decoded text, or ``None`` when the file cannot be read.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes)
    except OSError:
        return None
    if b"\x00" in raw[:4096] and raw[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        # Likely a binary blob masquerading as text (or UTF-16 without BOM).
        return None
    return raw.decode("utf-8", errors="replace")


class EntryKind(enum.Enum):
    """Kind of filesystem entry yielded by the traversal helpers."""

    FILE = "file"
    DIRECTORY = "directory"


@dataclass(slots=True)
class TraversalStats:
    """Coverage metadata collected during one filesystem traversal."""

    entries_seen: int = 0
    entries_skipped: int = 0
    truncated: bool = False
    unreadable_dirs: int = 0

    def as_dict(self) -> dict[str, int | bool]:
        """Return JSON-serialisable traversal metadata."""
        return {
            "entries_seen": self.entries_seen,
            "entries_skipped": self.entries_skipped,
            "truncated": self.truncated,
            "unreadable_dirs": self.unreadable_dirs,
        }


def iter_entries(
    root: Path,
    config: AnalyzerConfig | None = None,
    stats: TraversalStats | None = None,
) -> Iterator[tuple[Path, os.stat_result, EntryKind]]:
    """Yield ``(path, lstat, kind)`` triples without following symlinks.

    Uses an explicit stack instead of :meth:`Path.rglob` so that:

    * symlinks are never traversed, making cyclic symlinks structurally
      impossible to recurse into (the framework never calls ``stat`` on a link
      target);
    * only regular files and real directories are yielded -- FIFOs, sockets and
      device nodes are skipped so that a later ``open()`` can never block;
    * unreadable directories are skipped instead of aborting the audit;
    * the traversal is bounded by ``config.max_filesystem_entries``.

    Symlinks are always treated as leaf entries and are never followed. This
    is a mandatory safety policy: following links could escape the rootfs or
    recurse indefinitely through cyclic firmware links.

    The directory ``root`` itself is never yielded.

    Args:
        root: Directory to walk.
        config: Traversal configuration; defaults to :class:`AnalyzerConfig`.
        stats: Optional object populated with traversal coverage metadata.

    Yields:
        ``(path, lstat_result, kind)`` triples in unspecified order.
    """
    effective = config or AnalyzerConfig()
    metadata = stats or TraversalStats()
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as scanner:
                entries = list(scanner)
        except OSError:
            # Permission denied, vanished directory, I/O error: keep going.
            metadata.unreadable_dirs += 1
            continue
        for entry in entries:
            metadata.entries_seen += 1
            if metadata.entries_seen > effective.max_filesystem_entries:
                metadata.truncated = True
                return
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                metadata.entries_skipped += 1
                continue
            entry_path = Path(entry.path)
            try:
                relative = entry_path.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - defensive
                metadata.entries_skipped += 1
                continue
            if effective.is_excluded(relative):
                metadata.entries_skipped += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                yield entry_path, st, EntryKind.DIRECTORY
                stack.append(entry_path)
            elif stat.S_ISREG(st.st_mode):
                yield entry_path, st, EntryKind.FILE
            else:
                metadata.entries_skipped += 1


def walk_files(
    root: Path,
    config: AnalyzerConfig | None = None,
    stats: TraversalStats | None = None,
) -> Iterator[tuple[Path, os.stat_result]]:
    """Yield regular files under ``root`` together with their ``lstat`` result.

    Symlinks are not followed and special files are skipped; see
    :func:`iter_entries` for the full rationale. ``stats`` receives the
    traversal coverage metadata when supplied.

    Args:
        root: Directory to walk.
        config: Traversal configuration; defaults to :class:`AnalyzerConfig`.

    Yields:
        ``(path, lstat_result)`` tuples in unspecified order.
    """
    for path, st, kind in iter_entries(root, config, stats):
        if kind is EntryKind.FILE:
            yield path, st


def walk_directories(
    root: Path,
    config: AnalyzerConfig | None = None,
    stats: TraversalStats | None = None,
) -> Iterator[tuple[Path, os.stat_result]]:
    """Yield directories under ``root``, excluding ``root`` itself.

    Args:
        root: Directory to walk.
        config: Traversal configuration; defaults to :class:`AnalyzerConfig`.
        stats: Optional object populated with traversal coverage metadata.

    Yields:
        ``(path, lstat_result)`` tuples in unspecified order.
    """
    for path, st, kind in iter_entries(root, config, stats):
        if kind is EntryKind.DIRECTORY:
            yield path, st
