"""Analyzer plugin registry.

Every concrete :class:`~firmware_auditor.analyzers.base.BaseAnalyzer` subclass is
listed once in :data:`ANALYZER_CLASSES`. The registry resolves the *instance*
``name`` property lazily instead of duplicating the identifier in a second
mapping, so there is exactly one source of truth per plugin: if an analyzer
renames itself, ``--analyzers`` and the reports follow automatically.

Public helpers:

* :func:`available_analyzers` -- name to class mapping (read-only).
* :func:`analyzer_names` -- registered names, in declaration order.
* :func:`build_analyzers` -- instantiate a selection, validating the names.

Declaration order is the execution order for ``--jobs 1``, which keeps output
stable across runs.
"""

from __future__ import annotations

from functools import lru_cache
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from analyzers.base import (
    AnalyzerConfig,
    AnalyzerError,
    BaseAnalyzer,
    Finding,
    Severity,
)
from analyzers.binary_hardening import BinaryHardeningAnalyzer, ElfFacts
from analyzers.filesystem_hygiene import (
    FilesystemHygieneAnalyzer,
    FilesystemHygieneStats,
    PasswdEntry,
    ShadowEntry,
)

__all__ = [
    # Contracts, re-exported so plugins only need this package.
    "AnalyzerConfig",
    "AnalyzerError",
    "BaseAnalyzer",
    "Finding",
    "Severity",
    # Concrete analyzers.
    "BinaryHardeningAnalyzer",
    "ElfFacts",
    "FilesystemHygieneAnalyzer",
    "FilesystemHygieneStats",
    "PasswdEntry",
    "ShadowEntry",
    # Registry.
    "ANALYZER_CLASSES",
    "analyzer_names",
    "available_analyzers",
    "build_analyzers",
]

#: Every shipped analyzer, in declaration (= default execution) order.
#:
#: Adding a plugin means appending its class here; nothing else in the framework
#: needs to change for the CLI, the pipeline or the reporters to pick it up.
ANALYZER_CLASSES: Final[tuple[type[BaseAnalyzer], ...]] = (
    BinaryHardeningAnalyzer,
    FilesystemHygieneAnalyzer,
)


@lru_cache(maxsize=1)
def _registry() -> dict[str, type[BaseAnalyzer]]:
    """Build the name-to-class mapping once.

    The ``name`` of an analyzer is an instance property, so a throwaway instance
    per class is the canonical way to read it. Instantiation is side-effect free
    by contract (``__init__`` only stores configuration), and the result is
    cached, so this happens at most once per process.

    Returns:
        A mutable mapping from analyzer name to its class.

    Raises:
        AnalyzerError: If a plugin exposes an empty or duplicated name; both
            would make ``--analyzers`` ambiguous.
    """
    mapping: dict[str, type[BaseAnalyzer]] = {}
    for analyzer_class in ANALYZER_CLASSES:
        name = analyzer_class().name
        if not name:
            raise AnalyzerError(
                analyzer_class.__name__,
                "analyzer exposes an empty 'name'; every plugin needs a stable identifier",
            )
        if name in mapping:
            raise AnalyzerError(
                name,
                f"duplicate analyzer name shared by {mapping[name].__name__} and "
                f"{analyzer_class.__name__}",
            )
        mapping[name] = analyzer_class
    return mapping


def available_analyzers() -> Mapping[str, type[BaseAnalyzer]]:
    """Return the registered analyzers as a read-only mapping.

    Returns:
        Analyzer name to class. Ordering follows :data:`ANALYZER_CLASSES`.
    """
    return MappingProxyType(_registry())


def analyzer_names() -> tuple[str, ...]:
    """Return the registered analyzer names in declaration order.

    Returns:
        A tuple such as ``("binary_hardening", "filesystem_hygiene")``.
    """
    return tuple(_registry())


def build_analyzers(
    names: Sequence[str] | None = None,
    config: AnalyzerConfig | None = None,
) -> list[BaseAnalyzer]:
    """Instantiate the requested analyzers.

    Args:
        names: Analyzer identifiers to enable. ``None`` enables every registered
            analyzer. Names are matched case-insensitively and de-duplicated
            while preserving the caller's order, so ``--analyzers a,a,b`` runs
            two analyzers, not three.
        config: Configuration forwarded to each analyzer. This is the single
            place where exclude globs, size caps and traversal limits are set.

    Returns:
        One instance per resolved name, in the order requested.

    Raises:
        ValueError: If a requested name is unknown or if ``names`` resolves to an
            empty selection. The error message lists what is available, because
            this surfaces directly in the CLI.
    """
    registry = _registry()
    if names is None:
        selected = list(registry)
    else:
        selected = []
        for raw_name in names:
            name = raw_name.strip().lower()
            if not name:
                continue
            if name not in registry:
                available = ", ".join(registry) or "<none>"
                raise ValueError(f"unknown analyzer {raw_name!r} (available: {available})")
            if name not in selected:
                selected.append(name)

    if not selected:
        raise ValueError("no analyzer selected; pass at least one name or None for all")

    return [registry[name](config) for name in selected]
