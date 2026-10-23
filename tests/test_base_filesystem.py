from __future__ import annotations

import os
from pathlib import Path

import pytest

from analyzers.base import AnalyzerConfig, TraversalStats, iter_entries
from analyzers import build_analyzers
from core.pipeline import Pipeline


def test_symlinks_are_not_followed(rootfs: Path) -> None:
    target = rootfs / "target"
    target.write_text("target", encoding="utf-8")
    link = rootfs / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    entries = list(iter_entries(rootfs))
    paths = {path.relative_to(rootfs).as_posix() for path, _stat, _kind in entries}
    assert "target" in paths
    assert "link" not in paths


def test_protected_pseudo_filesystem_paths_are_excluded(rootfs: Path) -> None:
    proc = rootfs / "proc"
    proc.mkdir()
    (proc / "secret").write_text("not scanned", encoding="utf-8")

    entries = list(iter_entries(rootfs, AnalyzerConfig(exclude_globs=("proc",))))
    assert all(path.relative_to(rootfs).as_posix() != "proc/secret" for path, _stat, _kind in entries)


def test_traversal_records_coverage_metadata(rootfs: Path) -> None:
    (rootfs / "included").write_text("x", encoding="utf-8")
    (rootfs / "excluded").write_text("y", encoding="utf-8")
    stats = TraversalStats()

    entries = list(
        iter_entries(rootfs, AnalyzerConfig(exclude_globs=("excluded",)), stats)
    )

    assert len(entries) == 1
    assert stats.entries_seen == 2
    assert stats.entries_skipped == 1
    assert stats.truncated is False


def test_truncation_is_an_incomplete_scan(rootfs: Path) -> None:
    (rootfs / "one").write_text("x", encoding="utf-8")
    (rootfs / "two").write_text("y", encoding="utf-8")
    analyzer = build_analyzers(
        ["filesystem_hygiene"],
        AnalyzerConfig(max_filesystem_entries=1),
    )[0]

    result = Pipeline([analyzer], min_severity="info").run(rootfs)

    assert result.successful is False
    assert result.to_dict()["scan"]["complete"] is False
    assert result.errors[0].error_type == "AuditIncompleteError"
    assert result.reports[0].stats is not None
    assert result.reports[0].stats["truncated"] is True

