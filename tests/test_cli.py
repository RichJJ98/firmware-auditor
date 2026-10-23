from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def run_cli(rootfs: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    return subprocess.run(
        [sys.executable, "-m", "cli", str(rootfs), *arguments],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_exit_code_zero_for_clean_rootfs(rootfs: Path) -> None:
    completed = run_cli(rootfs)
    assert completed.returncode == 0
    assert "No findings" in completed.stdout


def test_cli_exit_code_one_for_gate_finding(rootfs: Path) -> None:
    etc = rootfs / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root::0:0:root:/root:/bin/sh\n", encoding="utf-8")

    completed = run_cli(rootfs)

    assert completed.returncode == 1
    assert "gate tripped" in completed.stderr


def test_cli_exit_code_two_for_invalid_rootfs(rootfs: Path) -> None:
    completed = run_cli(rootfs / "does-not-exist")

    assert completed.returncode == 2
    assert "does not exist" in completed.stderr

