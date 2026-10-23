from __future__ import annotations

import os
import stat
from pathlib import Path

from analyzers.filesystem_hygiene import FilesystemHygieneAnalyzer


def test_private_key_is_detected_without_leaking_material(rootfs: Path) -> None:
    key = rootfs / "id_rsa"
    secret = "-----BEGIN RSA PRIVATE KEY-----\nPRIVATE-DATA\n"
    key.write_text(secret, encoding="ascii")

    findings = FilesystemHygieneAnalyzer().run(rootfs)

    private = [finding for finding in findings if finding.rule_id == "FWK-KEY-001"]
    assert private
    assert private[0].file_path == "id_rsa"
    assert "PRIVATE-DATA" not in private[0].description
    assert "PRIVATE-DATA" not in (private[0].evidence or "")


def test_world_writable_sensitive_file_is_detected(rootfs: Path) -> None:
    etc = rootfs / "etc"
    etc.mkdir()
    passwd = etc / "passwd"
    passwd.write_text("root::0:0:root:/root:/bin/sh\n", encoding="utf-8")
    os.chmod(passwd, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)

    findings = FilesystemHygieneAnalyzer().run(rootfs)

    assert any(finding.rule_id == "FWK-PERM-002" for finding in findings)
    assert any(finding.rule_id == "FWK-ACCT-002" for finding in findings)

