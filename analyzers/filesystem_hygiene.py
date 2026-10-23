"""Filesystem posture auditor: weak permissions, exposed key material, account hygiene.

This analyzer covers the *configuration* half of an embedded Linux audit; the
exploit-mitigation half lives in :mod:`firmware_auditor.analyzers.binary_hardening`.

Rules implemented
-----------------
===========================  ==========  =========================================
Rule                         Severity    Detection
===========================  ==========  =========================================
``FWK-PERM-001``             critical¹   world-writable directory (``o+w``)
``FWK-PERM-002``             critical    world-writable file in a sensitive tree
``FWK-PERM-003``             high        credential file writable by its group
``FWK-PERM-004``             critical    ``/etc/shadow`` or ``/etc/gshadow``
                                         readable by any user
``FWK-PERM-005``             medium      setuid binary outside the expected set
                                         (``info`` when it is an expected one)
``FWK-PERM-006``             low         setgid binary
``FWK-KEY-001``              critical    private key material confirmed in content
``FWK-KEY-002``              high        filename implies a private key but the
                                         content cannot confirm it
``FWK-KEY-003``              critical    SSH host key shipped in the image
``FWK-KEY-004``              info        certificate or public key present
``FWK-KEY-005``              high        plaintext pre-shared key in
                                         ``wpa_supplicant`` configuration
``FWK-KEY-006``              low         embedded ``authorized_keys``
``FWK-ACCT-001``             critical    UID 0 account other than ``root``
``FWK-ACCT-002``             critical    empty password field in ``/etc/passwd``
``FWK-ACCT-003``             critical    empty hash in ``/etc/shadow``
``FWK-ACCT-004``             critical²   weak or legacy password hash
                                         (DES, MD5, SHA-256, unrecognised)
``FWK-ACCT-005``             low         system account (UID < 1000) with an
                                         interactive login shell
``FWK-ACCT-006``             high        password *hash* stored in the
                                         world-readable ``/etc/passwd``
``FWK-ACCT-007``             info        ``/etc/passwd`` references shadow but
                                         ``/etc/shadow`` is absent
``FWK-ACCT-008``             medium      duplicated UID
``FWK-ACCT-009``             critical    plaintext (non-hash) password in
                                         ``/etc/passwd``
===========================  ==========  =========================================

¹ ``critical`` inside a sensitive tree, ``medium`` elsewhere.
² ``critical`` for DES, ``high`` for MD5, ``low`` for SHA-256.

Design notes
------------
* **Content is never trusted over the executable bit, and symlinks are never
  followed.** Firmware images routinely contain absolute symlinks
  (``etc/passwd`` -> ``/etc/passwd``). Opening one would resolve against the
  *analyst's* host and silently audit the workstation instead of the image, so
  every read goes through :func:`_read_bytes_safely`, which ``lstat``s first and
  refuses anything that is not a regular file.
* **Secrets are never copied into the report.** Evidence strings carry the PEM
  header, the hash *format* label or the length of a pre-shared key -- never the
  secret itself. A finding is attached to a pipeline and may end up in a public
  SARIF file; echoing a private key there would turn an audit into a leak.
* **Malformed input is skipped, never fatal.** Truncated ``passwd`` lines, NIS
  ``+``/``-`` compatibility entries, NUL-padded configuration blobs and
  unreadable files all produce zero findings rather than an exception, because a
  firmware dump almost always contains a few broken files.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Sequence

from analyzers.base import (
    AnalyzerConfig,
    BaseAnalyzer,
    EntryKind,
    Finding,
    Severity,
    TraversalStats,
    iter_entries,
    relative_posix,
)

__all__ = [
    "FilesystemHygieneAnalyzer",
    "FilesystemHygieneStats",
    "PasswdEntry",
    "ShadowEntry",
]


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

#: Bytes read when sniffing key material. PEM headers live in the first line.
KEY_READ_BYTES: Final[int] = 8 * 1024

#: Bytes read for configuration files that may embed a secret further down.
CONFIG_READ_BYTES: Final[int] = 256 * 1024

#: Account databases are tiny; anything larger is not a real ``passwd`` file.
MAX_ACCOUNT_FILE_BYTES: Final[int] = 1024 * 1024

#: Directories whose contents are loaded, executed or parsed by privileged
#: processes. A writable entry here is a privilege-escalation primitive.
SENSITIVE_DIR_PREFIXES: Final[tuple[str, ...]] = (
    "etc",
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "usr/local/bin",
    "usr/local/sbin",
    "lib",
    "lib32",
    "lib64",
    "usr/lib",
    "usr/lib64",
    "usr/local/lib",
    "boot",
    "root",
    "opt",
    "var/www",
    "www",
)

#: Directories that are *supposed* to be world-writable. Reporting them would
#: bury the real findings in noise.
EXPECTED_WORLD_WRITABLE_DIRS: Final[frozenset[str]] = frozenset(
    {
        "tmp",
        "var/tmp",
        "var/lock",
        "var/run",
        "run",
        "dev",
        "dev/shm",
        "dev/mqueue",
        "dev/pts",
        "proc",
        "sys",
        "var/mail",
        "var/spool/mail",
        "var/spool/lpd",
    }
)

#: Files whose mode directly governs credential confidentiality.
CREDENTIAL_FILES: Final[frozenset[str]] = frozenset(
    {
        "etc/shadow",
        "etc/gshadow",
        "etc/passwd",
        "etc/group",
        "etc/sudoers",
        "etc/ssh/sshd_config",
        "etc/dropbear/dropbear.conf",
    }
)

#: Credential files that must never be world-readable (hashes are offline-crackable).
SECRET_FILES: Final[frozenset[str]] = frozenset({"etc/shadow", "etc/gshadow"})

#: Setuid binaries a mainstream distribution legitimately ships. Anything else
#: deserves a human look, and a root-owned setuid helper in an IoT image is a
#: classic vendor backdoor.
EXPECTED_SETUID: Final[frozenset[str]] = frozenset(
    {
        "bin/su",
        "bin/mount",
        "bin/umount",
        "bin/ping",
        "bin/ping6",
        "bin/fusermount",
        "usr/bin/su",
        "usr/bin/mount",
        "usr/bin/umount",
        "usr/bin/ping",
        "usr/bin/ping6",
        "usr/bin/passwd",
        "usr/bin/sudo",
        "usr/bin/sudoedit",
        "usr/bin/newgrp",
        "usr/bin/chsh",
        "usr/bin/chfn",
        "usr/bin/gpasswd",
        "usr/bin/crontab",
        "usr/bin/pkexec",
        "usr/bin/fusermount",
        "usr/lib/openssh/ssh-keysign",
        "usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "usr/libexec/dbus-daemon-launch-helper",
        "sbin/unix_chkpwd",
        "usr/sbin/unix_chkpwd",
        "usr/lib/chromium/chrome-sandbox",
    }
)

#: Filenames that normally carry private key material.
KEY_NAME_PATTERNS: Final[tuple[str, ...]] = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*.pem",
    "*.key",
    "*.p8",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.ppk",
    "*.kdbx",
    "*.ovpn",
    "*.asc",
)

#: Host keys are special: every device sharing one is impersonable.
HOST_KEY_PATTERNS: Final[tuple[str, ...]] = (
    "ssh_host_*_key",
    "dropbear_*host_key",
    "dropbear_*_host_key",
)

#: Public material: present in almost every image, reported as information only.
PUBLIC_NAME_PATTERNS: Final[tuple[str, ...]] = ("*.crt", "*.cer", "*.pub", "*.csr")

AUTHORIZED_KEYS_PATTERNS: Final[tuple[str, ...]] = ("authorized_keys", "authorized_keys2")

#: Configuration files that may embed a Wi-Fi pre-shared key.
WPA_PATTERNS: Final[tuple[str, ...]] = ("wpa_supplicant*.conf", "wpa_supplicant*.config")

#: Shells that do not grant an interactive session.
NON_INTERACTIVE_SHELLS: Final[frozenset[str]] = frozenset(
    {
        "",
        "/bin/false",
        "/usr/bin/false",
        "/bin/true",
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/usr/bin/nologin",
        "/bin/sync",
        "/sbin/halt",
        "/sbin/shutdown",
        "/sbin/reboot",
        "/usr/sbin/shutdown",
    }
)

#: Password-field markers meaning "no usable password here".
LOCKED_MARKERS: Final[frozenset[str]] = frozenset({"", "x", "*", "!", "!!", "*LK*", "NP", "!*"})

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

#: ``-----BEGIN [<algo> ]PRIVATE KEY-----`` covering RSA/EC/DSA/OPENSSH/ENCRYPTED.
_PRIVATE_KEY_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
)
_PUTTY_KEY_RE: Final[re.Pattern[bytes]] = re.compile(rb"PuTTY-User-Key-File-\d")
_CERTIFICATE_RE: Final[re.Pattern[bytes]] = re.compile(rb"-----BEGIN CERTIFICATE-----")
_PUBLIC_KEY_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA )?PUBLIC KEY-----"
)

#: Legacy ``crypt(3)`` DES: exactly 13 characters with no ``$`` separator.
_DES_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[./0-9A-Za-z]{13}$")

#: ``psk=...`` / ``psk = "..."`` inside a wpa_supplicant configuration.
_PSK_RE: Final[re.Pattern[str]] = re.compile(r"^\s*psk\s*=\s*(?P<value>.*)$", re.IGNORECASE)

_PRIVATE_KINDS: Final[frozenset[str]] = frozenset({"private", "putty"})

_REFERENCES: Final[dict[str, tuple[str, ...]]] = {
    "perm": ("https://cwe.mitre.org/data/definitions/732.html",),
    "creds": ("https://cwe.mitre.org/data/definitions/522.html",),
    "hardcoded": ("https://cwe.mitre.org/data/definitions/798.html",),
    "passwd": ("https://cwe.mitre.org/data/definitions/521.html",),
    "setuid": ("https://cwe.mitre.org/data/definitions/250.html",),
}


# ---------------------------------------------------------------------------
# Parsed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PasswdEntry:
    """One parsed line of ``/etc/passwd``.

    Attributes:
        name: Login name.
        password: Second field verbatim (``x``, ``*``, empty, a hash or worse).
        uid: Numeric user id.
        gid: Numeric group id.
        home: Home directory field.
        shell: Login shell field.
        line: 1-based line number in the source file.
    """

    name: str
    password: str
    uid: int
    gid: int
    home: str
    shell: str
    line: int


@dataclass(frozen=True, slots=True)
class ShadowEntry:
    """One parsed line of ``/etc/shadow``.

    Attributes:
        name: Login name the entry belongs to.
        password: Hash field verbatim; ``""`` means "no password required".
        line: 1-based line number in the source file.
    """

    name: str
    password: str
    line: int


@dataclass(slots=True)
class FilesystemHygieneStats:
    """Counters describing one :meth:`FilesystemHygieneAnalyzer.run` pass.

    Attributes:
        files_scanned: Regular files examined.
        sensitive_files: How many of those sat in a sensitive tree.
        world_writable: World-writable files and directories detected.
        key_files: Key-looking files whose content was inspected.
        accounts_checked: Account records evaluated across passwd and shadow.
        findings: Number of findings emitted by the pass.
        traversal: Filesystem traversal coverage metadata.
    """

    files_scanned: int = 0
    sensitive_files: int = 0
    world_writable: int = 0
    key_files: int = 0
    accounts_checked: int = 0
    findings: int = 0
    traversal: TraversalStats = field(default_factory=TraversalStats)

    def as_dict(self) -> dict[str, int | bool]:
        """Return a JSON-serialisable summary of the counters."""
        return {
            "files_scanned": self.files_scanned,
            "sensitive_files": self.sensitive_files,
            "world_writable": self.world_writable,
            "key_files": self.key_files,
            "accounts_checked": self.accounts_checked,
            "findings": self.findings,
            **self.traversal.as_dict(),
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _matches_any(filename: str, patterns: Sequence[str]) -> bool:
    """Case-insensitive glob match of ``filename`` against ``patterns``.

    Args:
        filename: Base name, with extension, of the candidate file.
        patterns: Lower-case glob patterns.

    Returns:
        ``True`` when at least one pattern matches.
    """
    lowered = filename.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in patterns)


def _in_sensitive_dir(relative_path: str) -> bool:
    """Return whether a rootfs-relative path lives in a sensitive tree.

    Args:
        relative_path: POSIX path relative to the rootfs.

    Returns:
        ``True`` for ``etc``, ``etc/init.d/rcS``, ``usr/bin/busybox`` and
        similar; ``False`` for ``tmp/x`` or ``home/user/notes``.
    """
    for prefix in SENSITIVE_DIR_PREFIXES:
        if relative_path == prefix or relative_path.startswith(prefix + "/"):
            return True
    return False


def _is_expected_world_writable(relative_path: str) -> bool:
    """Return whether a world-writable directory is an expected one.

    Args:
        relative_path: POSIX path of the directory relative to the rootfs.

    Returns:
        ``True`` for ``tmp``, ``var/tmp/x``, ``dev/shm`` and friends.
    """
    if relative_path in EXPECTED_WORLD_WRITABLE_DIRS:
        return True
    return any(
        relative_path.startswith(expected + "/") for expected in EXPECTED_WORLD_WRITABLE_DIRS
    )


def _read_bytes_safely(path: Path, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes from a regular file, never following links.

    Firmware rootfs images are full of absolute symlinks. Following one would
    make the audit read the analyst's own filesystem, so the mode is checked with
    :meth:`Path.lstat` first and any non-regular entry is refused. FIFOs are also
    rejected here, which is what keeps ``open()`` from blocking forever.

    Args:
        path: Candidate file.
        limit: Maximum number of bytes to read.

    Returns:
        The bytes read (possibly empty), or ``None`` when the entry is not a
        regular file or cannot be read.
    """
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _read_text_safely(path: Path, limit: int) -> str | None:
    """Read a small text database tolerantly and without following symlinks.

    Args:
        path: Candidate ``passwd``/``shadow`` style file.
        limit: Maximum number of bytes to read.

    Returns:
        The decoded text, or ``None`` when the file is absent, is not a regular
        file, or looks binary. Decoding never raises: firmware configuration
        files are routinely ISO-8859-1 or truncated.
    """
    raw = _read_bytes_safely(path, limit)
    if raw is None:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _classify_key_material(head: bytes | None) -> str | None:
    """Classify the first bytes of a candidate key file.

    Only the *header* is inspected; the body is never parsed or retained.

    Args:
        head: Leading bytes of the file, or ``None`` when unreadable.

    Returns:
        ``"private"``, ``"putty"``, ``"certificate"``, ``"public"`` or ``None``.
    """
    if not head:
        return None
    if _PRIVATE_KEY_RE.search(head):
        return "private"
    if _PUTTY_KEY_RE.search(head):
        return "putty"
    if _CERTIFICATE_RE.search(head):
        return "certificate"
    if _PUBLIC_KEY_RE.search(head):
        return "public"
    return None


def _looks_like_hash(value: str) -> bool:
    """Return whether a password field looks like an encoded hash.

    Args:
        value: Raw password field.

    Returns:
        ``True`` for ``$6$...``, ``$1$...`` and 13-character DES strings.
    """
    return value.startswith("$") or bool(_DES_HASH_RE.match(value))


def _classify_hash(value: str) -> tuple[Severity | None, str]:
    """Classify a ``/etc/shadow`` hash by algorithm and crackability.

    Args:
        value: Raw hash field.

    Returns:
        ``(severity, label)``. ``severity`` is ``None`` when the entry is locked,
        disabled or uses an algorithm that needs no finding; ``label`` is a short
        algorithm description suitable for a report (never the hash itself).
    """
    if value == "":
        return Severity.CRITICAL, "empty"
    if value.startswith("!"):
        return None, "locked"
    if value in {"*", "*LK*", "x", "NP", "!!"}:
        return None, "disabled"
    if value.startswith("$1$"):
        return Severity.HIGH, "MD5 crypt"
    if value.startswith("$5$"):
        return Severity.LOW, "SHA-256 crypt"
    if value.startswith("$6$"):
        return None, "SHA-512 crypt"
    if value.startswith("$y$") or value.startswith("$gy$"):
        return None, "yescrypt"
    if value.startswith("$2"):
        return None, "bcrypt"
    if value.startswith("$7$"):
        return Severity.MEDIUM, "scrypt (parameters unknown)"
    if _DES_HASH_RE.match(value):
        # 56-bit DES crypt is brute-forceable in minutes on commodity hardware.
        return Severity.CRITICAL, "DES crypt"
    return Severity.MEDIUM, "unrecognised format"


def _is_interactive_shell(shell: str) -> bool:
    """Return whether a login shell grants an interactive session.

    Args:
        shell: Shell field from ``/etc/passwd``.

    Returns:
        ``False`` for empty fields and the usual ``nologin``/``false`` helpers.
    """
    return shell.strip() not in NON_INTERACTIVE_SHELLS


def _parse_passwd(text: str) -> list[PasswdEntry]:
    """Parse ``/etc/passwd`` leniently.

    Skips comments, blank lines, NIS ``+``/``-`` compatibility entries and lines
    with too few fields or a non-numeric UID. Malformed records are dropped
    silently: a truncated firmware file must not abort the audit.

    Args:
        text: Decoded file contents.

    Returns:
        Parsed entries in file order.
    """
    entries: list[PasswdEntry] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "+-":
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        name, password, uid_text, gid_text, _gecos, home, shell = fields[:7]
        try:
            uid = int(uid_text)
            gid = int(gid_text)
        except ValueError:
            continue
        entries.append(
            PasswdEntry(
                name=name,
                password=password,
                uid=uid,
                gid=gid,
                home=home,
                shell=shell,
                line=index,
            )
        )
    return entries


def _parse_shadow(text: str) -> list[ShadowEntry]:
    """Parse ``/etc/shadow`` leniently.

    Args:
        text: Decoded file contents.

    Returns:
        Parsed entries in file order; malformed lines are skipped.
    """
    entries: list[ShadowEntry] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "+-":
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        entries.append(ShadowEntry(name=fields[0], password=fields[1], line=index))
    return entries


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class FilesystemHygieneAnalyzer(BaseAnalyzer):
    """Audit permissions, key material and account hygiene on an extracted rootfs.

    The traversal is single-pass: one :func:`iter_entries` walk feeds the
    permission, setuid and key checks, and the account database is read
    separately because it needs cross-line correlation (``passwd`` joined against
    ``shadow``).

    Nothing is written, executed or mounted; every file is opened read-only and
    closed immediately.
    """

    description = (
        "Audits world-writable paths, exposed private keys and passwd/shadow account hygiene."
    )
    version = "1.0.0"

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        super().__init__(config)
        self._stats = FilesystemHygieneStats()

    @property
    def name(self) -> str:
        """Analyzer identifier used by ``--analyzers`` and the reports."""
        return "filesystem_hygiene"

    @property
    def stats(self) -> FilesystemHygieneStats:
        """Counters for the most recent :meth:`run` invocation."""
        return self._stats

    # -- public API --------------------------------------------------------

    def run(self, rootfs_path: Path) -> list[Finding]:
        """Scan ``rootfs_path`` for filesystem and account weaknesses.

        Args:
            rootfs_path: Root of the extracted firmware filesystem.

        Returns:
            All findings, unsorted. The pipeline applies severity filtering and
            deterministic ordering.
        """
        self._stats = FilesystemHygieneStats()
        findings: list[Finding] = []

        for path, info, kind in iter_entries(rootfs_path, self.config, self._stats.traversal):
            relative = relative_posix(rootfs_path, path)
            if kind is EntryKind.DIRECTORY:
                findings.extend(self._check_directory(relative, info))
                continue

            self._stats.files_scanned += 1
            if _in_sensitive_dir(relative):
                self._stats.sensitive_files += 1
            findings.extend(self._check_file_permissions(relative, info))
            findings.extend(self._check_key_material(relative, path, info))

        findings.extend(self._audit_accounts(rootfs_path))
        self._stats.findings = len(findings)
        return findings

    # -- permissions -------------------------------------------------------

    def _check_directory(self, relative: str, info: os.stat_result) -> list[Finding]:
        """Report world-writable directories that are not expected ones.

        A world-writable directory inside ``/etc`` lets any local user rename or
        replace a root-owned file, which is a direct privilege escalation.

        Args:
            relative: Rootfs-relative POSIX path of the directory.
            info: ``lstat`` result for the directory.

        Returns:
            Zero or one finding.
        """
        if not info.st_mode & stat.S_IWOTH:
            return []
        if _is_expected_world_writable(relative):
            return []

        self._stats.world_writable += 1
        sensitive = _in_sensitive_dir(relative)
        severity = Severity.CRITICAL if sensitive else Severity.MEDIUM
        return [
            self.make_finding(
                title="World-writable directory",
                severity=severity,
                file_path=relative,
                description=(
                    f"Directory '{relative}' is writable by every user (mode "
                    f"{stat.filemode(info.st_mode)}). Any local account can create, rename "
                    "or delete entries here"
                    + (
                        ", and this tree is consumed by privileged processes, so a local "
                        "attacker can replace a root-executed file."
                        if sensitive
                        else "."
                    )
                ),
                mitigation=(
                    "Restrict the mode to '0755' (or '0750'/'0700' where group access is not "
                    "needed) and confirm no service depends on anonymous write access."
                ),
                rule_id="FWK-PERM-001",
                evidence=f"mode={stat.filemode(info.st_mode)}",
                references=_REFERENCES["perm"],
            )
        ]

    def _check_file_permissions(self, relative: str, info: os.stat_result) -> list[Finding]:
        """Apply the file-level permission rules to one regular file.

        Args:
            relative: Rootfs-relative POSIX path of the file.
            info: ``lstat`` result for the file.

        Returns:
            Zero or more findings (world-write, credential mode, setuid/setgid).
        """
        findings: list[Finding] = []
        mode = info.st_mode

        if mode & stat.S_IWOTH and (_in_sensitive_dir(relative) or relative in CREDENTIAL_FILES):
            self._stats.world_writable += 1
            findings.append(
                self.make_finding(
                    title="World-writable file in a sensitive tree",
                    severity=Severity.CRITICAL,
                    file_path=relative,
                    description=(
                        f"'{relative}' is writable by any user (mode {stat.filemode(mode)}). "
                        "An unprivileged account can rewrite a configuration file or replace a "
                        "binary that root later executes."
                    ),
                    mitigation=(
                        "Remove the 'o+w' bit ('chmod o-w <file>'), fix the packaging recipe that "
                        "introduced it, and verify the shipped squashfs preserves the mode."
                    ),
                    rule_id="FWK-PERM-002",
                    evidence=f"mode={stat.filemode(mode)}",
                    references=_REFERENCES["perm"],
                )
            )

        if relative in CREDENTIAL_FILES:
            findings.extend(self._check_credential_mode(relative, mode))

        if mode & stat.S_ISUID:
            findings.append(self._setuid_finding(relative, mode))
        if mode & stat.S_ISGID:
            findings.append(
                self.make_finding(
                    title="Setgid binary",
                    severity=Severity.LOW,
                    file_path=relative,
                    description=(
                        f"'{relative}' carries the setgid bit (mode {stat.filemode(mode)}), so it "
                        "runs with the privileges of its group. Unless the group matters, this "
                        "widens the attack surface for no benefit."
                    ),
                    mitigation=(
                        "Drop the bit with 'chmod g-s <file>' unless the binary genuinely needs "
                        "group privileges, and keep the group ownership minimal."
                    ),
                    rule_id="FWK-PERM-006",
                    evidence=f"mode={stat.filemode(mode)}",
                    references=_REFERENCES["setuid"],
                )
            )

        return findings

    def _check_credential_mode(self, relative: str, mode: int) -> list[Finding]:
        """Check access bits on a credential-bearing file.

        Args:
            relative: Rootfs-relative POSIX path of the file.
            mode: Full ``st_mode`` value.

        Returns:
            Zero or more findings.
        """
        findings: list[Finding] = []

        if relative in SECRET_FILES and mode & stat.S_IROTH:
            findings.append(
                self.make_finding(
                    title="Password hash database readable by any user",
                    severity=Severity.CRITICAL,
                    file_path=relative,
                    description=(
                        f"'{relative}' is world-readable (mode {stat.filemode(mode)}). Every "
                        "account on the device can copy the password hashes and crack them "
                        "offline; on shared-hardware deployments the hashes are also identical "
                        "across devices."
                    ),
                    mitigation=(
                        "Restrict to 'root:shadow 0640' (or 'root:root 0600' where no setuid "
                        "helper needs it) and rotate any credential whose hash was exposed."
                    ),
                    rule_id="FWK-PERM-004",
                    evidence=f"mode={stat.filemode(mode)}",
                    references=_REFERENCES["creds"],
                )
            )

        if mode & stat.S_IWGRP and not mode & stat.S_IWOTH:
            findings.append(
                self.make_finding(
                    title="Credential file writable by its group",
                    severity=Severity.HIGH,
                    file_path=relative,
                    description=(
                        f"'{relative}' can be modified by any member of its group (mode "
                        f"{stat.filemode(mode)}). Writing to an account database is equivalent to "
                        "adding an account or resetting a password."
                    ),
                    mitigation=(
                        "Make the file group-readable but not group-writable ('chmod g-w'), and "
                        "keep the group limited to the privileged service that needs it."
                    ),
                    rule_id="FWK-PERM-003",
                    evidence=f"mode={stat.filemode(mode)}",
                    references=_REFERENCES["creds"],
                )
            )

        return findings

    def _setuid_finding(self, relative: str, mode: int) -> Finding:
        """Build the setuid finding, downgrading binaries from the expected set.

        Args:
            relative: Rootfs-relative POSIX path of the file.
            mode: Full ``st_mode`` value.

        Returns:
            A single finding.
        """
        expected = relative in EXPECTED_SETUID
        severity = Severity.INFO if expected else Severity.MEDIUM
        if expected:
            description = (
                f"'{relative}' is a setuid binary (mode {stat.filemode(mode)}). This one is part "
                "of the expected distribution set, so it is reported for inventory purposes only; "
                "keep its patch level current."
            )
            mitigation = (
                "No action required beyond patch management. Re-verify the install prefix if the "
                "distribution set changes."
            )
        else:
            description = (
                f"'{relative}' carries the setuid bit (mode {stat.filemode(mode)}) and is not part "
                "of the expected distribution set. Any defect in it becomes a local-to-root "
                "escalation, and vendor images often ship leftover setuid helpers as a support "
                "convenience."
            )
            mitigation = (
                "Remove the bit ('chmod u-s <file>') if elevation is not required, prefer "
                "capabilities ('setcap cap_net_raw+ep') for narrow needs, and audit the binary "
                "before shipping."
            )
        return self.make_finding(
            title="Setuid binary" if not expected else "Setuid binary (expected set)",
            severity=severity,
            file_path=relative,
            description=description,
            mitigation=mitigation,
            rule_id="FWK-PERM-005",
            evidence=f"mode={stat.filemode(mode)}",
            references=_REFERENCES["setuid"],
        )

    # -- key material ------------------------------------------------------

    def _check_key_material(
        self, relative: str, path: Path, info: os.stat_result
    ) -> list[Finding]:
        """Inspect one file for private keys, certificates and embedded secrets.

        Only files whose name or purpose suggests key material are opened, which
        keeps the pass cheap on a rootfs with tens of thousands of files.

        Args:
            relative: Rootfs-relative POSIX path of the file.
            path: Absolute path used for reading.
            info: ``lstat`` result for the file.

        Returns:
            Zero or more findings.
        """
        filename = path.name
        is_key_name = _matches_any(filename, KEY_NAME_PATTERNS)
        is_public_name = _matches_any(filename, PUBLIC_NAME_PATTERNS)
        is_host_key = _matches_any(filename, HOST_KEY_PATTERNS)
        is_authorized = _matches_any(filename, AUTHORIZED_KEYS_PATTERNS)
        is_wpa_config = _matches_any(filename, WPA_PATTERNS)

        if not (is_key_name or is_public_name or is_host_key or is_authorized or is_wpa_config):
            return []

        limit = CONFIG_READ_BYTES if is_wpa_config else KEY_READ_BYTES
        head = _read_bytes_safely(path, min(limit, max(info.st_size, 0) or limit))
        kind = _classify_key_material(head)
        findings: list[Finding] = []

        if kind in _PRIVATE_KINDS:
            self._stats.key_files += 1
            findings.append(self._private_key_finding(relative, kind, is_host_key))
        elif is_authorized:
            if head:
                findings.append(
                    self.make_finding(
                        title="Embedded SSH authorized_keys",
                        severity=Severity.LOW,
                        file_path=relative,
                        description=(
                            f"'{relative}' ships SSH public keys that are trusted for login on the "
                            "device. Any holder of the matching private key can authenticate; if the "
                            "image is shared, so is that access."
                        ),
                        mitigation=(
                            "Remove provisioned keys from production images, or generate them per "
                            "device during manufacturing and restrict the file to 'root 0600'."
                        ),
                        rule_id="FWK-KEY-006",
                        evidence=_redacted_ssh_evidence(head),
                        references=_REFERENCES["hardcoded"],
                    )
                )
        elif kind in {"certificate", "public"}:
            findings.append(
                self.make_finding(
                    title="Certificate or public key present",
                    severity=Severity.INFO,
                    file_path=relative,
                    description=(
                        f"'{relative}' contains "
                        f"{'a certificate' if kind == 'certificate' else 'a public key'}"
                        ". Public material is not confidential; it is listed so the trust store can "
                        "be reviewed (a committed private CA would let an attacker mint trusted "
                        "certificates)."
                    ),
                    mitigation=(
                        "Confirm the material is public and needed at runtime. Never ship the CA "
                        "private key alongside it."
                    ),
                    rule_id="FWK-KEY-004",
                    evidence=(
                        "-----BEGIN CERTIFICATE-----"
                        if kind == "certificate"
                        else "public key block"
                    ),
                )
            )
        elif is_key_name or is_host_key:
            self._stats.key_files += 1
            findings.append(
                self.make_finding(
                    title="Possible private key (content unconfirmed)",
                    severity=Severity.HIGH,
                    file_path=relative,
                    description=(
                        f"'{relative}' has a name typical of private key material but no PEM/PuTTY "
                        "header could be confirmed, so the severity is name-based only. Common "
                        "causes are an encrypted or binary key container, a truncated file, or a "
                        "placeholder."
                    ),
                    mitigation=(
                        "Confirm the file's purpose, remove it from the image if it is not needed at "
                        "runtime, and rotate the key if it was ever shipped."
                    ),
                    rule_id="FWK-KEY-002",
                    evidence=f"name matched key pattern; bytes_read={len(head) if head else 0}",
                    references=_REFERENCES["hardcoded"],
                )
            )

        if is_wpa_config:
            findings.extend(self._check_wpa_psk(relative, head))

        return findings

    def _private_key_finding(self, relative: str, kind: str, is_host_key: bool) -> Finding:
        """Build the confirmed-private-key finding.

        Args:
            relative: Rootfs-relative POSIX path of the file.
            kind: ``"private"`` or ``"putty"``.
            is_host_key: Whether the file is an SSH host key.

        Returns:
            A single critical finding with a redacted evidence string.
        """
        header = "-----BEGIN ... PRIVATE KEY-----" if kind == "private" else "PuTTY-User-Key-File"
        if is_host_key:
            return self.make_finding(
                title="SSH host key shipped in the firmware image",
                severity=Severity.CRITICAL,
                file_path=relative,
                description=(
                    f"'{relative}' contains a private host key that the device presents when acting "
                    "as an SSH server. If every unit ships the same key, an attacker who extracts "
                    "one device can impersonate any other and defeat host-key verification for "
                    "users connecting to it."
                ),
                mitigation=(
                    "Generate a unique host key per device on first boot (dropbear/OpenSSH "
                    "supported), never bake it into the image, and rotate the key on already "
                    "shipped units."
                ),
                rule_id="FWK-KEY-003",
                evidence=header,
                references=_REFERENCES["creds"],
            )
        return self.make_finding(
            title="Private key material in the firmware image",
            severity=Severity.CRITICAL,
            file_path=relative,
            description=(
                f"'{relative}' contains an unencrypted private key ({header}). Anyone with read "
                "access to the image -- a downloaded update, a dumped flash chip, a support bundle "
                "-- obtains the key and can impersonate the device or decrypt its traffic."
            ),
            mitigation=(
                "Remove the key from the image, revoke and reissue it, and provision per-device "
                "credentials at manufacture or first boot (secure element or TPM where available)."
            ),
            rule_id="FWK-KEY-001",
            evidence=header,
            references=_REFERENCES["creds"],
        )

    def _check_wpa_psk(self, relative: str, head: bytes | None) -> list[Finding]:
        """Detect a plaintext Wi-Fi pre-shared key in a wpa_supplicant config.

        Args:
            relative: Rootfs-relative POSIX path of the configuration file.
            head: Leading bytes of the file, or ``None`` when unreadable.

        Returns:
            Zero or one finding. The key value is never included.
        """
        if not head:
            return []
        text = head.decode("utf-8", errors="replace")
        for raw_line in text.splitlines():
            match = _PSK_RE.match(raw_line)
            if match is None:
                continue
            value = match.group("value").strip()
            if not value or value in {"*", '""', "''"}:
                continue
            return [
                self.make_finding(
                    title="Wi-Fi pre-shared key stored in plaintext",
                    severity=Severity.HIGH,
                    file_path=relative,
                    description=(
                        f"'{relative}' contains a 'psk=' entry, so the Wi-Fi passphrase (or its "
                        f"PSK) is recoverable from the image ({len(value)} characters). It is "
                        "listed here with the value redacted."
                    ),
                    mitigation=(
                        "Provision the PSK per device at manufacture, protect the configuration "
                        "with mode '0600', and avoid shipping a fleet-wide passphrase inside the "
                        "firmware."
                    ),
                    rule_id="FWK-KEY-005",
                    evidence=f"psk=<redacted; {len(value)} chars>",
                    references=_REFERENCES["hardcoded"],
                )
            ]
        return []

    # -- accounts ----------------------------------------------------------

    def _audit_accounts(self, rootfs_path: Path) -> list[Finding]:
        """Audit ``/etc/passwd`` and ``/etc/shadow``.

        Args:
            rootfs_path: Root of the extracted firmware filesystem.

        Returns:
            Zero or more findings, anchored to line numbers where available.
        """
        passwd_text = _read_text_safely(rootfs_path / "etc" / "passwd", MAX_ACCOUNT_FILE_BYTES)
        if passwd_text is None:
            return []

        entries = _parse_passwd(passwd_text)
        shadow_text = _read_text_safely(rootfs_path / "etc" / "shadow", MAX_ACCOUNT_FILE_BYTES)
        shadow_entries = _parse_shadow(shadow_text) if shadow_text is not None else []
        self._stats.accounts_checked = len(entries) + len(shadow_entries)

        findings: list[Finding] = []
        findings.extend(self._audit_passwd(entries))
        findings.extend(self._audit_shadow(shadow_entries))

        if shadow_text is None and any(entry.password == "x" for entry in entries):
            findings.append(
                self.make_finding(
                    title="/etc/shadow is missing",
                    severity=Severity.INFO,
                    file_path="etc/passwd",
                    description=(
                        "'/etc/passwd' delegates password hashes to '/etc/shadow' (field 'x') but "
                        "no shadow file could be read, so password strength and locking state could "
                        "not be verified. In an extracted image this usually means the file was "
                        "excluded or lives on a writable overlay."
                    ),
                    mitigation=(
                        "Confirm whether the shadow database is stored elsewhere (overlay, TPM, "
                        "read-only partition) and re-run the audit against the complete image."
                    ),
                    rule_id="FWK-ACCT-007",
                )
            )

        return findings

    def _audit_passwd(self, entries: Sequence[PasswdEntry]) -> list[Finding]:
        """Apply the ``/etc/passwd`` rules.

        Args:
            entries: Parsed passwd records.

        Returns:
            Zero or more findings.
        """
        findings: list[Finding] = []
        seen_uids: dict[int, str] = {}

        for entry in entries:
            if entry.uid == 0 and entry.name != "root":
                findings.append(
                    self.make_finding(
                        title="Additional UID 0 account",
                        severity=Severity.CRITICAL,
                        file_path="etc/passwd",
                        description=(
                            f"Account '{entry.name}' (line {entry.line}) has UID 0, so it is "
                            "superuser-equivalent. Vendor images use this as a hidden maintenance "
                            "account; it is indistinguishable from a backdoor and survives password "
                            "rotation of 'root'."
                        ),
                        mitigation=(
                            "Remove the account or assign it a non-zero UID, and audit how it is "
                            "created in the build rootfs overlay."
                        ),
                        rule_id="FWK-ACCT-001",
                        line=entry.line,
                        evidence=f"uid=0 user={entry.name}",
                        references=_REFERENCES["passwd"],
                    )
                )

            if entry.password == "":
                findings.append(
                    self.make_finding(
                        title="Account with empty password",
                        severity=Severity.CRITICAL,
                        file_path="etc/passwd",
                        description=(
                            f"Account '{entry.name}' (line {entry.line}) has an empty password "
                            "field, which means no password is required to log in. On a device "
                            "exposing telnet, SSH or a serial console this is unauthenticated root "
                            "access."
                        ),
                        mitigation=(
                            "Set a strong password or lock the account ('*'/'!' in the field), and "
                            "prefer key-based authentication for services that support it."
                        ),
                        rule_id="FWK-ACCT-002",
                        line=entry.line,
                        evidence=f"user={entry.name} password_field=empty",
                        references=_REFERENCES["passwd"],
                    )
                )
            elif entry.password not in LOCKED_MARKERS:
                if _looks_like_hash(entry.password):
                    findings.append(
                        self.make_finding(
                            title="Password hash stored in the world-readable passwd file",
                            severity=Severity.HIGH,
                            file_path="etc/passwd",
                            description=(
                                f"Account '{entry.name}' (line {entry.line}) stores a hash directly "
                                "in '/etc/passwd', which is normally world-readable. The hash is "
                                "therefore exposed to every local user and is crackable offline."
                            ),
                            mitigation=(
                                "Move the hash to '/etc/shadow' ('shadow' field = 'x') and restrict "
                                "the shadow database to 'root:shadow 0640'."
                            ),
                            rule_id="FWK-ACCT-006",
                            line=entry.line,
                            evidence=f"user={entry.name} password_field=hash",
                            references=_REFERENCES["creds"],
                        )
                    )
                else:
                    findings.append(
                        self.make_finding(
                            title="Plaintext password in the passwd file",
                            severity=Severity.CRITICAL,
                            file_path="etc/passwd",
                            description=(
                                f"Account '{entry.name}' (line {entry.line}) has a value that is "
                                "neither a hash nor a shadow reference in the password field, which "
                                "indicates a plaintext or placeholder credential left by the "
                                "provisioning process."
                            ),
                            mitigation=(
                                "Replace the field with 'x' and store a strong hash in "
                                "'/etc/shadow'; rotate the credential immediately."
                            ),
                            rule_id="FWK-ACCT-009",
                            line=entry.line,
                            evidence=(
                                f"user={entry.name} password_field=non-hash "
                                f"(length={len(entry.password)})"
                            ),
                            references=_REFERENCES["creds"],
                        )
                    )

            if 0 < entry.uid < 1000 and _is_interactive_shell(entry.shell):
                findings.append(
                    self.make_finding(
                        title="System account with an interactive shell",
                        severity=Severity.LOW,
                        file_path="etc/passwd",
                        description=(
                            f"Account '{entry.name}' (UID {entry.uid}, line {entry.line}) has login "
                            f"shell '{entry.shell or '<empty>'}'. Service accounts rarely need a "
                            "shell, and each one is an extra credential an attacker can target."
                        ),
                        mitigation=(
                            "Set the shell to '/usr/sbin/nologin' or '/bin/false' for service "
                            "accounts that do not need interactive login."
                        ),
                        rule_id="FWK-ACCT-005",
                        line=entry.line,
                        evidence=f"user={entry.name} uid={entry.uid} shell={entry.shell}",
                        references=_REFERENCES["passwd"],
                    )
                )

            previous = seen_uids.get(entry.uid)
            if previous is not None and entry.uid != 0:
                findings.append(
                    self.make_finding(
                        title="Duplicated UID",
                        severity=Severity.MEDIUM,
                        file_path="etc/passwd",
                        description=(
                            f"Account '{entry.name}' (line {entry.line}) reuses UID {entry.uid}, "
                            f"already assigned to '{previous}'. Both names resolve to the same "
                            "permissions, which breaks audit trails and can hand one service the "
                            "other's file access."
                        ),
                        mitigation=(
                            "Give each account a unique UID; duplicated UIDs are usually a sign of a "
                            "hand-edited passwd file in the build overlay."
                        ),
                        rule_id="FWK-ACCT-008",
                        line=entry.line,
                        evidence=f"uid={entry.uid} users={previous},{entry.name}",
                        references=_REFERENCES["passwd"],
                    )
                )
            else:
                seen_uids.setdefault(entry.uid, entry.name)

        return findings

    def _audit_shadow(self, entries: Sequence[ShadowEntry]) -> list[Finding]:
        """Apply the ``/etc/shadow`` rules.

        Args:
            entries: Parsed shadow records.

        Returns:
            Zero or more findings; the hash itself is never written to a report.
        """
        findings: list[Finding] = []

        for entry in entries:
            severity, label = _classify_hash(entry.password)
            if severity is None:
                continue
            if label == "empty":
                findings.append(
                    self.make_finding(
                        title="Account with no password hash",
                        severity=Severity.CRITICAL,
                        file_path="etc/shadow",
                        description=(
                            f"Account '{entry.name}' (line {entry.line}) has an empty hash field, so "
                            "authentication succeeds with an empty password."
                        ),
                        mitigation=(
                            "Set a strong hash or lock the entry ('!' prefix); for a device, disable "
                            "password login entirely in the SSH/telnet configuration."
                        ),
                        rule_id="FWK-ACCT-003",
                        line=entry.line,
                        evidence=f"user={entry.name} hash=empty",
                        references=_REFERENCES["passwd"],
                    )
                )
                continue

            findings.append(
                self.make_finding(
                    title=f"Weak password hash ({label})",
                    severity=severity,
                    file_path="etc/shadow",
                    description=(
                        f"Account '{entry.name}' (line {entry.line}) uses {label}. "
                        + (
                            "DES crypt truncates to 8 characters and is brute-forceable in minutes."
                            if label == "DES crypt"
                            else "This is below the current baseline; an extracted hash can be "
                            "cracked offline with commodity hardware."
                            if severity in {Severity.HIGH, Severity.MEDIUM}
                            else "SHA-256 is acceptable but SHA-512/yescrypt is preferred."
                        )
                    ),
                    mitigation=(
                        "Re-hash with SHA-512 ('$6$') or yescrypt, and force a password change for "
                        "accounts whose old hash was shipped in a firmware image."
                    ),
                    rule_id="FWK-ACCT-004",
                    line=entry.line,
                    evidence=f"user={entry.name} hash_format={label}",
                    references=_REFERENCES["passwd"],
                )
            )

        return findings


def _redacted_ssh_evidence(head: bytes) -> str:
    """Summarise an ``authorized_keys`` file without exposing key material.

    Args:
        head: Leading bytes of the file.

    Returns:
        A short description such as ``"2 key line(s); first_type=ssh-ed25519"``.
    """
    text = head.decode("utf-8", errors="replace")
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        return "no key lines"
    first_type = lines[0].split()[0] if lines[0].split() else "unknown"
    return f"{len(lines)} key line(s); first_type={first_type}"
