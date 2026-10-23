"""Static ELF hardening auditor (NX, PIE, stack canaries, RELRO, W^X).

The analyzer walks an extracted rootfs, recognises ELF images by magic rather
than by permission bit (permissions are routinely destroyed by tar/zip round
trips), and inspects each one **without ever executing it**.

Checks implemented
------------------
===========================  ==========  =====================================
Rule                         Severity    Detection
===========================  ==========  =====================================
``FWK-NX-001``               high        ``PT_GNU_STACK`` absent or carrying
                                         ``PF_X``
``FWK-PIE-001``              medium      ``ET_EXEC``, or ``ET_DYN`` without
                                         ``PT_PHDR``
``FWK-PIE-002``              info        ELF type that cannot be classified
``FWK-CANARY-001``           medium      no ``__stack_chk_fail`` /
                                         ``__stack_chk_guard`` reference
``FWK-RELRO-001``            medium      ``PT_GNU_RELRO`` absent
``FWK-RELRO-002``            low         RELRO mapped but lazy binding enabled
``FWK-RELRO-003``            info        dynamic table unreadable (inconclusive)
``FWK-WX-001``               high        a ``PT_LOAD`` segment is writable
                                         *and* executable
===========================  ==========  =====================================

A rule that cannot be evaluated yields an ``info`` "could not be determined"
finding rather than a silent pass: an operator reading a clean report must be
able to tell "verified good" from "never checked".

Only ``pyelftools`` is used for parsing; the single deliberate exception is the
canary check, which falls back to a bounded byte scan when a binary has no
symbol table at all (stripped firmware images are the norm). That fallback is
recorded in the finding evidence so an analyst can tell the two apart.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Final, Iterator

from analyzers.base import (
    AnalyzerConfig,
    AnalyzerError,
    BaseAnalyzer,
    Finding,
    Severity,
    TraversalStats,
    is_elf,
    relative_posix,
    walk_files,
)

__all__ = ["ElfFacts", "BinaryHardeningAnalyzer", "BinaryHardeningStats"]


# ---------------------------------------------------------------------------
# ELF constants
#
# Defined locally (rather than imported from ``elftools.elf.constants``) so the
# analyzer keeps working across pyelftools releases that reorganise or deprecate
# helper modules. Values come from the System V gABI and the Linux extensions.
# ---------------------------------------------------------------------------

PF_X: Final[int] = 0x1
PF_W: Final[int] = 0x2

ET_REL: Final[int] = 1
ET_EXEC: Final[int] = 2
ET_DYN: Final[int] = 3
ET_CORE: Final[int] = 4

#: ``e_type`` values that are never executable images and must be skipped.
NON_EXECUTABLE_TYPES: Final[frozenset[int]] = frozenset({0, ET_REL, ET_CORE})

#: ``DF_BIND_NOW`` (``DT_FLAGS``) and ``DF_1_NOW`` (``DT_FLAGS_1``): the two
#: bit-flag ways a linker records full RELRO, besides a bare ``DT_BIND_NOW``.
DF_BIND_NOW: Final[int] = 0x8
DF_1_NOW: Final[int] = 0x1

#: Numeric ``e_type`` values, used to normalise decoders that hand back enum
#: *names* (pyelftools) instead of raw integers.
_ETYPE_BY_NUMBER: Final[dict[int, str]] = {
    0: "ET_NONE",
    ET_REL: "ET_REL",
    ET_EXEC: "ET_EXEC",
    ET_DYN: "ET_DYN",
    ET_CORE: "ET_CORE",
}

#: Friendly architecture labels keyed by the ``EM_*`` names pyelftools emits.
_MACHINE_LABELS: Final[dict[str, str]] = {
    "EM_386": "x86",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64",
    "EM_S390": "S390",
    "EM_ARM": "ARM",
    "EM_X86_64": "x86_64",
    "EM_AARCH64": "AArch64",
    "EM_RISCV": "RISC-V",
    "EM_SH": "SuperH",
    "EM_SPARC": "SPARC",
    "EM_MSP430": "MSP430",
    "EM_XTENSA": "Xtensa",
    "EM_AVR": "AVR",
}


def _normalize_e_type(value: object) -> int:
    """Normalise an ``e_type`` header field to its numeric value.

    pyelftools decodes ``e_type`` through an enum, so ``header["e_type"]`` is a
    *string* such as ``"ET_DYN"`` -- not the integer the gABI defines. Other
    decoders and raw struct reads do return integers. Both are accepted here,
    which keeps the analyzer portable across pyelftools releases and makes the
    comparison logic explicit instead of relying on either behaviour.

    Args:
        value: The raw ``e_type`` value (``str``, ``int`` or anything else).

    Returns:
        The numeric ELF type, or ``-1`` when it cannot be determined.
    """
    if isinstance(value, bool):  # bool is an int subclass; never a valid type
        return -1
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        for number, name in _ETYPE_BY_NUMBER.items():
            if name == value:
                return number
        try:
            return int(value, 0)
        except ValueError:
            return -1
    return -1


def _normalize_machine(value: object) -> str:
    """Normalise an ``e_machine`` header field to its ``EM_*`` name.

    pyelftools returns ``"EM_X86_64"``; a raw struct read returns ``62``. Keeping
    the symbolic name (rather than only a number) means an unknown architecture
    is still reported verbatim instead of being flattened to ``0``.

    Args:
        value: The raw ``e_machine`` value.

    Returns:
        The ``EM_*`` name when known, the decimal spelling for unknown numeric
        values, or ``"unknown"``.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return f"EM_{value}"
    return "unknown"

#: Symbol names that prove a binary was built with ``-fstack-protector``.
CANARY_SYMBOLS: Final[tuple[str, ...]] = (
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__stack_chk_guard",
    "__stack_smash_handler",
)

#: Byte patterns used when no symbol table exists (stripped binaries).
CANARY_BYTE_PATTERNS: Final[tuple[bytes, ...]] = (
    b"__stack_chk_fail",
    b"__stack_chk_guard",
    b"__stack_smash_handler",
)

#: Upper bound for the byte-scan canary fallback. Firmware binaries are
#: normally a few hundred kilobytes; the cap exists so that a bundled data blob
#: cannot turn a static audit into a multi-gigabyte read. Files above the cap
#: are reported as "canary unknown", never as "canary absent".
MAX_SCAN_BYTES: Final[int] = 16 * 1024 * 1024

_REFERENCES: Final[dict[str, tuple[str, ...]]] = {
    "nx": ("https://wiki.gentoo.org/wiki/Hardened/Toolchain",),
    "pie": ("https://wiki.gentoo.org/wiki/Hardened/PIE",),
    "canary": ("https://wiki.osdev.org/Stack_Smashing_Protector",),
    "relro": ("https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro",),
    "wx": ("https://en.wikipedia.org/wiki/W%5EX",),
}


# ---------------------------------------------------------------------------
# Parsed facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ElfFacts:
    """Raw hardening facts extracted from one ELF image.

    ``None`` is used instead of ``False`` whenever a property could not be
    determined (e.g. a truncated file), so that "unknown" is never silently
    reported as a vulnerability.

    Attributes:
        e_type: Numeric ELF type (``ET_EXEC``, ``ET_DYN``, ...).
        e_type_name: Symbolic ELF type as reported by the decoder, kept for the
            report so an unexpected value is never silently normalised away.
        machine: Symbolic machine name (``EM_X86_64``, ...).
        is_shared_object: Heuristic classification of the image.
        has_gnu_stack: Whether a ``PT_GNU_STACK`` header is present.
        nx_enabled: ``False`` when the stack is executable.
        pie: ``True`` for ``ET_DYN`` images carrying ``PT_PHDR``.
        relro: ``"full"``, ``"partial"``, ``"none"`` or ``"unknown"``.
        canary: Whether a stack protector symbol/pattern was found.
        canary_source: ``"symbol"``, ``"string"`` or ``"none"``.
        wx_segments: Number of writable+executable ``PT_LOAD`` segments.
        segment_count: Total program headers, for context in reports.
    """

    e_type: int
    e_type_name: str
    machine: str
    is_shared_object: bool
    has_gnu_stack: bool
    nx_enabled: bool | None
    pie: bool | None
    relro: str
    canary: bool | None
    canary_source: str
    wx_segments: int
    segment_count: int


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BinaryHardeningStats:
    """Counters describing one :meth:`BinaryHardeningAnalyzer.run` pass.

    Reported by the pipeline alongside the findings so an operator can tell
    "no binaries found" apart from "binaries found but unparsable" -- a
    distinction that matters when triaging a suspiciously clean report.

    Attributes:
        binaries: ELF images successfully identified by magic.
        shared_objects: How many of those were classified as libraries.
        files_skipped: Regular files rejected by the size pre-filter.
        unreadable: Rootfs-relative paths of images that failed to parse.
        findings: Number of findings emitted by the pass.
        traversal: Filesystem traversal coverage metadata.
    """

    binaries: int = 0
    shared_objects: int = 0
    files_skipped: int = 0
    unreadable: list[str] = field(default_factory=list)
    findings: int = 0
    traversal: TraversalStats = field(default_factory=TraversalStats)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable summary of the counters."""
        return {
            "binaries": self.binaries,
            "shared_objects": self.shared_objects,
            "files_skipped": self.files_skipped,
            "unreadable_count": len(self.unreadable),
            "unreadable": list(self.unreadable),
            "findings": self.findings,
            **self.traversal.as_dict(),
        }


class BinaryHardeningAnalyzer(BaseAnalyzer):
    """Audit ELF binaries for missing exploit mitigations.

    The analyzer is read-only: it maps headers, the dynamic table and the symbol
    tables, and closes the file handle immediately. Corrupt or truncated ELF
    images are skipped (and counted) instead of aborting the scan, because
    firmware dumps reliably contain a few truncated files.
    """

    description = "Audits ELF binaries for missing NX, PIE, RELRO, stack canaries and W^X violations."
    version = "1.0.0"

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        super().__init__(config)
        self._stats = BinaryHardeningStats()

    @property
    def name(self) -> str:
        """Analyzer identifier used by ``--analyzers`` and the reports."""
        return "binary_hardening"

    @property
    def stats(self) -> "BinaryHardeningStats":
        """Counters for the most recent :meth:`run` invocation."""
        return self._stats

    # -- public API --------------------------------------------------------

    def run(self, rootfs_path: Path) -> list[Finding]:
        """Scan every ELF regular file under ``rootfs_path``.

        Non-ELF files are rejected by a four-byte magic read, so the walk stays
        cheap on data-heavy images. Images that fail to parse (truncated,
        partially flashed, non-native endianness) are appended to
        :attr:`stats` rather than raising, because a firmware dump reliably
        contains a few unreadable files and losing the other findings would be
        worse than reporting a partial picture.

        Args:
            rootfs_path: Root of the extracted firmware filesystem.

        Returns:
            One finding per failed control, per binary.
        """
        self._stats = BinaryHardeningStats()
        findings: list[Finding] = []

        for path, st in walk_files(rootfs_path, self.config, self._stats.traversal):
            if not self._is_candidate(st):
                self._stats.files_skipped += 1
                continue
            if not is_elf(path):
                continue
            self._stats.binaries += 1
            relative = relative_posix(rootfs_path, path)
            facts = self._inspect(path)
            if facts is None:
                self._stats.unreadable.append(relative)
                continue
            if facts.is_shared_object:
                self._stats.shared_objects += 1
            findings.extend(self._evaluate(relative, facts))

        self._stats.findings = len(findings)
        return findings

    # -- discovery ---------------------------------------------------------

    def _is_candidate(self, st: os.stat_result) -> bool:
        """Decide from metadata alone whether a file is worth opening.

        The executable bit is deliberately **not** required: permissions are
        routinely flattened to ``0644`` when a rootfs travels through
        ``squashfs -> tar -> zip``, so requiring ``+x`` would silently skip most
        of the image. Size is the only metadata filter that matters.

        Args:
            st: ``lstat`` result of the candidate.

        Returns:
            ``True`` when the file is a regular file of plausible ELF size.
        """
        if not stat.S_ISREG(st.st_mode):
            return False
        # 64 bytes is the smallest structurally possible ELF64 file.
        if st.st_size < 64:
            return False
        return st.st_size <= self.config.max_file_bytes

    # -- parsing -----------------------------------------------------------

    def _inspect(self, path: Path) -> ElfFacts | None:
        """Parse one ELF image into :class:`ElfFacts`.

        Args:
            path: ELF file to parse.

        Returns:
            The extracted facts, or ``None`` when the image cannot be parsed.
        """
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise AnalyzerError(
                self.name,
                "pyelftools is not installed; run 'pip install pyelftools'",
            ) from exc

        try:
            with path.open("rb") as handle:
                elf = ELFFile(handle)  # type: ignore[no-untyped-call]
                return self._extract(elf, handle, path)
        except Exception:
            # ELFError, ConstructError, struct.error, OSError, ValueError:
            # all mean "this image is not analysable", never "no findings".
            return None

    def _extract(self, elf: object, handle: IO[bytes], path: Path) -> ElfFacts:
        """Derive :class:`ElfFacts` from an already opened :class:`ELFFile`.

        Args:
            elf: An ``elftools`` ``ELFFile`` instance.
            handle: The underlying binary file object (needed for the byte scan).
            path: Path of the image, used for the shared-object heuristic.

        Returns:
            Populated facts.

        Raises:
            ValueError: If the image is not an executable object (relocatable or
                core dump), so the caller skips it.
        """
        header = elf.header  # type: ignore[attr-defined]
        raw_e_type = header["e_type"]
        e_type = _normalize_e_type(raw_e_type)
        e_type_name = _ETYPE_BY_NUMBER.get(e_type, str(raw_e_type))
        machine = _normalize_machine(header["e_machine"])
        if e_type in NON_EXECUTABLE_TYPES:
            raise ValueError(f"not an executable image (e_type={e_type_name})")

        segments = list(elf.iter_segments())  # type: ignore[attr-defined]
        types = [seg["p_type"] for seg in segments]

        has_gnu_stack = "PT_GNU_STACK" in types
        has_phdr = "PT_PHDR" in types
        has_interp = "PT_INTERP" in types
        has_relro = "PT_GNU_RELRO" in types

        nx_enabled: bool | None
        if has_gnu_stack:
            stack_seg = next(s for s in segments if s["p_type"] == "PT_GNU_STACK")
            nx_enabled = not bool(int(stack_seg["p_flags"]) & PF_X)
        else:
            # Absent PT_GNU_STACK is the historical "executable stack" default
            # on x86/x86_64 and is still treated as such by the kernel for
            # legacy images.
            nx_enabled = False

        wx_segments = 0
        has_exec_load = False
        for seg in segments:
            if seg["p_type"] != "PT_LOAD":
                continue
            flags = int(seg["p_flags"])
            if flags & PF_X:
                has_exec_load = True
            if (flags & PF_W) and (flags & PF_X):
                wx_segments += 1
        if not has_exec_load:
            raise ValueError("no executable PT_LOAD segment")

        is_shared_object = self._is_shared_object(
            elf=elf, e_type=e_type, has_interp=has_interp, path=path
        )

        if e_type == ET_EXEC:
            pie: bool | None = False
        elif e_type == ET_DYN:
            # Full PIE requires the PHDR to be mapped by the dynamic loader, so
            # the kernel can apply the randomised load bias to the headers too.
            pie = bool(has_phdr)
        else:  # pragma: no cover - exotic types are rejected above
            pie = None

        relro = self._relro_state(elf, has_relro=has_relro, has_dynamic="PT_DYNAMIC" in types)
        canary, canary_source = self._canary_state(elf, handle)

        return ElfFacts(
            e_type=e_type,
            e_type_name=e_type_name,
            machine=machine,
            is_shared_object=is_shared_object,
            has_gnu_stack=has_gnu_stack,
            nx_enabled=nx_enabled,
            pie=pie,
            relro=relro,
            canary=canary,
            canary_source=canary_source,
            wx_segments=wx_segments,
            segment_count=len(segments),
        )

    def _is_shared_object(self, *, elf: object, e_type: int, has_interp: bool, path: Path) -> bool:
        """Decide whether the image is a shared library rather than a program.

        PIE executables are also ``ET_DYN``, so the type alone proves nothing.
        A program has ``PT_INTERP`` (dynamically linked) or no ``DT_SONAME`` and
        a non-``lib*.so*`` name (static-PIE). Everything else is treated as a
        library, whose PIE status is meaningless.

        Args:
            elf: The ``ELFFile`` instance.
            e_type: Numeric ELF type.
            has_interp: Whether ``PT_INTERP`` is present.
            path: Image path, used as a last-resort name heuristic.

        Returns:
            ``True`` when the image is a shared object.
        """
        if e_type != ET_DYN:
            return False
        if has_interp:
            return False
        tags = self._dynamic_tags(elf)
        if tags is not None and any(tag_name == "DT_SONAME" for tag_name, _ in tags):
            return True
        lowered = path.name.lower()
        return lowered.endswith(".so") or ".so." in lowered

    @staticmethod
    def _dynamic_tags(elf: object) -> list[tuple[str, int]] | None:
        """Return ``(tag_name, value)`` pairs from the dynamic table.

        The section header table is authoritative and cheap, but fully stripped
        images (``strip --strip-all`` is common on embedded targets) may keep
        only program headers, so ``PT_DYNAMIC`` is used as a fallback. ``None``
        signals "no readable dynamic table", which the caller reports as
        inconclusive instead of guessing a verdict.

        Args:
            elf: The ``ELFFile`` instance.

        Returns:
            The decoded tags, or ``None`` when the table is unavailable.
        """
        candidates: list[object] = []
        try:
            section = elf.get_section_by_name(".dynamic")  # type: ignore[attr-defined]
        except Exception:
            section = None
        if section is not None:
            candidates.append(section)
        else:
            try:
                for segment in elf.iter_segments():  # type: ignore[attr-defined]
                    if segment["p_type"] == "PT_DYNAMIC" and hasattr(segment, "iter_tags"):
                        candidates.append(segment)
            except Exception:
                return None

        for source in candidates:
            tags: list[tuple[str, int]] = []
            try:
                for tag in source.iter_tags():  # type: ignore[attr-defined]
                    tags.append((str(tag.entry.d_tag), int(tag.entry.d_val)))
            except Exception:  # pragma: no cover - corrupt table
                continue
            if tags:
                return tags
        return None

    def _relro_state(self, elf: object, *, has_relro: bool, has_dynamic: bool) -> str:
        """Classify RELRO as ``full``, ``partial``, ``none`` or ``unknown``.

        ``PT_GNU_RELRO`` alone only remaps ``.got`` read-only; ``BIND_NOW``
        (``-Wl,-z,now``) is what makes it *full* by resolving PLT entries at
        load time instead of lazily.

        Args:
            elf: The ``ELFFile`` instance.
            has_relro: Whether ``PT_GNU_RELRO`` is present.
            has_dynamic: Whether ``PT_DYNAMIC`` is present.

        Returns:
            The RELRO classification.
        """
        if not has_relro:
            return "none"
        if not has_dynamic:
            # Fully static image: there is no lazy binding to protect.
            return "full"

        tags = self._dynamic_tags(elf)
        if tags is None:
            return "unknown"
        for tag_name, value in tags:
            if tag_name == "DT_BIND_NOW":
                return "full"
            if tag_name == "DT_FLAGS" and value & DF_BIND_NOW:
                return "full"
            if tag_name == "DT_FLAGS_1" and value & DF_1_NOW:
                return "full"

        # No PLT relocation at all means nothing to lazy-bind: also full.
        # When the relocation sections are unavailable (stripped), absence
        # cannot be proven, so the conservative "partial" verdict is kept.
        try:
            reloc = elf.get_section_by_name(".rel.plt")  # type: ignore[attr-defined]
            if reloc is None or reloc.num_relocations() == 0:  # type: ignore[attr-defined]
                return "full"
        except Exception:
            pass
        return "partial"

    @staticmethod
    def _iter_symbol_names(elf: object) -> Iterator[str]:
        """Yield symbol names from every symbol table available.

        Args:
            elf: The ``ELFFile`` instance.

        Yields:
            Symbol names, in section order.
        """
        for section_name in (".dynsym", ".symtab"):
            section = elf.get_section_by_name(section_name)  # type: ignore[attr-defined]
            if section is None or not hasattr(section, "iter_symbols"):
                continue
            try:
                for symbol in section.iter_symbols():
                    yield symbol.name
            except Exception:  # pragma: no cover - corrupt table
                continue

    def _canary_state(self, elf: object, handle: IO[bytes]) -> tuple[bool | None, str]:
        """Detect stack protector instrumentation.

        Symbol lookup is authoritative and runs first. When the image carries no
        symbol table (stripped firmware builds), a bounded byte scan provides
        weaker but actionable evidence.

        Args:
            elf: The ``ELFFile`` instance.
            handle: Underlying file object for the fallback scan.

        Returns:
            ``(canary_detected, source)`` where source is ``"symbol"``,
            ``"string"``, or ``"none"``.
        """
        wanted = set(CANARY_SYMBOLS)
        for symbol_name in self._iter_symbol_names(elf):
            if symbol_name in wanted:
                return True, "symbol"

        # Fallback path: the image has no symbol table at all (stripped
        # firmware build). The scan must cover the *whole* file, otherwise a
        # negative verdict would be unsupportable -- so an oversized file
        # yields "unknown" rather than a false "no canary" finding.
        try:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(0)
            if size > MAX_SCAN_BYTES:
                return None, "none"
            blob = handle.read(MAX_SCAN_BYTES)
        except OSError:  # pragma: no cover - I/O failure
            return None, "none"
        for pattern in CANARY_BYTE_PATTERNS:
            if pattern in blob:
                return True, "string"
        return False, "none"

    # -- rule evaluation ---------------------------------------------------

    def _evaluate(self, relative: str, facts: ElfFacts) -> list[Finding]:
        """Translate facts into findings.

        Args:
            relative: Rootfs-relative path of the image.
            facts: Parsed hardening facts.

        Returns:
            The findings for this image (possibly empty).
        """
        findings: list[Finding] = []
        arch = self._arch_label(facts.machine)
        kind = "shared library" if facts.is_shared_object else "executable"

        if facts.nx_enabled is not True:
            findings.append(
                self.make_finding(
                    title="Executable stack (NX disabled)",
                    severity=Severity.HIGH,
                    file_path=relative,
                    description=(
                        f"{kind.capitalize()} {relative} ({arch}) does not request a non-executable "
                        "stack: "
                        + ("PT_GNU_STACK is absent" if not facts.has_gnu_stack else "PT_GNU_STACK carries PF_X")
                        + ", so the kernel maps the stack with PROT_EXEC. A stack buffer overflow "
                        "can therefore jump straight into injected shellcode instead of needing a "
                        "ROP chain."
                    ),
                    mitigation=(
                        "Rebuild with '-Wl,-z,noexecstack' (or the toolchain equivalent) and verify "
                        "with 'readelf -l <binary> | grep GNU_STACK' that the flags are 'RW' and not "
                        "'RWE'."
                    ),
                    rule_id="FWK-NX-001",
                    evidence=f"PT_GNU_STACK present={facts.has_gnu_stack}",
                    references=_REFERENCES["nx"],
                )
            )

        if not facts.is_shared_object and facts.pie is False:
            findings.append(
                self.make_finding(
                    title="Binary is not position-independent (no PIE)",
                    severity=Severity.MEDIUM,
                    file_path=relative,
                    description=(
                        f"{relative} is an ET_EXEC image ({arch}). Without PIE the kernel loads it "
                        "at a fixed address, so ASLR cannot randomise the code and ROP gadgets have "
                        "predictable locations."
                    ),
                    mitigation=(
                        "Rebuild with '-fPIE -pie' (and '-static-pie' for static binaries). On "
                        "architectures where the vendor toolchain lacks PIE support, document the "
                        "exception and compensate with RELRO, stack canaries and seccomp."
                    ),
                    rule_id="FWK-PIE-001",
                    evidence=f"e_type={facts.e_type_name}",
                    references=_REFERENCES["pie"],
                )
            )
        elif not facts.is_shared_object and facts.pie is None:
            findings.append(
                self.make_finding(
                    title="PIE status could not be determined",
                    severity=Severity.INFO,
                    file_path=relative,
                    description=(
                        f"The ELF type of {relative} is not one the analyzer can classify for PIE "
                        "purposes; position independence could not be verified."
                    ),
                    mitigation="Inspect the image manually with 'readelf -h' and 'readelf -l'.",
                    rule_id="FWK-PIE-002",
                    evidence=f"e_type={facts.e_type_name}",
                )
            )

        if facts.relro == "none":
            findings.append(
                self.make_finding(
                    title="No RELRO protection",
                    severity=Severity.MEDIUM,
                    file_path=relative,
                    description=(
                        f"{relative} has no PT_GNU_RELRO segment, so the relocation tables and GOT "
                        "stay writable after load. An arbitrary-write primitive can overwrite a GOT "
                        "entry and redirect execution."
                    ),
                    mitigation=(
                        "Link with '-Wl,-z,relro,-z,now' to obtain full RELRO and confirm with "
                        "'readelf -l <binary> | grep GNU_RELRO' plus 'readelf -d <binary> | grep NOW'."
                    ),
                    rule_id="FWK-RELRO-001",
                    evidence="PT_GNU_RELRO absent",
                    references=_REFERENCES["relro"],
                )
            )
        elif facts.relro == "partial":
            findings.append(
                self.make_finding(
                    title="Partial RELRO (lazy binding enabled)",
                    severity=Severity.LOW,
                    file_path=relative,
                    description=(
                        f"{relative} maps PT_GNU_RELRO but was linked without BIND_NOW, so .got.plt "
                        "entries are resolved lazily and remain writable, keeping GOT-overwrite "
                        "techniques viable."
                    ),
                    mitigation="Add '-Wl,-z,now' (full RELRO) to the linker flags and rebuild.",
                    rule_id="FWK-RELRO-002",
                    evidence="PT_GNU_RELRO present, DT_BIND_NOW absent",
                    references=_REFERENCES["relro"],
                )
            )
        elif facts.relro == "unknown":
            findings.append(
                self.make_finding(
                    title="RELRO status could not be determined",
                    severity=Severity.INFO,
                    file_path=relative,
                    description=(
                        f"The dynamic section of {relative} could not be parsed, so RELRO could not "
                        "be classified; this is inconclusive rather than a confirmed weakness."
                    ),
                    mitigation="Inspect the image manually with 'readelf -l' and 'readelf -d'.",
                    rule_id="FWK-RELRO-003",
                )
            )

        if facts.canary is False:
            findings.append(
                self.make_finding(
                    title="No stack canary detected",
                    severity=Severity.MEDIUM,
                    file_path=relative,
                    description=(
                        f"{relative} shows no reference to __stack_chk_fail/__stack_chk_guard, which "
                        "means it was built without '-fstack-protector'. Stack overflows in this "
                        "binary corrupt the return address without detection."
                    ),
                    mitigation=(
                        "Rebuild with '-fstack-protector-strong' (or '-fstack-protector-all' for "
                        "privileged daemons) and keep the SSP runtime available in the image."
                    ),
                    rule_id="FWK-CANARY-001",
                    evidence=f"canary_source={facts.canary_source}",
                    references=_REFERENCES["canary"],
                )
            )

        if facts.wx_segments:
            findings.append(
                self.make_finding(
                    title="Writable and executable segment (W^X violation)",
                    severity=Severity.HIGH,
                    file_path=relative,
                    description=(
                        f"{relative} maps {facts.wx_segments} PT_LOAD segment(s) with both PF_W and "
                        "PF_X. Any write primitive inside that mapping becomes direct code execution, "
                        "defeating NX."
                    ),
                    mitigation=(
                        "Split the offending section or correct its linker script so data and code "
                        "live in separate segments; verify with 'readelf -l <binary>' that no LOAD "
                        "segment is 'RWE'."
                    ),
                    rule_id="FWK-WX-001",
                    evidence=f"rwx_segment_count={facts.wx_segments}",
                    references=_REFERENCES["wx"],
                )
            )

        return findings

    @staticmethod
    def _arch_label(machine: str) -> str:
        """Return a human-readable architecture label.

        Args:
            machine: Symbolic ``EM_*`` machine name as decoded from the header.

        Returns:
            A short architecture name, or the raw ``EM_*`` value when the
            architecture is not in the label table -- reporting the real name
            beats collapsing an exotic MIPS variant into a generic string.
        """
        return _MACHINE_LABELS.get(machine, machine or "unknown")
