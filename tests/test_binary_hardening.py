from __future__ import annotations

from pathlib import Path

from analyzers.binary_hardening import BinaryHardeningAnalyzer, ElfFacts


def facts(**overrides: object) -> ElfFacts:
    values: dict[str, object] = {
        "e_type": 3,
        "e_type_name": "ET_DYN",
        "machine": "EM_X86_64",
        "is_shared_object": False,
        "has_gnu_stack": True,
        "nx_enabled": True,
        "pie": True,
        "relro": "full",
        "canary": True,
        "canary_source": "symbol",
        "wx_segments": 0,
        "segment_count": 4,
    }
    values.update(overrides)
    return ElfFacts(**values)


def rule_ids(analyzer: BinaryHardeningAnalyzer, value: ElfFacts) -> set[str]:
    return {finding.rule_id for finding in analyzer._evaluate("bin/app", value)}


def test_nx_and_pie_findings() -> None:
    analyzer = BinaryHardeningAnalyzer()
    ids = rule_ids(analyzer, facts(nx_enabled=False, pie=False))
    assert {"FWK-NX-001", "FWK-PIE-001"} <= ids


def test_relro_findings() -> None:
    analyzer = BinaryHardeningAnalyzer()
    assert "FWK-RELRO-001" in rule_ids(analyzer, facts(relro="none"))
    assert "FWK-RELRO-002" in rule_ids(analyzer, facts(relro="partial"))


def test_canary_finding_and_duck_typed_symbol_detection() -> None:
    analyzer = BinaryHardeningAnalyzer()
    assert "FWK-CANARY-001" in rule_ids(analyzer, facts(canary=False, canary_source="none"))

    class Symbol:
        name = "__stack_chk_fail"

    class Section:
        def iter_symbols(self):
            return iter([Symbol()])

    class Elf:
        def get_section_by_name(self, name: str):
            return Section() if name == ".dynsym" else None

    detected, source = analyzer._canary_state(Elf(), __import__("io").BytesIO(b""))
    assert detected is True
    assert source == "symbol"


def test_hardened_facts_produce_no_findings() -> None:
    assert BinaryHardeningAnalyzer()._evaluate("bin/app", facts()) == []

