from __future__ import annotations

import json
from pathlib import Path

from analyzers import build_analyzers
from core.pipeline import Pipeline
from core.reporter import Reporter


def test_json_output_contains_scan_envelope(rootfs: Path) -> None:
    result = Pipeline(build_analyzers(["filesystem_hygiene"])).run(rootfs)
    payload = json.loads(Reporter().to_json(result))

    assert payload["tool"]["name"] == "firmware-auditor"
    assert payload["scan"]["complete"] is True
    assert payload["summary"]["total"] == 0
    assert payload["findings"] == []


def test_sarif_2_1_structure_with_finding(rootfs: Path) -> None:
    etc = rootfs / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root::0:0:root:/root:/bin/sh\n", encoding="utf-8")
    result = Pipeline(build_analyzers(["filesystem_hygiene"])).run(rootfs)
    sarif = Reporter().to_sarif(result)

    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "firmware-auditor"
    assert run["tool"]["driver"]["rules"]
    assert run["results"]
    result_item = run["results"][0]
    assert result_item["ruleId"]
    assert result_item["ruleIndex"] >= 0
    assert result_item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert result_item["partialFingerprints"]
    assert run["invocations"][0]["executionSuccessful"] is True

