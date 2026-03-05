"""Tests for OpenVEX document parsing."""

from __future__ import annotations

import json
from pathlib import Path

from flaw.models import VexJustification, VexStatus
from flaw.scanner.vex import parse_openvex


class TestVexParser:
    def test_parse_valid_vex(self, tmp_path: Path) -> None:
        vex_file = tmp_path / "valid.vex.json"
        vex_data = {
            "statements": [
                {
                    "vulnerability": "CVE-2023-44487",
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_in_execute_path",
                    "impact_statement": "HTTP/2 is disabled in config.",
                }
            ]
        }
        vex_file.write_text(json.dumps(vex_data))

        statements = parse_openvex([vex_file])
        assert len(statements) == 1
        assert statements[0].cve_id == "CVE-2023-44487"
        assert statements[0].status == VexStatus.NOT_AFFECTED
        assert statements[0].justification == VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        assert statements[0].impact_statement == "HTTP/2 is disabled in config."
        assert statements[0].purl is None

    def test_parse_with_purls(self, tmp_path: Path) -> None:
        vex_file = tmp_path / "purl.vex.json"
        vex_data = {
            "statements": [
                {
                    "vulnerability": "CVE-2021-44228",
                    "status": "fixed",
                    "products": ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
                }
            ]
        }
        vex_file.write_text(json.dumps(vex_data))

        statements = parse_openvex([vex_file])
        assert len(statements) == 1
        assert statements[0].purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    def test_missing_file_handled_gracefully(self, tmp_path: Path) -> None:
        missing_file = tmp_path / "does_not_exist.json"
        statements = parse_openvex([missing_file])
        assert statements == []

    def test_invalid_json_handled_gracefully(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ broken json")
        statements = parse_openvex([bad_file])
        assert statements == []

    def test_invalid_status_ignored(self, tmp_path: Path) -> None:
        vex_file = tmp_path / "invalid_status.json"
        vex_data = {"statements": [{"vulnerability": "CVE-1", "status": "fake_status"}]}
        vex_file.write_text(json.dumps(vex_data))
        statements = parse_openvex([vex_file])
        assert statements == []

    def test_invalid_justification_ignored(self, tmp_path: Path) -> None:
        vex_file = tmp_path / "bad_just.json"
        vex_data = {
            "statements": [
                {
                    "vulnerability": "CVE-1",
                    "status": "not_affected",
                    "justification": "some_random_string_not_in_enum",
                }
            ]
        }
        vex_file.write_text(json.dumps(vex_data))
        statements = parse_openvex([vex_file])

        assert len(statements) == 1
        assert statements[0].cve_id == "CVE-1"
        assert statements[0].status == VexStatus.NOT_AFFECTED
        assert statements[0].justification is None
