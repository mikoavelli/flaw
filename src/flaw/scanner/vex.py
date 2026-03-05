"""OpenVEX parser for Vulnerability Exploitability eXchange (VEX) documents."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from flaw.models import VexJustification, VexStatement, VexStatus

logger = logging.getLogger("flaw")


def parse_openvex(paths: list[Path] | None) -> list[VexStatement]:
    """Parse multiple OpenVEX JSON documents into internal models."""
    if not paths:
        return []

    statements: list[VexStatement] = []

    for path in paths:
        if not path.is_file():
            logger.warning("VEX document not found: %s", path)
            continue

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            stmts_raw = data.get("statements", [])

            for stmt in stmts_raw:
                vuln_id = stmt.get("vulnerability", "")
                status_raw = stmt.get("status")
                justification_raw = stmt.get("justification")
                impact = stmt.get("impact_statement", "")
                products = stmt.get("products", [])

                try:
                    status = VexStatus(status_raw)
                except ValueError:
                    continue

                justification = None
                if justification_raw:
                    try:
                        justification = VexJustification(justification_raw)
                    except ValueError:
                        pass

                if not products:
                    statements.append(
                        VexStatement(
                            cve_id=vuln_id,
                            status=status,
                            justification=justification,
                            impact_statement=impact,
                        )
                    )
                else:
                    for p in products:
                        purl = p.get("@id", p) if isinstance(p, dict) else str(p)
                        statements.append(
                            VexStatement(
                                cve_id=vuln_id,
                                status=status,
                                justification=justification,
                                impact_statement=impact,
                                purl=purl,
                            )
                        )

            logger.debug("Parsed %d VEX statements from %s", len(stmts_raw), path.name)

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to parse VEX document %s: %s", path, e)

    return statements
