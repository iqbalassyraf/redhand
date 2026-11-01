"""
RedHand SDK - SARIF (OASIS Static Analysis Results Interchange Format) v2.1.0 Exporter
File: packages/redhand-sdk/src/redhand_sdk/scanner/sarif.py

Formats RedHand static scan findings for GitHub Advanced Security and GitLab CI/CD.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redhand_sdk.scanner.ast_checker import ScanFinding


def export_sarif_v2(findings: list[ScanFinding], output_path: str | Path | None = None) -> dict[str, Any]:
    """Generates an RFC/OASIS compliant SARIF 2.1.0 document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "defaultConfiguration": {
                    "level": "error" if f.severity == "error" else "warning"
                },
                "helpUri": f"https://docs.redhand.security/rules/{f.rule_id}",
            }

        results_list.append(
            {
                "ruleId": f.rule_id,
                "level": "error" if f.severity == "error" else "warning",
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_number, "startColumn": 1},
                        }
                    }
                ],
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RedHand ASPM Static Scanner",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://redhand.security",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc

