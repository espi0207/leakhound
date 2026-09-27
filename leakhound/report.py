"""Salida en texto, JSON y SARIF.

SARIF es el formato que entiende GitHub Code Scanning: si se sube desde una Action, los
hallazgos aparecen en la pestaña Security del repositorio, cada uno en su línea.
"""

from __future__ import annotations

import json

from . import __version__
from .ansi import clean, paint
from .rules import RULES, Severity
from .scanner import Finding

COLOR = {Severity.CRITICAL: "bright_red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "blue"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
INDENT = " " * 10


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.path, f.line))


def to_text(findings: list[Finding], where: str) -> str:
    if not findings:
        return paint(f"Sin secretos en {where}.", "green")
    out = []
    for f in _sorted(findings):
        tag = paint(f"[{f.severity.label}]".ljust(len(INDENT)), "bold", COLOR[f.severity])
        out.append(f"{tag}{paint(f.rule.title, 'bold')}  {clean(f.path)}:{f.line}")
        out.append(f"{INDENT}{clean(f.masked)}  " + paint(f"huella {f.fingerprint}", "gray"))
        if f.commit:
            where_now = "sigue en el código" if f.still_present else "ya no está en el código, pero sí en el historial"
            added = f"añadido en {f.commit[:8]} por {clean(f.author or '?')} el {f.date}"
            out.append(INDENT + paint(f"{added}; {where_now}", "gray"))
        out.append("")
    history = any(f.commit for f in findings)
    out.append(paint(f"{len(findings)} secreto(s) en {where}.", "bold"))
    out.append(
        "Un secreto que ha llegado a git hay que darlo por filtrado: revócalo y genera otro."
        + (" Borrarlo en un commit nuevo no lo quita del historial." if history else "")
    )
    return "\n".join(out)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in _sorted(findings)], indent=2, ensure_ascii=False)


def to_sarif(findings: list[Finding]) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.id.title().replace("-", ""),
            "shortDescription": {"text": r.title},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        }
        for r in RULES
    ]
    results = []
    for f in _sorted(findings):
        message = f"{f.rule.title}: {f.masked}"
        if f.commit:
            message += f" (añadido en el commit {f.commit[:8]})"
        results.append(
            {
                "ruleId": f.rule.id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
                "partialFingerprints": {"leakhound/v1": f.fingerprint},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakhound",
                        "version": __version__,
                        "informationUri": "https://github.com/espi0207/leakhound",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
