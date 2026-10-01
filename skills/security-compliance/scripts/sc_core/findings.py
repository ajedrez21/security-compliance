"""Construcción de hallazgos normalizados con IDs estables y texto saneado."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from .redact import sanitize_text

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # menor índice = más severo
ORIGINS = ["scanner", "heuristic", "local_observation", "agent_review", "user_supplied", "provider_verified"]


def stable_id(*parts: Any) -> str:
    raw = "\0".join("" if p is None else str(p) for p in parts)
    return "F-" + hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def make_finding(control_id: str, title: str, severity: str, confidence: str, origin: str, *,
                 tool: Optional[str] = None, rule_id: Optional[str] = None, file: Optional[str] = None,
                 start_line: Optional[int] = None, end_line: Optional[int] = None, description: str = "",
                 evidence: str = "", risk: str = "", remediation: str = "",
                 mappings: Optional[List[Dict[str, Any]]] = None, in_scope: bool = True,
                 review_status: str = "unreviewed", extra_key: str = "") -> Dict[str, Any]:
    assert severity in SEVERITIES and origin in ORIGINS and confidence in ("high", "medium", "low")
    return {
        "id": stable_id(control_id, tool, rule_id, file, start_line, extra_key or title),
        "control_id": control_id,
        "title": sanitize_text(title, 300),
        "severity": severity,
        "confidence": confidence,
        "origin": origin,
        "tool": tool,
        "rule_id": sanitize_text(rule_id, 200) if rule_id else None,
        "file": file,
        "start_line": start_line,
        "end_line": end_line if end_line is not None else start_line,
        "description": sanitize_text(description, 1500),
        "evidence": sanitize_text(evidence, 600),
        "risk": sanitize_text(risk, 800),
        "remediation": sanitize_text(remediation, 800),
        "mappings": mappings or [],
        "review_status": review_status,
        "baseline_status": "unknown",   # sin comparación real contra una baseline
        "in_scope": in_scope,
        "exception": None,
    }
