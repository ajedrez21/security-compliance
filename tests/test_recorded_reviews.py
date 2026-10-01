"""Revisiones del agente REGISTRADAS sobre fixtures (casos positivos y negativos).

Qué prueba: que el pipeline importe y valide estas revisiones y produzca los estados/hallazgos esperados.
Qué NO prueba: la calidad del análisis de un LLM en general. Las revisiones las hizo el mismo agente (Claude Code,
claude-sonnet-5-5) que escribió los fixtures: sesgo conocido. Si un fixture cambia, el snapshot_hash deja de
coincidir y la revisión se rechaza: hay que repetirla.
"""
import json
import unittest
from pathlib import Path

from helpers import FIXTURES, TmpCase, load_report, run_sc


class TestRecordedReviews(TmpCase):
    def run_case(self, fixture):
        proj = self.project(fixture)
        review = FIXTURES / "reviews" / f"{fixture}.review.json"
        p = run_sc("security", "--project", str(proj), "--output", str(self.out), "--review", str(review))
        self.assertEqual(p.returncode, 0, p.stderr)
        rep = load_report(self.out)
        self.assertTrue(rep["agent_review"]["accepted"], rep["agent_review"].get("reason"))
        self.assertEqual(rep["agent_review"]["rejected_entries"], [])
        return rep, {c["control_id"]: c for c in rep["controls"]}

    def test_vulnerable_app_positive_and_negative_cases(self):
        rep, ctl = self.run_case("vuln_app")
        self.assertEqual(ctl["SEC-AUTHZ-001"]["status"], "FAIL")      # ruta sin middleware
        self.assertEqual(ctl["SEC-INPUT-001"]["status"], "FAIL")      # concatenación SQL
        self.assertEqual(ctl["SEC-INPUT-003"]["status"], "FAIL")      # eval
        self.assertEqual(ctl["SEC-AUTHN-001"]["status"], "PASS")      # jwt.verify correcto
        self.assertEqual(ctl["SEC-INPUT-002"]["status"], "PASS")      # innerHTML con constante: no es un hallazgo
        self.assertEqual(ctl["SEC-AUTHZ-002"]["status"], "UNKNOWN")   # sin modelo de propiedad: no se concluye
        self.assertEqual(sorted(f["severity"] for f in rep["findings"] if f["origin"] == "agent_review"), ["critical", "critical", "high"])
        self.assertEqual(rep["gate"]["status"], "BLOCKED")
        # la consulta parametrizada (línea 11) y la ruta con requireAuth NO generaron hallazgos
        lines = {f["start_line"] for f in rep["findings"] if f["origin"] == "agent_review"}
        self.assertEqual(lines, {17, 29, 36})

    def test_global_guard_is_not_flagged_for_missing_local_decorator(self):
        """AC-13: control global respetado; y un control no concluyente se reporta UNKNOWN, no PASS."""
        rep, ctl = self.run_case("nest_global_guard")
        self.assertEqual(ctl["SEC-AUTHZ-001"]["status"], "PASS")
        self.assertEqual(ctl["SEC-AUTHZ-002"]["status"], "PASS")
        self.assertEqual(ctl["SEC-AUTHN-001"]["status"], "UNKNOWN")
        self.assertEqual([f for f in rep["findings"] if f["origin"] == "agent_review"], [])
        self.assertEqual(ctl["SEC-AUTHZ-001"]["provenance"], ["agent_review"])

    def test_review_is_rejected_if_the_fixture_changes(self):
        proj = self.project("vuln_app")
        (proj / "src" / "view.js").write_text("// cambió\n")
        review = FIXTURES / "reviews" / "vuln_app.review.json"
        run_sc("security", "--project", str(proj), "--output", str(self.out), "--review", str(review))
        rep = load_report(self.out)
        self.assertFalse(rep["agent_review"]["accepted"])
        self.assertEqual({c["control_id"]: c["status"] for c in rep["controls"]}["SEC-INPUT-001"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
