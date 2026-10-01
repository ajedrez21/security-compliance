"""El reporte se actualiza a medida que se corrigen los problemas (progreso entre ejecuciones)."""
import json
import unittest

from helpers import FIXTURES, POSIX, SYNTHETIC_SECRET, TmpCase, git, load_report, make_fake, run_dir_of, run_sc

from sc_core import progress, report as rep_mod


def runs(out):
    return sorted((p for p in out.iterdir() if p.is_dir()), key=lambda p: (p.name[:16], p.stat().st_mtime_ns))


class TestProgress(TmpCase):
    def setUp(self):
        super().setUp()
        self.proj = self.project("vuln_app")

    def sec(self, review=None, out=None, env=None):
        args = ["security", "--project", str(self.proj), "--output", str(out or self.out)]
        if review:
            args += ["--review", str(review)]
        p = run_sc(*args, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads((runs(out or self.out)[-1] / "report.json").read_text())

    def write_review(self, snap, results, findings=(), name="r.json"):
        p = self.tmp / name
        p.write_text(json.dumps({"schema_version": 1, "reviewer": {"client": "t"}, "created_at": "2026-10-01T00:00:00Z",
                                 "snapshot": {"snapshot_hash": snap}, "control_results": results, "findings": list(findings)}))
        return p

    def test_first_run_has_no_comparison(self):
        r = self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        self.assertFalse(r["progress"]["has_previous"])
        self.assertEqual(r["history"], [])
        self.assertIn("primera revisión", (runs(self.out)[-1] / "remediation.md").read_text().lower())

    def test_fix_without_rereview_is_not_reported_as_resolved(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        src = self.proj / "src" / "server.js"
        src.write_text(src.read_text().replace("eval(req.body.expression)", "Number(req.body.expression)"))
        r2 = self.sec()            # el código cambió y no hay revisión nueva del agente
        pr = r2["progress"]
        self.assertTrue(pr["has_previous"])
        self.assertEqual(pr["resolved"], [])
        self.assertEqual(len(pr["not_reverified"]), 3)          # no se puede afirmar que se corrigieron
        self.assertTrue(all(b["control_status_now"] == "NOT_RUN" for b in pr["not_reverified"]))
        self.assertIn("Sin reverificar", (runs(self.out)[-1] / "remediation.md").read_text())

    def test_fix_plus_rereview_marks_resolved_and_keeps_the_rest_open(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        src = self.proj / "src" / "server.js"
        src.write_text(src.read_text().replace("eval(req.body.expression)", "Number(req.body.expression)"))
        snap = self.sec()["snapshot"]["snapshot_hash"]
        old = json.loads((FIXTURES / "reviews" / "vuln_app.review.json").read_text())
        cr = {c["control_id"]: c for c in old["control_results"]}
        results = [
            {"control_id": "SEC-INPUT-003", "status": "PASS", "rationale": "Ya no se usa eval: la expresión se convierte con Number().", "files_examined": ["src/server.js"]},
            {**cr["SEC-INPUT-001"]}, {**cr["SEC-AUTHZ-001"]}]
        findings = [f for f in old["findings"] if f["control_id"] in ("SEC-INPUT-001", "SEC-AUTHZ-001")]
        for f in findings:
            f["start_line"] = {"sqli1": 17, "authz1": 29}[f["ref"]]
        r3 = self.sec(self.write_review(snap, results, findings), out=self.out)
        pr = r3["progress"]
        self.assertEqual([b["control_id"] for b in pr["resolved"]], ["SEC-INPUT-003"])
        self.assertEqual(sorted(b["control_id"] for b in pr["persistent"]), ["SEC-AUTHZ-001", "SEC-INPUT-001"])
        self.assertEqual(pr["new"], [])
        self.assertEqual(sum(pr["counts_before"].values()) - sum(pr["counts_after"].values()), 1)
        md = (runs(self.out)[-1] / "remediation.md").read_text()
        self.assertIn("- [x]", md)
        self.assertIn("Resueltos", md)
        html = (runs(self.out)[-1] / "presentation.html").read_text()
        self.assertIn("✅ Resueltos", html)
        self.assertIn("Evolución entre revisiones", html)        # 3 puntos: historial + actual
        self.assertEqual(len(r3["history"]), 2)
        self.assertEqual(rep_mod.validate_report({k: v for k, v in r3.items()}), [])

    def test_shifted_line_numbers_do_not_count_as_new(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        f = progress.fingerprint
        a = {"control_id": "SEC-X-001", "tool": "semgrep", "origin": "scanner", "rule_id": "r", "file": "a.js", "title": "Titulo  X", "start_line": 3}
        b = dict(a, title="titulo x", start_line=40)
        self.assertEqual(f(a), f(b))
        ag1 = {"control_id": "SEC-X-001", "tool": "cursor", "origin": "agent_review", "file": "a.js", "title": "una redacción", "id": "F-1", "start_line": 1}
        ag2 = dict(ag1, tool="codex", title="otra redacción distinta", id="F-2")
        self.assertEqual(f(ag1), f(ag2))                       # otro cliente/redacción: misma identidad
        two = progress.fingerprints([dict(a, id="F-a", start_line=3), dict(a, id="F-b", start_line=9)])
        self.assertEqual(len(two), 2)                          # dos hallazgos iguales en el mismo archivo no se colapsan

    def test_latest_copies_are_refreshed_each_run(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        self.sec(out=self.out)
        self.assertTrue((self.out / "latest-security-presentation.html").is_file())
        self.assertTrue((self.out / "latest-security-remediation.md").is_file())
        self.assertEqual((self.out / "latest-security-remediation.md").read_text(), (runs(self.out)[-1] / "remediation.md").read_text())
        self.assertEqual(len(runs(self.out)), 2)                # las ejecuciones nunca se sobrescriben

    def test_other_commands_and_projects_are_not_compared(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        p = run_sc("audit", "--project", str(self.proj), "--output", str(self.out))
        r = json.loads((runs(self.out)[-1] / "report.json").read_text())
        self.assertEqual(r["command"], "audit")
        self.assertFalse(r["progress"]["has_previous"])

    @unittest.skipUnless(POSIX, "fakes POSIX")
    def test_secret_removed_with_clean_scanner_is_resolved(self):
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        (self.proj / "src" / "app.js").write_text(f"const key = '{SYNTHETIC_SECRET}';\n")
        run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env={"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "findings", bin_))})
        (self.proj / "src" / "app.js").write_text("module.exports = process.env.KEY;\n")
        run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env={"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "clean", bin_))})
        pr = json.loads((runs(self.out)[-1] / "report.json").read_text())["progress"]
        self.assertEqual({b["control_id"] for b in pr["resolved"]}, {"SEC-SECRETS-001"})   # scanner + heurística
        self.assertEqual(pr["gate_before"], "BLOCKED")
        self.assertEqual(pr["gate_after"], "PASS")
        # y el valor sintético no aparece en ningún lado
        blob = "".join(f.read_text(errors="ignore") for f in self.out.rglob("*") if f.is_file())
        self.assertNotIn(SYNTHETIC_SECRET, blob)

    def test_unreadable_previous_report_does_not_break_a_new_run(self):
        self.sec(FIXTURES / "reviews" / "vuln_app.review.json")
        (runs(self.out)[-1] / "report.json").write_text("{corrupto")
        r = self.sec(out=self.out)
        self.assertFalse(r["progress"]["has_previous"])


if __name__ == "__main__":
    unittest.main()
