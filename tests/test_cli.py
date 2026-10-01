"""CLI de extremo a extremo: AC-01, AC-03, AC-07, AC-19, AC-21, AC-26, AC-30."""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import FIXTURES, ROOT, SKILL, TmpCase, git, load_report, run_dir_of, run_sc, copy_fixture

from sc_core import report as rep_mod

COMMANDS = ["help", "doctor", "init", "audit", "diff", "pr", "sox", "iso", "security", "secrets", "dependencies", "report"]


class TestIndependence(unittest.TestCase):
    def test_no_byf_coupling_and_no_llm_credentials_in_core(self):
        """AC-01: un único core portable, sin BYF ni API keys LLM."""
        bad = re.compile(r"(?i)\bbyf\b|ANTHROPIC_API_KEY|OPENAI_API_KEY|api\.openai\.com|api\.anthropic\.com")
        hits = []
        for base in (SKILL, ROOT / "installer"):
            for p in base.rglob("*"):
                if p.is_file() and p.suffix in (".py", ".md", ".json", ".yml", ".yaml", ".sh", ".ps1") and "__pycache__" not in p.parts:
                    for m in bad.finditer(p.read_text(encoding="utf-8", errors="ignore")):
                        hits.append((str(p.relative_to(ROOT)), m.group(0)))
        self.assertEqual(hits, [])

    def test_single_skill_package_and_stdlib_only(self):
        skills = [p for p in (ROOT / "skills").iterdir() if p.is_dir()]
        self.assertEqual([p.name for p in skills], ["security-compliance"])
        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        imports = set()
        for p in (SKILL / "scripts").rglob("*.py"):
            for line in p.read_text(encoding="utf-8").splitlines():
                m = re.match(r"^\s*(?:from|import)\s+([a-zA-Z_][\w]*)", line)
                if m:
                    imports.add(m.group(1))
        local = {"sc_core", "sc", "errors"}
        third = {i for i in imports if i not in local and (stdlib is None or i not in stdlib)} - {"__future__"}
        if stdlib is not None:
            self.assertEqual(third, set(), "el core debe usar solo la biblioteca estándar")


class TestHelpDoctorInit(TmpCase):
    def test_help_and_doctor_work_in_empty_project_without_scanners(self):
        empty = self.tmp / "vacio"
        empty.mkdir()
        h = run_sc("help", cwd=empty)
        self.assertEqual(h.returncode, 0)
        for c in COMMANDS:
            self.assertIn(c, h.stdout)
        full = run_sc("help", "all", cwd=empty).stdout
        self.assertIn("CÓDIGOS DE SALIDA", full)
        d = run_sc("doctor", "--project", str(empty), "--json")
        self.assertEqual(d.returncode, 0, d.stderr)
        data = json.loads(d.stdout)
        self.assertFalse(data["capabilities"]["secrets_scanner"])
        self.assertTrue(data["capabilities"]["assisted_review"])
        names = {c["name"]: c for c in data["checks"]}
        self.assertEqual(names["client_discovery"]["status"], "unverified")      # instalado ≠ descubierto
        self.assertEqual(names["scanner:gitleaks"]["status"], "missing")
        self.assertEqual(list(empty.iterdir()), [])                                # no escribe nada

    def test_no_arguments_prints_short_help_and_suggests_without_running(self):
        proj = self.project("node_basic")
        out = run_sc(cwd=proj)
        self.assertEqual(out.returncode, 0)
        self.assertIn("audit", out.stdout)
        self.assertIn("No se inició ninguna revisión", out.stdout)
        (proj / "src" / "x.js").write_text("1")
        out = run_sc(cwd=proj)
        self.assertIn("ejecute 'diff'", out.stdout)
        self.assertFalse((proj / ".security-compliance").exists())

    def test_audit_works_without_yaml_and_init_creates_valid_config_without_overwriting(self):
        proj = self.project("node_basic")
        a = run_sc("audit", "--project", str(proj), "--output", str(self.out))
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertFalse(load_report(self.out)["config"]["config_file"])
        i = run_sc("init", "--project", str(proj), "--non-interactive")
        self.assertEqual(i.returncode, 0, i.stderr)
        cfg = proj / ".security-compliance.yml"
        self.assertTrue(cfg.is_file())
        self.assertIn("sox_scope: unknown", cfg.read_text())
        self.assertFalse((proj / ".gitignore").exists())          # no cambia .gitignore silenciosamente
        self.assertIn("gitignore", i.stdout.lower())
        run_sc("audit", "--project", str(proj), "--output", str(self.out / "x"))
        self.assertEqual(load_report(self.out / "x")["config"]["config_file"], ".security-compliance.yml")
        cfg.write_text(cfg.read_text() + "# mi cambio\n")
        before = cfg.read_text()
        again = run_sc("init", "--project", str(proj), "--non-interactive", "--sox-scope", "yes")
        self.assertIn("ya existe", again.stdout)
        self.assertEqual(cfg.read_text(), before)

    def test_init_flags_and_gitignore_opt_in(self):
        proj = self.project("node_basic")
        run_sc("init", "--project", str(proj), "--non-interactive", "--sox-scope", "yes", "--update-gitignore")
        self.assertIn("sox_scope: yes", (proj / ".security-compliance.yml").read_text())
        self.assertIn(".security-compliance/", (proj / ".gitignore").read_text())
        # el archivo generado lo acepta el propio runner
        self.assertEqual(run_sc("audit", "--project", str(proj), "--output", str(self.out)).returncode, 0)

    def test_invalid_args_and_config_exit_2_with_clear_message(self):
        proj = self.project("node_basic")
        self.assertEqual(run_sc("audit", "--bogus").returncode, 2)
        self.assertEqual(run_sc("audit", "--project", str(self.tmp / "no-existe")).returncode, 2)
        (proj / ".security-compliance.yml").write_text("schema_version: 1\nfoo: 1\n")
        p = run_sc("audit", "--project", str(proj), "--output", str(self.out))
        self.assertEqual(p.returncode, 2)
        self.assertIn("propiedad desconocida", p.stderr)
        pj = run_sc("audit", "--project", str(proj), "--json")
        self.assertEqual(json.loads(pj.stdout)["exit_code"], 2)


class TestReports(TmpCase):
    def test_json_validates_schema_and_markdown_matches(self):
        """AC-19."""
        proj = self.project("python_basic")
        (proj / "app" / "main.py").write_text("import os\nprint('hola')\n")
        (proj / "Dockerfile").write_text("FROM python:latest\nCMD [\"python\"]\n")
        git(proj, "add", "-A")
        git(proj, "commit", "-qm", "d")
        p = run_sc("audit", "--project", str(proj), "--output", str(self.out))
        self.assertEqual(p.returncode, 0, p.stderr)
        rd = run_dir_of(self.out)
        rep = json.loads((rd / "report.json").read_text())
        self.assertEqual(rep_mod.validate_report(rep), [])
        md = (rd / "report.md").read_text()
        self.assertIn(rep["gate"]["status"], md)
        for f in rep["findings"]:
            self.assertIn(f["id"], md)
        for c in rep["controls"]:
            row = [l for l in md.splitlines() if l.startswith(f"| `{c['control_id']}`")]
            self.assertTrue(row, c["control_id"])
            self.assertIn(c["status"], row[0])
        self.assertIn(f"hallazgos: {len(rep['findings'])}", p.stdout)
        cov = rep["coverage"]
        self.assertEqual(sum(cov["by_status"].values()), cov["controls_selected"])
        self.assertEqual(len(rep["controls"]), cov["controls_selected"])

    def test_report_command_rerenders_without_rescanning_and_detects_tampering(self):
        proj = self.project("node_basic")
        run_sc("audit", "--project", str(proj), "--output", str(self.out))
        rd = run_dir_of(self.out)
        before = sorted(p.name for p in self.out.iterdir())
        md = run_sc("report", "--run", str(rd))
        self.assertEqual(md.returncode, 0, md.stderr)
        self.assertEqual(md.stdout.strip(), (rd / "report.md").read_text().strip())
        self.assertIn("coincide con SHA256SUMS", md.stderr)
        js = run_sc("report", "--run", str(rd), "--format", "json")
        self.assertEqual(json.loads(js.stdout)["run_id"], rd.name)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), before)    # no creó otra ejecución
        data = json.loads((rd / "report.json").read_text())
        data["gate"]["status"] = "PASS"
        data["gate"]["reasons"] = []
        (rd / "report.json").write_text(json.dumps(data))
        t = run_sc("report", "--run", str(rd))
        self.assertIn("NO COINCIDE", t.stderr)
        self.assertEqual(run_sc("report", "--run", str(self.tmp / "nada")).returncode, 2)

    def test_agent_controls_carry_their_review_procedure_in_the_report(self):
        proj = self.project("node_basic")
        run_sc("security", "--project", str(proj), "--output", str(self.out))
        ctl = {c["control_id"]: c for c in load_report(self.out)["controls"]}
        self.assertTrue(ctl["SEC-AUTHZ-001"]["review_procedure"])
        self.assertEqual(ctl["SEC-SECRETS-001"]["review_procedure"], [])

    def test_output_inside_project_is_never_part_of_the_audited_scope(self):
        proj = self.project("node_basic")
        out = proj / "audit-output"
        run_sc("audit", "--project", str(proj), "--output", str(out))
        first = load_report(out)
        run_sc("audit", "--project", str(proj), "--output", str(out))
        runs = sorted(p for p in out.iterdir() if p.is_dir())
        second = json.loads((runs[-1] / "report.json").read_text())
        self.assertEqual(first["snapshot"]["snapshot_hash"], second["snapshot"]["snapshot_hash"])
        self.assertIn("audit-output", second["snapshot"]["exclusions"])
        self.assertFalse(any(f.startswith("audit-output") for f in
                             [e["path"] for e in json.loads((runs[-1] / "inventory.json").read_text())["files"]]))

    def test_runs_are_never_overwritten(self):
        proj = self.project("node_basic")
        for _ in range(2):
            run_sc("audit", "--project", str(proj), "--output", str(self.out))
        runs = [p for p in self.out.iterdir() if p.is_dir()]
        self.assertEqual(len(runs), 2)
        self.assertEqual(len({p.name for p in runs}), 2)

    def test_no_certification_claims(self):
        """AC-21."""
        proj = self.project("node_basic")
        run_sc("audit", "--project", str(proj), "--output", str(self.out))
        md = (run_dir_of(self.out) / "report.md").read_text()
        self.assertIn("No constituye una certificación", md)
        for forbidden in (r"(?i)sox[- ]compliant", r"(?i)iso[^.\n]{0,20}certificad[oa]\b(?!.*no)", r"(?i)cumple\s+asvs", r"(?i)asvs\s+nivel\s+\d\s+(cumplido|alcanzado)"):
            self.assertIsNone(re.search(forbidden, md.replace("No constituye una certificación", "")), forbidden)
        self.assertIn("NO es verificación ni conformidad", md)
        self.assertNotIn("PASS", [c["status"] for c in load_report(self.out)["controls"] if c["domain"] == "iso"
                                  and c["control_id"] == "ISO-ORG-001"])

    def test_markdown_escapes_agent_supplied_html(self):
        proj = self.project("nest_global_guard")
        run_sc("security", "--project", str(proj), "--output", str(self.out / "a"))
        snap = load_report(self.out / "a")["snapshot"]["snapshot_hash"]
        review = {"schema_version": 1, "reviewer": {"client": "t"}, "created_at": "2026-09-30T12:00:00Z", "snapshot": {"snapshot_hash": snap},
                  "control_results": [{"control_id": "SEC-INPUT-002", "status": "FAIL", "rationale": "Salida sin escapar en la vista.", "finding_refs": ["h"]}],
                  "findings": [{"ref": "h", "control_id": "SEC-INPUT-002", "title": "<script>alert(1)</script> [clic](javascript:alert(1))",
                                "severity": "low", "confidence": "high", "file": "src/users.controller.ts", "start_line": 5,
                                "description": "<img src=x onerror=alert(1)> descripción con HTML."}]}
        rp = self.tmp / "r.json"
        rp.write_text(json.dumps(review))
        run_sc("security", "--project", str(proj), "--output", str(self.out / "b"), "--review", str(rp))
        md = (run_dir_of(self.out / "b") / "report.md").read_text()
        self.assertNotRegex(md, r"(?<!\\)<[a-zA-Z/!]")      # ninguna etiqueta HTML sin escapar
        self.assertNotRegex(md, r"(?<!\\)\[[^\n]*?(?<!\\)\]\(")      # sin enlaces Markdown activos


class TestStacksEndToEnd(TmpCase):
    """AC-26: Node, Python y .NET producen reportes completos en el entorno disponible."""

    def test_node_python_dotnet_projects_produce_complete_reports(self):
        for fx, stack in (("node_basic", "node"), ("python_basic", "python"), ("dotnet_basic", "dotnet")):
            with self.subTest(fx):
                proj = self.project(fx, name=f"p-{fx}")
                out = self.tmp / f"out-{fx}"
                p = run_sc("audit", "--project", str(proj), "--output", str(out))
                self.assertEqual(p.returncode, 0, p.stderr)
                rd = run_dir_of(out)
                rep = json.loads((rd / "report.json").read_text())
                self.assertEqual(rep_mod.validate_report(rep), [])
                self.assertIn(stack, rep["stacks"])
                self.assertEqual(rep["coverage"]["controls_selected"], 50)
                self.assertEqual({f.name for f in rd.iterdir()}, {"report.json", "report.md", "remediation.md", "presentation.html", "inventory.json", "SHA256SUMS", "tool-output"})
                self.assertEqual(len(list((rd / "tool-output").iterdir())), 3)

    def test_dependencies_command_inventories_and_does_not_query_network_by_default(self):
        proj = self.project("dotnet_basic")
        run_sc("dependencies", "--project", str(proj), "--output", str(self.out))
        rep = load_report(self.out)
        self.assertEqual({c["control_id"] for c in rep["controls"]}, {"SEC-DEPS-001", "SEC-DEPS-002"})
        self.assertTrue(any(d["name"] == "Newtonsoft.Json" for d in rep["dependencies"]["dependencies"]))
        dep001 = next(c for c in rep["controls"] if c["control_id"] == "SEC-DEPS-001")
        self.assertEqual(dep001["status"], "NOT_RUN")


class TestAllCommands(TmpCase):
    def test_every_mandatory_command_exists_is_documented_and_behaves(self):
        """AC-30."""
        proj = self.project("node_basic")
        ev = self.tmp / "ev.json"
        ev.write_text(json.dumps({"schema_version": 1, "project": {"repo": "x/y"}, "collected_at": "2026-09-30T12:00:00Z", "items": []}))
        calls = {
            "audit": ["audit", "--project", str(proj), "--output", str(self.out / "audit")],
            "diff": ["diff", "--project", str(proj), "--output", str(self.out / "diff")],
            "pr": ["pr", "--project", str(proj), "--evidence", str(ev), "--output", str(self.out / "pr")],
            "sox": ["sox", "--project", str(proj), "--output", str(self.out / "sox")],
            "iso": ["iso", "--project", str(proj), "--output", str(self.out / "iso")],
            "security": ["security", "--project", str(proj), "--output", str(self.out / "security")],
            "secrets": ["secrets", "--project", str(proj), "--output", str(self.out / "secrets")],
            "dependencies": ["dependencies", "--project", str(proj), "--output", str(self.out / "dependencies")],
        }
        for name, args in calls.items():
            with self.subTest(name):
                p = run_sc(*args)
                self.assertEqual(p.returncode, 0, f"{name}: {p.stderr}")
                rep = load_report(self.out / name)
                self.assertEqual(rep["command"], name)
                self.assertEqual(rep_mod.validate_report(rep), [])
        iso = load_report(self.out / "iso")
        self.assertTrue(any(c["supporting"] for c in iso["controls"]))
        self.assertEqual(run_sc("help").returncode, 0)
        self.assertEqual(run_sc("doctor", "--project", str(proj)).returncode, 0)
        self.assertEqual(run_sc("init", "--project", str(proj), "--non-interactive").returncode, 0)
        self.assertEqual(run_sc("report", "--run", str(run_dir_of(self.out / "audit"))).returncode, 0)

    def test_docs_and_skill_document_every_command(self):
        for doc in (ROOT / "docs" / "COMMANDS.md", SKILL / "references" / "commands.md", SKILL / "SKILL.md"):
            text = doc.read_text(encoding="utf-8")
            for c in COMMANDS:
                self.assertIn(f"`{c}`", text, f"{doc.name} no documenta {c}")


if __name__ == "__main__":
    unittest.main()


class TestPresentationOutputs(TmpCase):
    """Plan de remediación y presentación HTML."""

    def run_vuln(self):
        proj = self.project("vuln_app")
        review = FIXTURES / "reviews" / "vuln_app.review.json"
        p = run_sc("security", "--project", str(proj), "--output", str(self.out), "--review", str(review))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("presentation.html", p.stdout)
        return run_dir_of(self.out), load_report(self.out)

    def test_remediation_lists_every_problem_with_fix_and_norms(self):
        rd, rep = self.run_vuln()
        text = (rd / "remediation.md").read_text()
        for f in rep["findings"]:
            self.assertIn(f["id"], text)
            self.assertIn(f["title"].split()[0], text)
        self.assertIn("- [ ]", text)
        self.assertIn("Qué hacer", text)
        self.assertIn("OWASP ASVS 5.0.0 V8.2.1 (exacta)", text)
        self.assertIn("Pendiente de verificar", text)
        self.assertLess(text.index("### Crítica"), text.index("### Alta"))      # ordenado por severidad

    def test_html_is_self_contained_safe_and_complete(self):
        rd, rep = self.run_vuln()
        h = (rd / "presentation.html").read_text()
        self.assertNotRegex(h, r"(?i)<script|<iframe|<object|onerror=|javascript:")
        self.assertNotRegex(h, r"(?i)(src|href)=\"https?://")                  # sin recursos externos
        self.assertIn("Content-Security-Policy", h)
        for needle in ("<svg", "Hallazgos por severidad", "Niveles de severidad y criterios", "Normas y marcos", "OWASP ASVS 5.0.0",
                       "ISO/IEC 27001:2022", "SOX / ITGC", "NO están validados", "Flujo:", "prefers-color-scheme", "Bloqueado"):
            self.assertIn(needle, h)
        for f in rep["findings"]:
            self.assertIn(f["id"], h)

    def test_html_escapes_agent_supplied_markup(self):
        proj = self.project("nest_global_guard")
        run_sc("security", "--project", str(proj), "--output", str(self.out / "a"))
        snap = load_report(self.out / "a")["snapshot"]["snapshot_hash"]
        review = {"schema_version": 1, "reviewer": {"client": "t"}, "created_at": "2026-09-30T12:00:00Z", "snapshot": {"snapshot_hash": snap},
                  "control_results": [{"control_id": "SEC-INPUT-002", "status": "FAIL", "rationale": "Salida sin escapar en la vista.", "finding_refs": ["h"]}],
                  "findings": [{"ref": "h", "control_id": "SEC-INPUT-002", "title": "<script>alert(1)</script>", "severity": "low", "confidence": "high",
                                "file": "src/users.controller.ts", "start_line": 5, "description": "<img src=x onerror=alert(1)> texto"}]}
        rp = self.tmp / "r.json"
        rp.write_text(json.dumps(review))
        run_sc("security", "--project", str(proj), "--output", str(self.out / "b"), "--review", str(rp))
        h = (run_dir_of(self.out / "b") / "presentation.html").read_text()
        self.assertNotIn("<script>alert", h)
        self.assertNotIn("<img src=x", h)
        self.assertIn("&lt;script&gt;", h)

    def test_empty_findings_and_report_command_formats(self):
        proj = self.project("node_basic")
        run_sc("audit", "--project", str(proj), "--output", str(self.out))
        rd = run_dir_of(self.out)
        h = run_sc("report", "--run", str(rd), "--format", "html")
        self.assertEqual(h.returncode, 0, h.stderr)
        self.assertIn("<svg", h.stdout)
        r = run_sc("report", "--run", str(rd), "--format", "remediation")
        self.assertIn("# Plan de remediación", r.stdout)
        sums = (rd / "SHA256SUMS").read_text()
        self.assertIn("presentation.html", sums)
        self.assertIn("remediation.md", sums)
