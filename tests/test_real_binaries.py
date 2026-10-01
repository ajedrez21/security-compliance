"""Adaptadores contra BINARIOS REALES (se omiten si la herramienta no está instalada).

OSV-Scanner consulta api.osv.dev (envía nombre/versión de paquetes sintéticos): solo con SC_TEST_NETWORK=1.
"""
import json
import os
import shutil
import unittest
from pathlib import Path

from helpers import TmpCase, load_report, run_sc

from sc_core.tools.base import CLEAN, FINDINGS
from sc_core.tools.gitleaks import Gitleaks
from sc_core.tools.osv import OsvScanner
from sc_core.tools.semgrep import Semgrep

PAT = "ghp_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"[:36]   # formato de GitHub PAT sintético (no es un token real)


def ctx(tmp, root, **kw):
    work = tmp / "work"
    work.mkdir(exist_ok=True)
    c = {"root": root, "excludes": [".git", "node_modules", ".security-compliance"], "timeout": 240, "workdir": work,
         "network_allowed": False, "changed_paths": None}
    c.update(kw)
    return c


def have(name):
    return shutil.which(name) is not None


class RealCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.proj = self.project("python_basic")
        (self.proj / "app" / "danger.py").write_text("import yaml\n\ndef f(s):\n    return yaml.load(s)\n")
        (self.proj / "src").mkdir()
        (self.proj / "src" / "cfg.js").write_text(f"const token = '{PAT}';\n")


@unittest.skipUnless(have("gitleaks"), "gitleaks no instalado")
class TestRealGitleaks(RealCase):
    def test_detects_secret_without_persisting_it_and_clean_scan(self):
        run = Gitleaks().run(ctx(self.tmp, self.proj))
        self.assertEqual(run["status"], FINDINGS, run)
        self.assertNotIn(PAT, json.dumps(run))
        f = run["findings"][0]
        self.assertEqual((f["file"], f["start_line"]), ("src/cfg.js", 1))
        self.assertIn("--gitleaks-ignore-path", run["command"])
        (self.proj / "src" / "cfg.js").write_text("module.exports = 1;\n")
        self.assertEqual(Gitleaks().run(ctx(self.tmp, self.proj))["status"], CLEAN)

    def test_repo_gitleaksignore_cannot_suppress(self):
        run1 = Gitleaks().run(ctx(self.tmp, self.proj))
        fp = run1["findings"][0]["rule_id"]
        # el repositorio intenta suprimir con .gitleaksignore (fingerprint real: archivo:regla:línea)
        (self.proj / ".gitleaksignore").write_text(f"src/cfg.js:{fp}:1\n")
        self.assertEqual(Gitleaks().run(ctx(self.tmp, self.proj))["status"], FINDINGS)

    def test_e2e_report_has_no_secret_anywhere(self):
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), tools=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        rep = load_report(self.out)
        self.assertEqual(rep["gate"]["status"], "BLOCKED")
        blob = p.stdout + p.stderr + "".join(f.read_text(errors="ignore") for f in self.out.rglob("*") if f.is_file())
        self.assertNotIn(PAT, blob)


@unittest.skipUnless(have("semgrep"), "semgrep no instalado")
class TestRealSemgrep(RealCase):
    def test_bundled_rules_detect_and_normalize(self):
        run = Semgrep().run(ctx(self.tmp, self.proj))
        self.assertEqual(run["status"], FINDINGS, run)
        f = next(x for x in run["findings"] if x["file"] == "app/danger.py")
        self.assertEqual(f["rule_id"], "sc.python.yaml-load-unsafe")
        self.assertEqual((f["severity"], f["start_line"]), ("high", 4))
        self.assertFalse(run.get("partial"))

    def test_changed_scope_limits_analysis(self):
        run = Semgrep().run(ctx(self.tmp, self.proj, changed_paths={"app/main.py"}))
        self.assertEqual(run["status"], CLEAN, run)

    def test_clean_project(self):
        (self.proj / "app" / "danger.py").write_text("print('ok')\n")
        self.assertEqual(Semgrep().run(ctx(self.tmp, self.proj))["status"], CLEAN)


@unittest.skipUnless(have("osv-scanner") and os.environ.get("SC_TEST_NETWORK") == "1", "osv-scanner o SC_TEST_NETWORK=1 ausente")
class TestRealOsv(TmpCase):
    def test_vulnerable_lockfile(self):
        p = self.tmp / "n"
        p.mkdir()
        (p / "package.json").write_text('{"name":"d","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}')
        (p / "package-lock.json").write_text(json.dumps({"name": "d", "version": "1.0.0", "lockfileVersion": 3, "packages": {
            "": {"name": "d", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
            "node_modules/lodash": {"version": "4.17.15"}}}))
        run = OsvScanner().run(ctx(self.tmp, p, network_allowed=True))
        self.assertEqual(run["status"], FINDINGS, run)
        self.assertTrue(all(f["file"] == "package-lock.json" for f in run["findings"]))


if __name__ == "__main__":
    unittest.main()
