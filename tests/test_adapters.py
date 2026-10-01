"""Adaptadores de scanners con binarios SIMULADOS (fakes). No prueban los binarios reales (ver docs/VALIDATION.md).

AC-10 (seis estados), AC-11 (herramienta faltante ≠ PASS), AC-12 (secreto sintético nunca persiste).
"""
import json
import os
import unittest
from pathlib import Path

from helpers import POSIX, SYNTHETIC_SECRET, TmpCase, all_text, load_report, make_fake, run_dir_of, run_sc

from sc_core.tools.base import (CLEAN, ERROR, FINDINGS, INVALID, MISSING, NO_PACKAGES, SKIPPED_POLICY, TIMEOUT)
from sc_core.tools.gitleaks import Gitleaks, build_config
from sc_core.tools.osv import OsvScanner
from sc_core.tools.semgrep import Semgrep


def ctx(tmp: Path, root: Path, **kw):
    work = tmp / "work"
    work.mkdir(exist_ok=True)
    base = {"root": root, "excludes": [".git", "node_modules"], "timeout": 20, "workdir": work,
            "network_allowed": True, "changed_paths": None}
    base.update(kw)
    return base


@unittest.skipUnless(POSIX, "los fakes son scripts POSIX")
class TestAdapterStates(TmpCase):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.proj = self.project("python_basic")
        (self.proj / "src").mkdir(exist_ok=True)

    def use(self, env_var: str, tool: str, mode: str):
        os.environ[env_var] = str(make_fake(tool, mode, self.bin))
        self.addCleanup(os.environ.pop, env_var, None)

    def run_gitleaks(self, mode, timeout=20):
        self.use("SC_GITLEAKS_BIN", "gitleaks", mode)
        return Gitleaks().run(ctx(self.tmp, self.proj, timeout=timeout))

    def test_gitleaks_states(self):
        self.assertEqual(self.run_gitleaks("clean")["status"], CLEAN)
        self.assertEqual(self.run_gitleaks("findings")["status"], FINDINGS)
        self.assertEqual(self.run_gitleaks("timeout", timeout=1)["status"], TIMEOUT)
        self.assertEqual(self.run_gitleaks("invalid")["status"], INVALID)
        self.assertEqual(self.run_gitleaks("error")["status"], ERROR)
        os.environ["SC_GITLEAKS_BIN"] = "/nonexistent/gitleaks"
        self.addCleanup(os.environ.pop, "SC_GITLEAKS_BIN", None)
        self.assertEqual(Gitleaks().run(ctx(self.tmp, self.proj))["status"], MISSING)

    def test_gitleaks_findings_drop_secret_and_match(self):
        run = self.run_gitleaks("findings")
        blob = json.dumps(run)
        self.assertNotIn(SYNTHETIC_SECRET, blob)
        f = run["findings"][0]
        self.assertEqual((f["rule_id"], f["file"], f["start_line"]), ("aws-access-token", "src/app.js", 1))
        self.assertEqual(f["origin"], "scanner")

    def test_gitleaks_command_uses_own_config_redact_and_no_shell(self):
        run = self.run_gitleaks("clean")
        self.assertIn("--redact", run["command"])
        self.assertIn("--exit-code 2", run["command"])
        self.assertIn("--gitleaks-ignore-path", run["command"])
        self.assertFalse(run["rules"]["repo_config_used"])
        self.assertEqual(run["version"], "8.28.0")

    def test_gitleaks_allowlist_config_escapes_patterns(self):
        cfg = build_config(["node_modules", "a.b/c", "*.min.js"])
        self.assertIn("useDefault = true", cfg)
        self.assertIn(r"(^|/)node_modules($|/)", cfg)
        self.assertIn(r"a\.b/c", cfg)

    def run_semgrep(self, mode, timeout=20):
        self.use("SC_SEMGREP_BIN", "semgrep", mode)
        return Semgrep().run(ctx(self.tmp, self.proj, timeout=timeout))

    def test_semgrep_states(self):
        self.assertEqual(self.run_semgrep("clean")["status"], CLEAN)
        r = self.run_semgrep("findings")
        self.assertEqual(r["status"], FINDINGS)
        self.assertEqual(r["findings"][0]["severity"], "high")
        self.assertEqual(r["findings"][0]["file"], "app/main.py")
        self.assertEqual(self.run_semgrep("timeout", timeout=1)["status"], TIMEOUT)
        self.assertEqual(self.run_semgrep("invalid")["status"], INVALID)
        self.assertEqual(self.run_semgrep("error")["status"], ERROR)
        self.assertTrue(self.run_semgrep("partial")["partial"])

    def test_semgrep_uses_bundled_rules_only_and_metrics_off(self):
        r = self.run_semgrep("clean")
        self.assertIn("--metrics=off", r["command"])
        self.assertIn("semgrep-local.yml", r["command"])
        self.assertTrue(r["rules"]["sha256"])
        self.assertFalse(r["rules"]["registry_used"])
        self.assertNotIn("p/default", r["command"])

    def test_semgrep_changed_scope_without_files(self):
        self.use("SC_SEMGREP_BIN", "semgrep", "clean")
        r = Semgrep().run(ctx(self.tmp, self.proj, changed_paths=set()))
        self.assertEqual(r["status"], NO_PACKAGES)

    def run_osv(self, mode, timeout=20, network=True):
        self.use("SC_OSV_BIN", "osv", mode)
        return OsvScanner().run(ctx(self.tmp, self.proj, timeout=timeout, network_allowed=network))

    def test_osv_states(self):
        self.assertEqual(self.run_osv("clean")["status"], CLEAN)
        r = self.run_osv("findings")
        self.assertEqual(r["status"], FINDINGS)
        self.assertEqual(r["findings"][0]["severity"], "critical")
        self.assertIn("GHSA-xxxx-0000-0000", r["findings"][0]["evidence"])
        self.assertEqual(self.run_osv("nopackages")["status"], NO_PACKAGES)
        self.assertEqual(self.run_osv("timeout", timeout=1)["status"], TIMEOUT)
        self.assertEqual(self.run_osv("invalid")["status"], INVALID)
        self.assertEqual(self.run_osv("error")["status"], ERROR)

    def test_osv_not_run_when_network_not_allowed(self):
        r = self.run_osv("findings", network=False)
        self.assertEqual(r["status"], SKIPPED_POLICY)
        self.assertIn("api.osv.dev", " ".join(r["notes"]))


@unittest.skipUnless(POSIX, "los fakes son scripts POSIX")
class TestScannerCoverageInReports(TmpCase):
    """AC-11 y AC-12 de extremo a extremo con adaptadores simulados."""

    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.proj = self.project("python_basic")
        (self.proj / "src").mkdir()
        (self.proj / "src" / "app.js").write_text(f"const key = '{SYNTHETIC_SECRET}';\n")

    def status(self, report, cid):
        return next(c for c in report["controls"] if c["control_id"] == cid)["status"]

    def test_missing_tool_is_never_pass(self):
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out))
        self.assertEqual(p.returncode, 0, p.stderr)
        rep = load_report(self.out)
        self.assertEqual(self.status(rep, "SEC-SECRETS-001"), "NOT_RUN")
        self.assertNotIn(rep["gate"]["status"], ("PASS", "PASS_WITH_WARNINGS"))
        self.assertEqual(rep["gate"]["status"], "INCOMPLETE")

    def test_clean_scan_passes_only_that_control(self):
        env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "clean", self.bin))}
        (self.proj / "src" / "app.js").write_text("module.exports = 1;\n")
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env=env)
        rep = load_report(self.out)
        self.assertEqual(self.status(rep, "SEC-SECRETS-001"), "PASS")
        self.assertEqual(rep["gate"]["status"], "PASS")

    def test_secret_finding_is_reported_without_leaking_anywhere(self):
        env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "findings", self.bin))}
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env=env)
        self.assertEqual(p.returncode, 0)
        rep = load_report(self.out)
        self.assertEqual(self.status(rep, "SEC-SECRETS-001"), "FAIL")
        self.assertEqual(rep["gate"]["status"], "BLOCKED")
        self.assertTrue(any(f["rule_id"] == "aws-access-token" for f in rep["findings"]))
        for blob in (all_text(self.out), p.stdout, p.stderr):
            self.assertNotIn(SYNTHETIC_SECRET, blob)
        # tampoco con --json
        p2 = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out / "b"), "--json", env=env)
        self.assertNotIn(SYNTHETIC_SECRET, p2.stdout + p2.stderr + all_text(self.out / "b"))

    def test_heuristic_only_never_counts_as_scanner_and_does_not_leak(self):
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out))
        rep = load_report(self.out)
        cand = [f for f in rep["findings"] if f["origin"] == "heuristic"]
        self.assertTrue(cand)
        self.assertEqual(self.status(rep, "SEC-SECRETS-001"), "NOT_RUN")
        for blob in (all_text(self.out), p.stdout, p.stderr):
            self.assertNotIn(SYNTHETIC_SECRET, blob)

    def test_scanner_with_partial_coverage_is_not_pass(self):
        env = {"SC_SEMGREP_BIN": str(make_fake("semgrep", "partial", self.bin))}
        run_sc("security", "--project", str(self.proj), "--output", str(self.out), env=env)
        rep = load_report(self.out)
        self.assertEqual(self.status(rep, "SEC-SAST-001"), "UNKNOWN")

    def test_timeout_and_error_states_map_to_error_status(self):
        env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "error", self.bin))}
        run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env=env)
        self.assertEqual(self.status(load_report(self.out), "SEC-SECRETS-001"), "ERROR")

    def test_inline_suppressions_are_warned(self):
        (self.proj / "src" / "x.js").write_text("const a = 'z'; // gitleaks:allow\n")
        env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "clean", self.bin))}
        run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env=env)
        self.assertTrue(any("gitleaks:allow" in w for w in load_report(self.out)["warnings"]))


if __name__ == "__main__":
    unittest.main()
