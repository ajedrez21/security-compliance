"""Gate y códigos de salida (AC-20) + política confiable en CI (AC-25)."""
import copy
import json
import unittest
from datetime import date, timedelta
from pathlib import Path

from helpers import POSIX, SYNTHETIC_SECRET, TmpCase, all_text, load_report, make_fake, run_sc

from sc_core import config as cfgmod, errors, evaluate
from sc_core.findings import make_finding


def cfg(**gate):
    c = copy.deepcopy(cfgmod.DEFAULTS)
    c["gate"].update(gate)
    return c


def ctl(cid, status, required=False, exception=None):
    return {"control_id": cid, "status": status, "required": required, "exception": exception}


def fnd(sev="high", conf="high", origin="scanner", scope=True, exception=None, review_status="unreviewed"):
    f = make_finding("SEC-SAST-001", "t", sev, conf, origin, tool="x", rule_id="r", file="a.py", start_line=1)
    f["in_scope"], f["exception"], f["review_status"] = scope, exception, review_status
    return f


def gate(results, findings=(), c=None, mode="advisory", **kw):
    args = dict(mode=mode, scope_empty=False, snapshot_consistent=True, warnings=[])
    args.update(kw)
    return evaluate.compute_gate(c or cfg(), results, list(findings), **args)


class TestGateStates(unittest.TestCase):
    def test_pass(self):
        self.assertEqual(gate([ctl("A-B-001", "PASS"), ctl("A-B-002", "NOT_APPLICABLE")])["status"], "PASS")

    def test_pass_with_warnings_from_non_blocking_finding(self):
        g = gate([ctl("A-B-001", "PASS")], [fnd("low")])
        self.assertEqual(g["status"], "PASS_WITH_WARNINGS")
        g = gate([ctl("A-B-001", "PASS")], [], warnings=["algo"])
        self.assertEqual(g["status"], "PASS_WITH_WARNINGS")

    def test_incomplete_for_each_unverified_state(self):
        for st in ("UNKNOWN", "NOT_RUN", "ERROR"):
            self.assertEqual(gate([ctl("A-B-001", "PASS"), ctl("A-B-002", st)])["status"], "INCOMPLETE", st)

    def test_blocked_by_finding_over_threshold(self):
        g = gate([ctl("A-B-001", "PASS")], [fnd("critical")])
        self.assertEqual(g["status"], "BLOCKED")
        self.assertEqual(len(g["blocking_findings"]), 1)

    def test_not_blocking_cases(self):
        for f in (fnd("medium"), fnd("high", conf="low"), fnd("high", origin="heuristic"), fnd("high", scope=False),
                  fnd("high", exception={"id": "E"}), fnd("high", review_status="false_positive")):
            self.assertNotEqual(gate([ctl("A-B-001", "PASS")], [f])["status"], "BLOCKED")

    def test_blocked_by_required_control_fail(self):
        g = gate([ctl("A-B-001", "FAIL", required=True)])
        self.assertEqual(g["status"], "BLOCKED")

    def test_required_unknown_policy_block_vs_incomplete(self):
        for st in ("UNKNOWN", "NOT_RUN", "ERROR"):
            self.assertEqual(gate([ctl("A-B-001", st, required=True)], c=cfg(unknown_required="block"))["status"], "BLOCKED")
            self.assertEqual(gate([ctl("A-B-001", st, required=True)], c=cfg(unknown_required="incomplete"))["status"], "INCOMPLETE")

    def test_precedence_blocked_over_incomplete_over_warnings(self):
        res = [ctl("A-B-001", "UNKNOWN")]
        self.assertEqual(gate(res, [fnd("high")])["status"], "BLOCKED")
        self.assertEqual(gate(res, [fnd("low")])["status"], "INCOMPLETE")
        self.assertEqual(gate([ctl("A-B-001", "PASS")], [fnd("low")])["status"], "PASS_WITH_WARNINGS")

    def test_empty_scope_never_passes(self):
        self.assertEqual(gate([ctl("A-B-001", "PASS")], scope_empty=True)["status"], "INCOMPLETE")

    def test_no_evaluable_controls_never_passes(self):
        self.assertEqual(gate([])["status"], "INCOMPLETE")
        self.assertEqual(gate([ctl("A-B-001", "NOT_APPLICABLE")])["status"], "INCOMPLETE")

    def test_inconsistent_snapshot_is_incomplete(self):
        self.assertEqual(gate([ctl("A-B-001", "PASS")], snapshot_consistent=False)["status"], "INCOMPLETE")

    def test_control_exception_is_honoured(self):
        g = gate([ctl("A-B-001", "FAIL", required=True, exception={"id": "E1"})])
        self.assertNotEqual(g["status"], "BLOCKED")


class TestExitCodes(unittest.TestCase):
    def test_advisory_always_zero(self):
        for s in ("PASS", "PASS_WITH_WARNINGS", "BLOCKED", "INCOMPLETE"):
            self.assertEqual(evaluate.exit_code_for(s, "advisory"), 0)

    def test_enforce_mapping(self):
        m = {"PASS": 0, "PASS_WITH_WARNINGS": 0, "BLOCKED": 1, "INCOMPLETE": 3}
        for s, code in m.items():
            self.assertEqual(evaluate.exit_code_for(s, "enforce"), code)

    def test_precedence_between_technical_error_and_findings(self):
        self.assertEqual(evaluate.combine_exit(True, "BLOCKED", "enforce"), errors.EXIT_ERROR)
        self.assertEqual(evaluate.combine_exit(False, "BLOCKED", "enforce"), errors.EXIT_BLOCKED)
        self.assertEqual(evaluate.combine_exit(False, "INCOMPLETE", "enforce"), errors.EXIT_INCOMPLETE)
        self.assertEqual(evaluate.combine_exit(False, "PASS", "enforce"), errors.EXIT_OK)
        self.assertEqual(evaluate.combine_exit(True, "PASS", "advisory"), errors.EXIT_ERROR)


class TestExceptions(unittest.TestCase):
    def exc(self, expires, **scope):
        return {"id": "EXC-1", "reason": "Riesgo aceptado temporalmente", "owner": "equipo", "expires": expires,
                "scope": scope or {"control_id": "SEC-SAST-001"}, "origin": "TICKET-1"}

    def test_valid_expired_and_untrusted(self):
        c = cfg()
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        f = fnd("high")
        c["exceptions"], c["_exceptions_trusted"] = [self.exc(tomorrow)], False
        evaluate.apply_exceptions(c, [f], [], enforce=False)
        self.assertTrue(f["exception"])
        f2 = fnd("high")
        c["exceptions"] = [self.exc(yesterday)]
        w = evaluate.apply_exceptions(c, [f2], [], enforce=False)
        self.assertIsNone(f2["exception"])
        self.assertTrue(any("vencida" in x for x in w))
        f3 = fnd("high")
        c["exceptions"] = [self.exc(tomorrow)]
        w = evaluate.apply_exceptions(c, [f3], [], enforce=True)    # enforce sin política confiable
        self.assertIsNone(f3["exception"])


@unittest.skipUnless(POSIX, "los fakes son scripts POSIX")
class TestCiPolicy(TmpCase):
    """AC-25: el PR no puede rebajar la política confiable; reportes conservados y saneados."""

    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.proj = self.project("python_basic")
        (self.proj / "src").mkdir()
        (self.proj / "src" / "app.js").write_text(f"const key = '{SYNTHETIC_SECRET}';\n")
        self.policy_dir = self.tmp / "politica-confiable"      # fuera del proyecto
        self.policy_dir.mkdir()
        self.policy = self.policy_dir / "policy.yml"
        self.policy.write_text("schema_version: 1\ngate:\n  block_severities: [critical, high]\n  required_controls: [SEC-SECRETS-001]\n"
                               "  unknown_required: block\ntrust:\n  agent_review: false\n  user_supplied_evidence: false\n")
        self.env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "findings", self.bin))}

    def test_enforce_requires_trusted_policy(self):
        p = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--output", str(self.out), env=self.env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("política confiable", p.stderr)

    def test_policy_inside_project_is_rejected_in_enforce(self):
        inside = self.proj / "policy.yml"
        inside.write_text(self.policy.read_text())
        p = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--policy", str(inside),
                   "--output", str(self.out), env=self.env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("dentro del proyecto", p.stderr)

    def test_blocked_exit_1_and_reports_sanitized(self):
        p = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--policy", str(self.policy),
                   "--output", str(self.out), env=self.env)
        self.assertEqual(p.returncode, 1, p.stderr)
        rep = load_report(self.out)
        self.assertEqual(rep["gate"]["status"], "BLOCKED")
        self.assertEqual(rep["gate"]["exit_code"], 1)
        self.assertEqual(rep["config"]["policy_source"], "trusted_policy")
        self.assertNotIn(SYNTHETIC_SECRET, all_text(self.out) + p.stdout + p.stderr)

    def test_pr_cannot_lower_trusted_policy(self):
        """El YAML del PR intenta no bloquear nada y excluir el directorio; la política confiable prevalece."""
        (self.proj / ".security-compliance.yml").write_text(
            "schema_version: 1\ngate:\n  block_severities: []\n  required_controls: []\n  unknown_required: incomplete\n"
            "paths:\n  exclude: [src]\nproject:\n  sox_scope: 'no'\n"
            "exceptions:\n  - id: PR-1\n    scope: {control_id: SEC-SECRETS-001}\n    reason: Me autoapruebo la excepción\n"
            "    owner: yo\n    expires: 2099-01-01\n")
        p = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--policy", str(self.policy),
                   "--output", str(self.out), env=self.env)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        rep = load_report(self.out)
        self.assertEqual(rep["gate"]["policy"]["block_severities"], ["critical", "high"])
        self.assertEqual(rep["gate"]["policy"]["required_controls"], ["SEC-SECRETS-001"])
        self.assertNotIn("src", rep["config"]["effective"]["paths"]["exclude"])
        self.assertEqual(rep["exceptions"], [])
        self.assertEqual(rep["project"]["sox_scope"], "unknown")   # el PR no se declara fuera de alcance

    def test_tool_missing_in_enforce_is_incomplete_exit_3_or_blocked_when_required(self):
        pol = self.policy_dir / "soft.yml"
        pol.write_text("schema_version: 1\ngate:\n  unknown_required: incomplete\n")
        p = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--policy", str(pol), "--output", str(self.out))
        self.assertEqual(p.returncode, 3)
        p2 = run_sc("secrets", "--project", str(self.proj), "--mode", "enforce", "--policy", str(self.policy),
                    "--output", str(self.out / "b"))
        self.assertEqual(p2.returncode, 1)     # control obligatorio sin verificar + unknown_required=block

    def test_advisory_returns_zero_but_json_keeps_real_gate(self):
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), "--json", env=self.env)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["gate"]["status"], "BLOCKED")

    def test_invalid_config_is_exit_2_even_if_findings_exist(self):
        (self.proj / ".security-compliance.yml").write_text("schema_version: 1\ntools:\n  command: rm -rf /\n")
        p = run_sc("secrets", "--project", str(self.proj), "--output", str(self.out), env=self.env)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(POSIX, "gate.sh requiere POSIX")
class TestCiGateScript(TmpCase):
    """AC-25: el ejemplo de CI bloquea según política, conserva reportes saneados y propaga el código."""

    def setUp(self):
        super().setUp()
        from helpers import ROOT, SKILL
        self.gate = ROOT / "integrations" / "ci" / "gate.sh"
        self.skill = SKILL
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.proj = self.project("python_basic")
        (self.proj / "src").mkdir()
        (self.proj / "src" / "app.js").write_text(f"const key = '{SYNTHETIC_SECRET}';\n")
        import subprocess as sp
        self.sp = sp
        sp.run(["git", "-C", str(self.proj), "add", "-A"], check=True)
        sp.run(["git", "-C", str(self.proj), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "s"], check=True)
        self.policy = self.tmp / "politica" / "policy.yml"
        self.policy.parent.mkdir()
        self.policy.write_text((ROOT / "integrations" / "ci" / "policy.example.yml").read_text())

    def run_gate(self, env_extra, policy=None):
        import os
        env = {**os.environ, **NO_TOOLS, **env_extra, "GITHUB_STEP_SUMMARY": str(self.tmp / "summary.md"), "PYTHONDONTWRITEBYTECODE": "1"}
        return self.sp.run(["sh", str(self.gate), str(self.skill), str(self.proj), str(policy or self.policy), str(self.out)],
                           capture_output=True, text=True, env=env)

    def test_blocks_with_exit_1_keeps_sanitized_reports_and_step_summary(self):
        r = self.run_gate({"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "findings", self.bin))})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        rep = load_report(self.out)
        self.assertEqual(rep["gate"]["status"], "BLOCKED")
        self.assertIn("BLOCKED", (self.tmp / "summary.md").read_text())
        self.assertNotIn(SYNTHETIC_SECRET, all_text(self.out) + (self.tmp / "summary.md").read_text() + r.stdout + r.stderr)

    def test_incomplete_without_scanners_is_3_or_blocked_when_required(self):
        r = self.run_gate({})                       # la política de ejemplo exige SEC-SECRETS-001 y SEC-SAST-001 (unknown_required=block)
        self.assertEqual(r.returncode, 1)
        soft = self.tmp / "politica" / "soft.yml"
        soft.write_text("schema_version: 1\ngate:\n  unknown_required: incomplete\n")
        self.assertEqual(self.run_gate({}, soft).returncode, 3)

    def test_policy_inside_project_is_error_2(self):
        inside = self.proj / "policy.yml"
        inside.write_text(self.policy.read_text())
        self.assertEqual(self.run_gate({}, inside).returncode, 2)


from helpers import NO_TOOLS_ENV as NO_TOOLS  # noqa: E402


class TestScannerLowConfidence(unittest.TestCase):
    """Un scanner que reportó algo (aun de baja confianza) nunca da PASS."""

    def test_low_confidence_only_is_unknown_not_pass(self):
        from sc_core.catalog import by_id
        c = by_id()["SEC-SECRETS-001"]
        f = make_finding("SEC-SECRETS-001", "t", "medium", "low", "scanner", tool="gitleaks", rule_id="generic-api-key", file="a.js", start_line=1)
        run = {"tool": "gitleaks", "version": "8.30.1", "status": "findings", "scope": "x", "notes": []}
        r = evaluate._scanner_control(c, {"secrets": run}, [f], cfg())
        self.assertEqual(r["status"], "UNKNOWN")
        self.assertIn("triage", r["reason"])

    def test_semgrep_rule_id_prefix_is_normalized(self):
        from sc_core.tools.semgrep import _rule_id
        self.assertEqual(_rule_id("Users.me.skills.security-compliance.rulesets.sc.python.eval-exec"), "sc.python.eval-exec")
        self.assertEqual(_rule_id("sc.js.eval"), "sc.js.eval")
        self.assertEqual(_rule_id("otra.regla"), "otra.regla")
