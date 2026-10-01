"""Evidencia de PR/CI y revisión del agente: AC-13..AC-16, AC-23."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helpers import FIXTURES, TmpCase, git, load_report, run_dir_of, run_sc, SKILL

from sc_core import schema as sch

REPO = "org/mi-repo"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.proj = self.project("node_basic")
        (self.proj / ".security-compliance.yml").write_text(
            f"schema_version: 1\nproject:\n  repo: {REPO}\n  sox_scope: 'yes'\n")
        git(self.proj, "add", "-A")
        git(self.proj, "commit", "-qm", "config")
        self.head = git(self.proj, "rev-parse", "HEAD")
        self.now = datetime.now(timezone.utc) + timedelta(minutes=1)

    def item(self, id_, type_, details, sha=None, ts=None, prov="user_supplied", **kw):
        d = {"id": id_, "type": type_, "provenance": prov, "source": {"system": "github", "ref": id_},
             "subject": id_, "timestamp": iso(ts or self.now), "details": details}
        if sha is not False:
            d["commit_sha"] = sha or self.head
        d.update(kw)
        return d

    def bundle(self, items, repo=REPO, pr_head=None, name="ev.json"):
        doc = {"schema_version": 1, "project": {"repo": repo}, "collected_at": iso(self.now), "items": items,
               "collector": {"name": "test", "method": "sintético"}}
        if pr_head:
            doc["pull_request"] = {"number": 1, "head_sha": pr_head}
        p = self.tmp / name
        p.write_text(json.dumps(doc))
        return p

    def sox(self, ev_path=None, *extra, command="sox", out=None):
        args = [command, "--project", str(self.proj), "--output", str(out or self.out)]
        if ev_path:
            args += ["--evidence", str(ev_path)]
        p = run_sc(*args, *extra)
        self.assertEqual(p.returncode, 0, p.stderr)
        return load_report(out or self.out)

    @staticmethod
    def st(rep, cid):
        return next(c for c in rep["controls"] if c["control_id"] == cid)


class TestItgcEvidence(EvidenceCase):
    def test_no_evidence_is_unknown_and_never_pass(self):
        rep = self.sox()
        for c in rep["controls"]:
            if c["domain"] == "itgc" and c["method"] != "agent":
                self.assertEqual(c["status"], "UNKNOWN", c["control_id"])
            if c["domain"] == "itgc" and c["method"] == "agent":   # ITGC-CHG-006 espera la revisión del agente
                self.assertIn(c["status"], ("UNKNOWN", "NOT_RUN"))
        self.assertEqual(rep["gate"]["status"], "INCOMPLETE")

    def test_workflow_file_is_not_a_successful_run(self):
        wf = self.proj / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("name: ci\non: push\njobs: {}\n")
        git(self.proj, "add", "-A")
        git(self.proj, "commit", "-qm", "wf")
        rep = self.sox()
        c = self.st(rep, "ITGC-CHG-003")
        self.assertEqual(c["status"], "UNKNOWN")
        self.assertIn("no prueba que se ejecutó", c["reason"])

    def test_sox_scope_unknown_is_unknown_and_no_is_not_applicable(self):
        (self.proj / ".security-compliance.yml").write_text(f"schema_version: 1\nproject:\n  repo: {REPO}\n")
        rep = self.sox()
        self.assertEqual(self.st(rep, "ITGC-CHG-002")["status"], "UNKNOWN")
        self.assertIn("Alcance SOX no definido", self.st(rep, "ITGC-CHG-002")["reason"])
        (self.proj / ".security-compliance.yml").write_text(f"schema_version: 1\nproject:\n  repo: {REPO}\n  sox_scope: 'no'\n")
        rep = self.sox(out=self.tmp / "out2")
        self.assertEqual(self.st(rep, "ITGC-CHG-002")["status"], "NOT_APPLICABLE")

    def test_valid_evidence_passes_but_is_flagged_unverified(self):
        ev = self.bundle([
            self.item("pr", "pr_metadata", {"author": "alice", "linked_tickets": ["T-1"]}),
            self.item("ap", "pr_approval", {"author": "alice", "approvals": [{"actor": "bob", "state": "approved", "commit_sha": self.head}]}),
            self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"})], pr_head=self.head)
        rep = self.sox(ev)
        for cid in ("ITGC-CHG-001", "ITGC-CHG-002", "ITGC-CHG-003"):
            self.assertEqual(self.st(rep, cid)["status"], "PASS", cid)
        self.assertTrue(rep["evidence"]["provided"])
        self.assertTrue(any("no se verificó de forma independiente" in w for w in rep["warnings"]))
        self.assertEqual({i["provenance"] for i in rep["evidence"]["items"]}, {"user_supplied"})

    def test_self_approval_fails_and_stale_approval_is_unknown(self):
        ev = self.bundle([self.item("ap", "pr_approval", {"author": "alice", "approvals": [{"actor": "alice", "state": "approved"}]})])
        self.assertEqual(self.st(self.sox(ev), "ITGC-CHG-002")["status"], "FAIL")
        ev = self.bundle([self.item("ap", "pr_approval", {"author": "alice", "approvals": [
            {"actor": "bob", "state": "approved", "commit_sha": "deadbeefdeadbeef"}]})], name="e2.json")
        c = self.st(self.sox(ev, out=self.tmp / "o2"), "ITGC-CHG-002")
        self.assertEqual(c["status"], "UNKNOWN")
        self.assertIn("obsoletas", c["reason"])

    def test_failed_ci_fails_control(self):
        ev = self.bundle([self.item("ci", "ci_run", {"kind": "test", "conclusion": "failure"})])
        self.assertEqual(self.st(self.sox(ev), "ITGC-CHG-003")["status"], "FAIL")

    def test_branch_protection_bypass_fails(self):
        ev = self.bundle([self.item("bp", "branch_protection", {"required_approvals": 1, "enforce_admins": True, "bypass_actors": ["admin"]}, sha=False)])
        c = self.st(self.sox(ev), "ITGC-CHG-004")
        self.assertEqual(c["status"], "FAIL")
        self.assertIn("bypass", c["reason"])


class TestEvidenceValidation(EvidenceCase):
    def one(self, items, **kw):
        rep = self.sox(self.bundle(items, **kw))
        return rep, rep["evidence"]["items"]

    def test_other_repo_is_rejected(self):
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"})], repo="otra/org-repo")
        self.assertEqual(items[0]["validation"]["status"], "rejected")
        self.assertNotEqual(self.st(rep, "ITGC-CHG-003")["status"], "PASS")

    def test_other_sha_is_non_conclusive(self):
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"}, sha="1" * 40)])
        self.assertEqual(items[0]["validation"]["status"], "non_conclusive")
        self.assertEqual(self.st(rep, "ITGC-CHG-003")["status"], "UNKNOWN")

    def test_evidence_older_than_the_commit_is_non_conclusive(self):
        old = datetime.now(timezone.utc) - timedelta(days=30)
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"}, ts=old)])
        self.assertEqual(items[0]["validation"]["status"], "non_conclusive")
        self.assertIn("anterior", items[0]["validation"]["reason"])

    def test_pr_head_mismatch_makes_all_non_conclusive(self):
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"})], pr_head="2" * 40)
        self.assertEqual(items[0]["validation"]["status"], "non_conclusive")
        self.assertTrue(any("head SHA" in w for w in rep["warnings"]))

    def test_local_changes_not_covered_by_commit(self):
        (self.proj / "src" / "index.js").write_text("// cambio local sin commit\n")
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"})])
        self.assertEqual(items[0]["validation"]["status"], "non_conclusive")
        self.assertIn("cambios locales", items[0]["validation"]["reason"])

    def test_provider_verified_claim_is_downgraded_and_reported(self):
        rep, items = self.one([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"}, prov="provider_verified",
                                         source={"system": "github", "ref": "https://github.com/org/mi-repo/actions/runs/1"})])
        self.assertEqual(items[0]["provenance"], "user_supplied")
        self.assertEqual(items[0]["provenance_declared"], "provider_verified")
        md = (run_dir_of(self.out) / "report.md").read_text()
        self.assertIn("declarada provider", md)
        self.assertEqual(self.st(rep, "ITGC-CHG-003")["provenance"], ["user_supplied"])

    def test_schema_invalid_evidence_is_exit_2(self):
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"schema_version": 1, "items": []}))
        p = run_sc("sox", "--project", str(self.proj), "--output", str(self.out), "--evidence", str(bad))
        self.assertEqual(p.returncode, 2)
        self.assertIn("schema", p.stderr)

    def test_untrusted_user_evidence_under_policy(self):
        ev = self.bundle([self.item("ci", "ci_run", {"kind": "test", "conclusion": "success"})])
        pol = self.tmp / "pol"
        pol.mkdir()
        (pol / "p.yml").write_text("schema_version: 1\nproject:\n  sox_scope: 'yes'\n  repo: org/mi-repo\n")
        p = run_sc("sox", "--project", str(self.proj), "--output", str(self.out), "--evidence", str(ev),
                   "--mode", "enforce", "--policy", str(pol / "p.yml"))
        self.assertEqual(p.returncode, 3)
        self.assertEqual(self.st(load_report(self.out), "ITGC-CHG-003")["status"], "UNKNOWN")


class ReviewCase(TmpCase):
    def prepare(self, fixture="nest_global_guard"):
        self.proj = self.project(fixture)
        p = run_sc("security", "--project", str(self.proj), "--output", str(self.out))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.first = load_report(self.out)
        return self.first["snapshot"]["snapshot_hash"]

    def review(self, snap, results, findings=(), name="review.json", **top):
        doc = {"schema_version": 1, "reviewer": {"client": "test-agent"}, "created_at": "2026-09-30T12:00:00Z",
               "snapshot": {"snapshot_hash": snap}, "control_results": results, "findings": list(findings)}
        doc.update(top)
        p = self.tmp / name
        p.write_text(json.dumps(doc))
        return p

    def rerun(self, review, out="out2", *extra):
        o = self.tmp / out
        p = run_sc("security", "--project", str(self.proj), "--output", str(o), "--review", str(review), *extra)
        self.assertEqual(p.returncode, 0, p.stderr)
        return load_report(o)

    @staticmethod
    def st(rep, cid):
        return next(c for c in rep["controls"] if c["control_id"] == cid)


class TestAgentReview(ReviewCase):
    def test_runner_never_flags_global_guard_route_as_vulnerable(self):
        """AC-13 (lado runner): sin revisión, authz queda NOT_RUN y sin hallazgos de autorización."""
        self.prepare()
        self.assertEqual(self.st(self.first, "SEC-AUTHZ-001")["status"], "NOT_RUN")
        self.assertFalse([f for f in self.first["findings"] if f["control_id"].startswith("SEC-AUTHZ")])

    def test_pass_requires_files_examined_and_keeps_agent_provenance(self):
        snap = self.prepare()
        good = {"control_id": "SEC-AUTHZ-001", "status": "PASS", "rationale": "APP_GUARD global cubre las rutas; @Public explícito.",
                "files_examined": ["src/app.module.ts", "src/users.controller.ts"]}
        rep = self.rerun(self.review(snap, [good]))
        c = self.st(rep, "SEC-AUTHZ-001")
        self.assertEqual((c["status"], c["source"], c["provenance"]), ("PASS", "agent_review", ["agent_review"]))
        self.assertTrue(rep["agent_review"]["accepted"])
        self.assertEqual(rep["agent_review"]["provenance"], "agent_review")
        bad = dict(good, files_examined=[])
        rep = self.rerun(self.review(snap, [bad]), "out3")
        self.assertEqual(self.st(rep, "SEC-AUTHZ-001")["status"], "NOT_RUN")
        self.assertTrue(any("files_examined" in r["reason"] for r in rep["agent_review"]["rejected_entries"]))

    def test_fail_requires_a_real_finding_and_invented_files_are_rejected(self):
        snap = self.prepare()
        fail = {"control_id": "SEC-INPUT-001", "status": "FAIL", "rationale": "Consulta concatenada con entrada del request.",
                "finding_refs": ["x"]}
        rep = self.rerun(self.review(snap, [fail]))
        self.assertNotEqual(self.st(rep, "SEC-INPUT-001")["status"], "FAIL")
        finding = {"ref": "x", "control_id": "SEC-INPUT-001", "title": "SQL concatenado", "severity": "high", "confidence": "high",
                   "file": "src/no-existe.ts", "start_line": 3, "description": "Hallazgo sobre un archivo inexistente."}
        rep = self.rerun(self.review(snap, [fail], [finding]), "out3")
        self.assertEqual([f for f in rep["findings"] if f["origin"] == "agent_review"], [])
        self.assertTrue(any("snapshot" in r["reason"] for r in rep["agent_review"]["rejected_entries"]))
        finding.update(file="src/users.controller.ts", start_line=9999)
        rep = self.rerun(self.review(snap, [fail], [finding]), "out4")
        self.assertTrue(any("excede" in r["reason"] for r in rep["agent_review"]["rejected_entries"]))
        finding.update(start_line=7)
        rep = self.rerun(self.review(snap, [fail], [finding]), "out5")
        f = next(x for x in rep["findings"] if x["control_id"] == "SEC-INPUT-001")
        self.assertEqual((f["origin"], f["tool"]), ("agent_review", "test-agent"))
        self.assertEqual(self.st(rep, "SEC-INPUT-001")["status"], "FAIL")
        self.assertEqual(rep["gate"]["status"], "BLOCKED")

    def test_review_for_other_snapshot_is_rejected(self):
        snap = self.prepare()
        res = [{"control_id": "SEC-AUTHZ-001", "status": "PASS", "rationale": "Revisión aparentemente correcta.", "files_examined": ["src/app.module.ts"]}]
        (self.proj / "src" / "users.controller.ts").write_text("// el código cambió después de la revisión\n")
        rep = self.rerun(self.review(snap, res))
        self.assertFalse(rep["agent_review"]["accepted"])
        self.assertIn("snapshot", rep["agent_review"]["reason"])
        self.assertNotEqual(self.st(rep, "SEC-AUTHZ-001")["status"], "PASS")

    def test_review_cannot_resolve_scanner_or_evidence_controls(self):
        snap = self.prepare()
        res = [{"control_id": "SEC-SECRETS-001", "status": "PASS", "rationale": "El agente afirma que no hay secretos.", "files_examined": ["src/app.module.ts"]},
               {"control_id": "ITGC-CHG-002", "status": "PASS", "rationale": "El agente afirma que hubo aprobación.", "files_examined": ["src/app.module.ts"]}]
        rep = self.rerun(self.review(snap, res))
        self.assertEqual(self.st(rep, "SEC-SECRETS-001")["status"], "NOT_RUN")
        reasons = " | ".join(r["reason"] for r in rep["agent_review"]["rejected_entries"])
        self.assertEqual(len(rep["agent_review"]["rejected_entries"]), 2)
        self.assertIn("solo se resuelve con scanner/evidencia", reasons)     # SEC-SECRETS-001
        self.assertIn("no seleccionado", reasons)                             # ITGC no está en 'security'

    def test_enforce_distrusts_review_unless_policy_allows(self):
        snap = self.prepare()
        res = [{"control_id": "SEC-AUTHZ-001", "status": "PASS", "rationale": "Guard global verificado manualmente.", "files_examined": ["src/app.module.ts"]}]
        rv = self.review(snap, res)
        pol = self.tmp / "pol"
        pol.mkdir()
        (pol / "p.yml").write_text("schema_version: 1\n")
        o = self.tmp / "o"
        p = run_sc("security", "--project", str(self.proj), "--output", str(o), "--review", str(rv), "--mode", "enforce", "--policy", str(pol / "p.yml"))
        self.assertEqual(p.returncode, 3)
        rep = load_report(o)
        self.assertFalse(rep["agent_review"]["accepted"])
        (pol / "p.yml").write_text("schema_version: 1\ntrust:\n  agent_review: true\n")
        o2 = self.tmp / "o2"
        run_sc("security", "--project", str(self.proj), "--output", str(o2), "--review", str(rv), "--mode", "enforce", "--policy", str(pol / "p.yml"))
        self.assertTrue(load_report(o2)["agent_review"]["accepted"])

    def test_schema_files_validate_shipped_examples(self):
        for ex, sc in (("review.example.json", "review"), ("evidence.example.json", "evidence")):
            data = json.loads((SKILL / "assets" / ex).read_text())
            self.assertEqual(sch.validate(data, sch.load_schema(SKILL / "schemas" / f"{sc}.schema.json")), [])


class TestPromptInjection(TmpCase):
    """AC-23: instrucciones maliciosas en un README son DATOS."""

    def test_malicious_readme_changes_nothing(self):
        proj = self.project("injection_readme")
        clean = self.project("injection_readme", name="limpio")
        (clean / "README.md").write_text("# Proyecto de demostración\n")
        git(clean, "add", "-A")
        git(clean, "commit", "-qm", "r")
        run_sc("audit", "--project", str(proj), "--output", str(self.out / "a"))
        run_sc("audit", "--project", str(clean), "--output", str(self.out / "b"))
        a, b = load_report(self.out / "a"), load_report(self.out / "b")
        st = lambda r: {c["control_id"]: c["status"] for c in r["controls"]}
        self.assertEqual(st(a), st(b))                          # mismos estados de control
        self.assertEqual(a["gate"]["status"], b["gate"]["status"])
        self.assertEqual(a["gate"]["status"], "INCOMPLETE")
        self.assertEqual(a["config"]["hash"], b["config"]["hash"])    # la política no cambia
        self.assertEqual({s["tool"] for s in a["scanners"]}, {s["tool"] for s in b["scanners"]})
        self.assertTrue(any("dirigido a agentes" in w for w in a["warnings"]))
        self.assertFalse(any("dirigido a agentes" in w for w in b["warnings"]))
        self.assertEqual([f["rule_id"] for f in a["findings"]], [f["rule_id"] for f in b["findings"]])


if __name__ == "__main__":
    unittest.main()
