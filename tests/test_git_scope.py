"""diff / pr: staged, unstaged, untracked, renombres, repo sin commits, base inexistente, shallow, cambios durante la revisión (AC-17, AC-18)."""
import json
import os
import subprocess
import unittest
from pathlib import Path

from helpers import POSIX, TmpCase, git, load_report, make_fake, run_dir_of, run_sc

from sc_core import gitutil


def changed(rep):
    return {f["path"]: f for f in rep["snapshot"]["changed_files"]}


class TestChangedFiles(TmpCase):
    def setUp(self):
        super().setUp()
        self.p = self.project("node_basic")

    def test_staged_unstaged_untracked_rename_and_delete(self):
        (self.p / "src" / "staged.js").write_text("1")
        git(self.p, "add", "src/staged.js")
        (self.p / "src" / "index.js").write_text("// modificado\n")                  # unstaged
        (self.p / "src" / "nuevo ñandú.js").write_text("2")                          # untracked, espacios + Unicode
        git(self.p, "mv", "package-lock.json", "lock renombrado.json")                # renombre
        r = gitutil.changed_files(self.p)
        by = {f["path"]: f for f in r["files"]}
        self.assertEqual(by["src/staged.js"]["status"], "A")
        self.assertEqual(by["src/index.js"]["status"], "M")
        self.assertEqual(by["src/nuevo ñandú.js"]["status"], "?")
        self.assertEqual(by["lock renombrado.json"]["status"], "R")
        self.assertEqual(by["lock renombrado.json"]["old_path"], "package-lock.json")
        git(self.p, "rm", "-q", "-f", "package.json")
        self.assertIn("D", {f["status"] for f in gitutil.changed_files(self.p)["files"]})

    def test_repo_without_commits_treats_everything_as_new(self):
        q = self.project("node_basic", name="sin-commits", commit=False)
        r = gitutil.changed_files(q)
        self.assertTrue(r["files"])
        self.assertTrue(all(f["status"] == "A" for f in r["files"]))
        self.assertTrue(any("sin commits" in n for n in r["notes"]))

    def test_diff_command_report_documents_scope(self):
        (self.p / "src" / "index.js").write_text("// modificado\n")
        pr = run_sc("diff", "--project", str(self.p), "--output", str(self.out))
        self.assertEqual(pr.returncode, 0, pr.stderr)
        rep = load_report(self.out)
        self.assertEqual(rep["snapshot"]["scope"], "changed_files")
        self.assertEqual(list(changed(rep)), ["src/index.js"])
        self.assertTrue(any("baseline" in l for l in rep["limitations"]))
        self.assertTrue(rep["project"]["git"]["dirty"])

    def test_base_includes_branch_commits_and_uses_merge_base(self):
        git(self.p, "checkout", "-q", "-b", "feature")
        (self.p / "src" / "feature.js").write_text("2")
        git(self.p, "add", "-A")
        git(self.p, "commit", "-qm", "feature")
        (self.p / "src" / "wip.js").write_text("3")    # untracked adicional
        run_sc("diff", "--project", str(self.p), "--base", "main", "--output", str(self.out))
        rep = load_report(self.out)
        self.assertEqual(set(changed(rep)), {"src/feature.js", "src/wip.js"})
        self.assertEqual(rep["project"]["git"]["base"], "main")
        self.assertTrue(rep["project"]["git"]["merge_base"])

    def test_detached_head(self):
        sha = git(self.p, "rev-parse", "HEAD")
        git(self.p, "checkout", "-q", "--detach", sha)
        (self.p / "src" / "x.js").write_text("1")
        run_sc("diff", "--project", str(self.p), "--output", str(self.out))
        rep = load_report(self.out)
        self.assertEqual(rep["project"]["git"]["branch"], "(detached HEAD)")
        self.assertIn("src/x.js", changed(rep))

    def test_no_changes_is_an_empty_scope_and_not_pass(self):
        run_sc("diff", "--project", str(self.p), "--output", str(self.out))
        rep = load_report(self.out)
        self.assertEqual(rep["coverage"]["files_in_scope"], 0)
        self.assertEqual(rep["gate"]["status"], "INCOMPLETE")
        self.assertTrue(any("vacío" in r for r in rep["gate"]["reasons"]))

    def test_diff_requires_git_repository(self):
        q = self.project("node_basic", name="sin-git", repo=False)
        p = run_sc("diff", "--project", str(q), "--output", str(self.out))
        self.assertEqual(p.returncode, 2)
        self.assertIn("audit", p.stderr)
        a = run_sc("audit", "--project", str(q), "--output", str(self.out / "a"))
        self.assertEqual(a.returncode, 0)
        self.assertTrue(any("no es un repositorio Git" in w for w in load_report(self.out / "a")["warnings"]))


class TestBaseErrors(TmpCase):
    def test_nonexistent_base_is_an_actionable_error_not_a_made_up_diff(self):
        p = self.project("node_basic")
        r = run_sc("diff", "--project", str(p), "--base", "no-existe", "--output", str(self.out))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no existe en este clone", r.stderr)
        self.assertIn("fetch", r.stderr)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_shallow_clone_without_base_history(self):
        origin = self.project("node_basic", name="origin")
        (origin / "src" / "b.js").write_text("b")
        git(origin, "add", "-A")
        git(origin, "commit", "-qm", "second")
        (origin / "src" / "c.js").write_text("c")
        git(origin, "add", "-A")
        git(origin, "commit", "-qm", "third")
        clone = self.tmp / "clone"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}", str(clone)], check=True, capture_output=True)
        self.assertTrue(gitutil.git_info(clone)["shallow"])
        r = run_sc("diff", "--project", str(clone), "--base", "HEAD~2", "--output", str(self.out))
        self.assertEqual(r.returncode, 2)
        self.assertIn("HEAD~2", r.stderr)

    def test_pr_head_sha_must_match(self):
        p = self.project("node_basic")
        r = run_sc("pr", "--project", str(p), "--head", "f" * 40, "--output", str(self.out))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no coincide con HEAD", r.stderr)


@unittest.skipUnless(POSIX, "fake POSIX")
class TestConcurrentChange(TmpCase):
    def test_files_changing_during_review_make_result_inconclusive(self):
        p = self.project("node_basic")
        (p / "src" / "app.js").write_text("x")
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        env = {"SC_GITLEAKS_BIN": str(make_fake("gitleaks", "mutate", bin_))}
        r = run_sc("secrets", "--project", str(p), "--output", str(self.out), env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = load_report(self.out)
        self.assertFalse(rep["snapshot"]["consistent"])
        self.assertNotEqual(rep["snapshot"]["snapshot_hash"], rep["snapshot"]["snapshot_hash_end"])
        self.assertEqual(rep["gate"]["status"], "INCOMPLETE")
        self.assertTrue(any("cambiaron durante la revisión" in w for w in rep["warnings"]))


if __name__ == "__main__":
    unittest.main()
