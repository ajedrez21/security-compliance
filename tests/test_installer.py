"""Instalador y ciclo de vida: AC-02, AC-04, AC-05, AC-06, AC-24, AC-27."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

from helpers import POSIX, ROOT, SKILL, TmpCase

sys.path.insert(0, str(ROOT / "installer"))
import sc_install  # noqa: E402

from sc_core import skillcheck  # noqa: E402


def install(*argv):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = sc_install.main(list(argv))
    return rc, buf.getvalue(), err.getvalue()


class InstallerCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.home = self.tmp / "home ñ con espacios"
        self.home.mkdir()
        self.proj = self.tmp / "mi proyecto ü"
        self.proj.mkdir()
        sc_install.FAULT = None
        self.addCleanup(setattr, sc_install, "FAULT", None)

    def dest(self, client="cursor", scope="global"):
        base = {"cursor": ".cursor", "claude": ".claude", "codex": ".agents"}[client]
        return (self.home if scope == "global" else self.proj) / base / "skills" / "security-compliance"

    def args(self, client="cursor", scope="global", *extra):
        a = ["--client", client, "--scope", scope, "--home", str(self.home)]
        if scope == "project":
            a += ["--project-path", str(self.proj)]
        return a + list(extra)

    def snapshot(self, d: Path):
        return {p.relative_to(d).as_posix(): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}

    def newer_source(self, version="1.0.1") -> Path:
        src = self.tmp / "src-nueva" / "security-compliance"
        shutil.copytree(SKILL, src, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (src / "VERSION").write_text(version + "\n")
        (src / "references" / "nuevo.md").write_text("# nuevo\n")
        return src


class TestInstallPaths(InstallerCase):
    def test_all_clients_and_scopes_with_spaces_and_unicode(self):
        """AC-04 + AC-02: rutas temporales con espacios/Unicode, sin administrador; paquete válido y ejecutable ya instalado."""
        for client in ("cursor", "claude", "codex"):
            for scope in ("global", "project"):
                with self.subTest(client=client, scope=scope):
                    rc, out, err = install(*self.args(client, scope))
                    self.assertEqual(rc, 0, err)
                    d = self.dest(client, scope)
                    self.assertTrue((d / "SKILL.md").is_file())
                    chk = skillcheck.validate_package(d)
                    self.assertTrue(chk["ok"], chk["errors"])
                    self.assertIn("NO comprobado", out)            # descubrimiento ≠ archivos instalados
                    self.assertIn("primer comando", out)
                    p = subprocess.run([sys.executable, str(d / "scripts" / "sc.py"), "help"], capture_output=True, text=True,
                                       cwd=str(self.tmp), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                    self.assertEqual(p.returncode, 0)

    def test_installed_copy_is_self_contained(self):
        install(*self.args("cursor"))
        d = self.dest("cursor")
        moved = self.tmp / "otro lugar"
        shutil.copytree(d, moved)
        shutil.rmtree(d)           # ya no existe el destino original
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "SC_SEMGREP_BIN": "/x", "SC_GITLEAKS_BIN": "/x", "SC_OSV_BIN": "/x"}
        proj = self.tmp / "p"
        proj.mkdir()
        (proj / "a.txt").write_text("hola")
        r = subprocess.run([sys.executable, str(moved / "scripts" / "sc.py"), "audit", "--project", str(proj), "--output", str(self.tmp / "o")],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(str(ROOT), (moved / ".sc-install.json").read_text())

    def test_missing_selection_fails_with_instructions_when_non_interactive(self):
        rc, _, err = install("--home", str(self.home), "--non-interactive")
        self.assertEqual(rc, 2)
        self.assertIn("--client", err)
        rc, _, err = install("--client", "cursor", "--scope", "project", "--home", str(self.home), "--non-interactive")
        self.assertEqual(rc, 2)
        self.assertIn("--project-path", err)

    def test_dry_run_writes_nothing(self):
        rc, out, _ = install(*self.args("claude", "global", "--dry-run"))
        self.assertEqual(rc, 0)
        self.assertIn("dry-run", out)
        self.assertEqual(list(self.home.iterdir()), [])


class TestIdempotenceUpdateRollback(InstallerCase):
    def test_reinstall_is_idempotent(self):
        install(*self.args("cursor"))
        before = self.snapshot(self.dest())
        rc, out, _ = install(*self.args("cursor"))
        self.assertEqual(rc, 0)
        self.assertIn("ya instalado", out)
        self.assertEqual(self.snapshot(self.dest()), before)

    def test_update_requires_flag_then_updates_atomically(self):
        install(*self.args("cursor"))
        new = self.newer_source()
        rc, _, err = install(*self.args("cursor"), "--source", str(new))
        self.assertEqual(rc, 2)
        self.assertIn("--update", err)
        rc, out, err = install(*self.args("cursor"), "--update", "--source", str(new))
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.dest() / "VERSION").read_text().strip(), "1.0.1")
        self.assertTrue((self.dest() / "references" / "nuevo.md").is_file())
        self.assertEqual(json.loads((self.dest() / ".sc-install.json").read_text())["version"], "1.0.1")
        leftovers = [p.name for p in self.dest().parent.iterdir() if p.name.startswith(".security-compliance.tmp")]
        self.assertEqual(leftovers, [])

    def test_failed_update_rolls_back_and_preserves_other_skills(self):
        """AC-05 + AC-06."""
        other = self.home / ".cursor" / "skills" / "otro-skill"
        other.mkdir(parents=True)
        (other / "SKILL.md").write_text("---\nname: otro-skill\ndescription: x\n---\n")
        install(*self.args("cursor"))
        before = self.snapshot(self.dest())
        sc_install.FAULT = "after_backup"
        rc, out, err = install(*self.args("cursor"), "--update", "--source", str(self.newer_source()))
        self.assertEqual(rc, 2)
        self.assertIn("rollback", out)
        self.assertEqual(self.snapshot(self.dest()), before)           # instalación previa intacta
        self.assertEqual((self.dest() / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual((other / "SKILL.md").read_text(), "---\nname: otro-skill\ndescription: x\n---\n")
        self.assertEqual([p.name for p in self.dest().parent.iterdir() if p.name.startswith(".security-compliance.tmp")], [])

    def test_local_modifications_block_update_unless_forced_and_are_backed_up(self):
        install(*self.args("cursor"))
        (self.dest() / "references" / "workflow.md").write_text("# mi cambio local\n")
        new = self.newer_source()
        rc, _, err = install(*self.args("cursor"), "--update", "--source", str(new))
        self.assertEqual(rc, 2)
        self.assertIn("modificados localmente", err)
        self.assertEqual((self.dest() / "references" / "workflow.md").read_text(), "# mi cambio local\n")
        rc, out, _ = install(*self.args("cursor"), "--update", "--force", "--source", str(new))
        self.assertEqual(rc, 0)
        backups = list((self.home / ".security-compliance" / "backups").glob("cursor-global-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "references" / "workflow.md").read_text(), "# mi cambio local\n")

    def test_foreign_skill_with_same_name_is_not_overwritten(self):
        d = self.dest()
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text("---\nname: security-compliance\ndescription: ajeno\n---\n# de otra persona\n")
        rc, _, err = install(*self.args("cursor"))
        self.assertEqual(rc, 2)
        self.assertIn("NO fue instalado por este instalador", err)
        self.assertIn("de otra persona", (d / "SKILL.md").read_text())
        rc, out, _ = install(*self.args("cursor"), "--force")
        self.assertEqual(rc, 0)
        backups = list((self.home / ".security-compliance" / "backups").glob("*"))
        self.assertIn("de otra persona", (backups[0] / "SKILL.md").read_text())


class TestUninstallAndNonInterference(InstallerCase):
    def test_uninstall_removes_only_own_files_and_keeps_shared_configuration(self):
        """AC-06 + AC-24."""
        shared = {
            self.home / ".cursor" / "mcp.json": '{"mcpServers":{}}',
            self.home / ".claude" / "settings.json": '{"hooks":{}}',
            self.home / ".cursor" / "skills" / "otro" / "SKILL.md": "---\nname: otro\ndescription: x\n---\n",
            self.proj / "AGENTS.md": "# reglas del equipo\n",
            self.proj / "CLAUDE.md": "# memoria\n",
            self.proj / ".gitignore": "node_modules\n",
        }
        for p, c in shared.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(c)
        for client, scope in (("cursor", "global"), ("claude", "global"), ("claude", "project")):
            self.assertEqual(install(*self.args(client, scope))[0], 0)
        for p, c in shared.items():      # la instalación no toca nada ajeno
            self.assertEqual(p.read_text(), c, p)
        for client, scope in (("cursor", "global"), ("claude", "global"), ("claude", "project")):
            rc, out, _ = install(*self.args(client, scope, "--uninstall"))
            self.assertEqual(rc, 0)
            self.assertFalse(self.dest(client, scope).exists())
        for p, c in shared.items():
            self.assertEqual(p.read_text(), c, p)

    def test_uninstall_preserves_modified_and_unknown_files(self):
        install(*self.args("cursor"))
        d = self.dest()
        (d / "references" / "workflow.md").write_text("# editado\n")
        (d / "mis-notas.txt").write_text("notas")
        rc, out, _ = install(*self.args("cursor", "global", "--uninstall"))
        self.assertEqual(rc, 0)
        self.assertTrue((d / "references" / "workflow.md").is_file())
        self.assertTrue((d / "mis-notas.txt").is_file())
        self.assertIn("preservados", out)
        self.assertFalse((d / "SKILL.md").exists())

    def test_uninstall_refuses_foreign_directory(self):
        d = self.dest()
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text("ajeno")
        rc, _, err = install(*self.args("cursor", "global", "--uninstall"))
        self.assertEqual(rc, 2)
        self.assertEqual((d / "SKILL.md").read_text(), "ajeno")

    def test_install_does_not_enable_hooks_or_mandatory_rules(self):
        """AC-24."""
        for client in ("cursor", "claude", "codex"):
            install(*self.args(client, "project"))
        found = sorted(p.relative_to(self.proj).as_posix() for p in self.proj.rglob("*") if p.is_file())
        forbidden = [f for f in found if any(k in f.lower() for k in ("hooks", "rules/", ".mdc", "agents.md", "claude.md", "settings.json", "hooks.json"))]
        self.assertEqual(forbidden, [])
        self.assertEqual({p.name for p in self.proj.iterdir()}, {".cursor", ".claude", ".agents"})
        text = "\n".join(p.read_text(errors="ignore") for p in self.proj.rglob("SKILL.md"))
        self.assertNotIn("alwaysApply", text)


class TestInvocationMode(InstallerCase):
    def test_manual_uses_each_clients_real_mechanism(self):
        for client in ("cursor", "claude"):
            install(*self.args(client, "global", "--invocation", "manual"))
            fm, _ = skillcheck.split_frontmatter((self.dest(client) / "SKILL.md").read_text())
            self.assertIs(fm["disable-model-invocation"], True)
            self.assertTrue(skillcheck.validate_package(self.dest(client))["ok"])
        install(*self.args("codex", "global", "--invocation", "manual"))
        self.assertIn("allow_implicit_invocation: false", (self.dest("codex") / "agents" / "openai.yaml").read_text())

    def test_assisted_has_no_manual_flags_and_can_switch_with_update(self):
        install(*self.args("cursor"))
        self.assertNotIn("disable-model-invocation", (self.dest() / "SKILL.md").read_text())
        rc, _, err = install(*self.args("cursor", "global", "--invocation", "manual"))
        self.assertEqual(rc, 2)                                   # requiere --update
        self.assertEqual(install(*self.args("cursor", "global", "--invocation", "manual", "--update"))[0], 0)
        self.assertIn("disable-model-invocation: true", (self.dest() / "SKILL.md").read_text())


class TestDuplicates(InstallerCase):
    def test_duplicate_installs_are_reported_not_deleted(self):
        install(*self.args("cursor"))
        rc, out, _ = install(*self.args("codex"))
        self.assertEqual(rc, 0)
        self.assertIn("OTRAS instalaciones", out)
        self.assertIn("Codex", out)
        self.assertTrue(self.dest("cursor").exists() and self.dest("codex").exists())


@unittest.skipUnless(POSIX, "install.sh requiere POSIX")
class TestWrapperAndPackage(InstallerCase):
    def test_install_sh_wrapper(self):
        r = subprocess.run([str(ROOT / "install.sh"), "--client", "cursor", "--scope", "global", "--home", str(self.home)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.dest() / "SKILL.md").is_file())

    def test_local_package_installs_from_another_location(self):
        """AC-27: el zip se instala sin el checkout de desarrollo."""
        out = self.tmp / "dist"
        b = subprocess.run([sys.executable, str(ROOT / "tools" / "build_package.py"), "--out", str(out)], capture_output=True, text=True)
        self.assertEqual(b.returncode, 0, b.stderr)
        z = next(out.glob("security-compliance-skill-*.zip"))
        manifest = json.loads(next(out.glob("*.manifest.json")).read_text())
        import hashlib
        self.assertEqual(hashlib.sha256(z.read_bytes()).hexdigest(), manifest["archive_sha256"])
        where = self.tmp / "descomprimido ñ"
        with zipfile.ZipFile(z) as zf:
            zf.extractall(where)
        pkg = next(where.iterdir())
        for rel, digest in json.loads((pkg / "MANIFEST.json").read_text())["files"].items():
            self.assertEqual(hashlib.sha256((pkg / rel).read_bytes()).hexdigest(), digest, rel)
        self.assertFalse((pkg / "tests").exists())
        r = subprocess.run(["sh", str(pkg / "install.sh"), "--client", "claude", "--scope", "global", "--home", str(self.home)],
                           capture_output=True, text=True, cwd=str(self.tmp))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(skillcheck.validate_package(self.dest("claude"))["ok"])
        self.assertNotIn(str(ROOT), (self.dest("claude") / ".sc-install.json").read_text())
        # determinismo del paquete
        out2 = self.tmp / "dist2"
        subprocess.run([sys.executable, str(ROOT / "tools" / "build_package.py"), "--out", str(out2)], capture_output=True, check=True)
        self.assertEqual(z.read_bytes(), next(out2.glob("*.zip")).read_bytes())


if __name__ == "__main__":
    unittest.main()
