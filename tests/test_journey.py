"""Recorrido completo desde una copia INSTALADA: instalar → doctor → init → diff/audit → reporte → actualizar → desinstalar."""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import NO_TOOLS_ENV, ROOT, SKILL, TmpCase, git

INSTALLER = ROOT / "installer" / "sc_install.py"


class TestJourney(TmpCase):
    def sh(self, *args, cwd=None):
        env = {**os.environ, **NO_TOOLS_ENV, "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, cwd=cwd, env=env)

    def test_full_journey(self):
        home = self.tmp / "home de usuario ñ"
        home.mkdir()
        proj = self.project("node_basic", name="mi app ü")
        # 1) instalar (proyecto sintético en alcance 'project' y global)
        r = self.sh(INSTALLER, "--client", "cursor", "--scope", "global", "--home", home)
        self.assertEqual(r.returncode, 0, r.stderr)
        installed = home / ".cursor" / "skills" / "security-compliance"
        sc = installed / "scripts" / "sc.py"
        # 2) doctor desde la copia instalada
        d = self.sh(sc, "doctor", "--project", proj, "--json")
        self.assertEqual(d.returncode, 0, d.stderr)
        checks = {c["name"]: c for c in json.loads(d.stdout)["checks"]}
        self.assertEqual(checks["install_files"]["status"], "ok")          # archivos instalados correctamente
        self.assertEqual(checks["client_discovery"]["status"], "unverified")  # descubrimiento NO comprobado
        # 3) init
        self.assertEqual(self.sh(sc, "init", "--project", proj, "--non-interactive").returncode, 0)
        # 4) diff / audit
        (proj / "src" / "nuevo.js").write_text("module.exports = 1;\n")
        out = self.tmp / "salida"
        self.assertEqual(self.sh(sc, "diff", "--project", proj, "--output", out).returncode, 0)
        self.assertEqual(self.sh(sc, "audit", "--project", proj, "--output", out).returncode, 0)
        runs = sorted(p for p in out.iterdir() if p.is_dir())
        self.assertEqual(len(runs), 2)
        # 5) reporte
        rep = self.sh(sc, "report", "--run", runs[0])
        self.assertEqual(rep.returncode, 0)
        self.assertIn("Revisión de controles técnicos", rep.stdout)
        # 6) actualización (versión nueva) conservando la instalación hasta que termina
        new = self.tmp / "nueva" / "security-compliance"
        shutil.copytree(SKILL, new, ignore=shutil.ignore_patterns("__pycache__"))
        (new / "VERSION").write_text("1.0.1\n")
        up = self.sh(INSTALLER, "--client", "cursor", "--scope", "global", "--home", home, "--update", "--source", new)
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertEqual((installed / "VERSION").read_text().strip(), "1.0.1")
        self.assertEqual(self.sh(sc, "help").returncode, 0)
        # 7) desinstalación
        un = self.sh(INSTALLER, "--client", "cursor", "--scope", "global", "--home", home, "--uninstall")
        self.assertEqual(un.returncode, 0, un.stderr)
        self.assertFalse(installed.exists())
        self.assertTrue((proj / ".security-compliance.yml").exists())        # los datos del proyecto no se tocan
        self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
