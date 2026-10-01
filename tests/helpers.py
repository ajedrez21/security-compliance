"""Utilidades de prueba: proyectos sintéticos, git, binarios simulados (fakes) y ejecución del CLI."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "security-compliance"
SC = SKILL / "scripts" / "sc.py"
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(SKILL / "scripts"))

POSIX = os.name == "posix"
# Secreto sintético (formato AKIA + 16 caracteres); se arma en runtime para no versionarlo literal.
SYNTHETIC_SECRET = "AKIA" + "ZQTESTSYNTH0123X"
assert len(SYNTHETIC_SECRET) == 20

NO_TOOLS_ENV = {"SC_SEMGREP_BIN": "/nonexistent/semgrep", "SC_GITLEAKS_BIN": "/nonexistent/gitleaks",
                "SC_OSV_BIN": "/nonexistent/osv-scanner"}


def git(cwd: Path, *args: str, check: bool = True) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    p = subprocess.run(["git", "-c", "init.defaultBranch=main", *args], cwd=cwd, capture_output=True, text=True, env=env)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {args} falló: {p.stderr}")
    return p.stdout.strip()


def copy_fixture(name: str, dest: Path) -> Path:
    shutil.copytree(FIXTURES / name, dest)
    return dest


def init_repo(path: Path, commit: bool = True) -> Path:
    git(path, "init", "-q", ".")
    if commit:
        git(path, "add", "-A")
        git(path, "commit", "-qm", "init")
    return path


def run_sc(*args: str, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, tools: bool = False,
           timeout: int = 120) -> subprocess.CompletedProcess:
    e = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if not tools:
        e.update(NO_TOOLS_ENV)
    e.update(env or {})
    return subprocess.run([sys.executable, str(SC), *args], capture_output=True, text=True, cwd=cwd, env=e,
                          timeout=timeout)


def load_report(proc_or_dir) -> Dict[str, Any]:
    """Carga report.json de la última ejecución en un directorio de salida."""
    out = Path(proc_or_dir)
    return json.loads((run_dir_of(out) / "report.json").read_text(encoding="utf-8"))


def run_dir_of(out: Path) -> Path:
    return sorted((p for p in out.iterdir() if p.is_dir()), key=lambda p: (p.name[:16], p.stat().st_mtime_ns))[-1]


def all_text(path: Path) -> str:
    chunks = []
    for p in path.rglob("*"):
        if p.is_file():
            chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


# ------------------------------------------------------------------ binarios simulados (POSIX)

FAKE_GITLEAKS = '''#!{py}
import json, sys, time, os
a = sys.argv[1:]
mode = "{mode}"
if a[:1] == ["version"]:
    print("8.28.0"); sys.exit(0)
if a[:2] == ["dir", "--help"]:
    print("Usage: gitleaks dir [flags]\\n  --gitleaks-ignore-path string\\n  --redact\\n"); sys.exit(0)
if mode == "timeout":
    time.sleep(60)
rp = a[a.index("--report-path") + 1]
if mode == "error":
    sys.stderr.write("fatal: algo falló"); sys.exit(1)
if mode == "invalid":
    open(rp, "w").write("{{no es json"); sys.exit(2)
if mode == "mutate":
    open(os.path.join(a[1], "mutated-during-scan.txt"), "w").write("x"); open(rp, "w").write("[]"); sys.exit(0)
if mode == "findings":
    secret = "{secret}"
    open(rp, "w").write(json.dumps([{{"RuleID": "aws-access-token", "Description": "AWS Access Key",
        "File": os.path.join(a[1], "src", "app.js"), "StartLine": 1, "EndLine": 1, "Secret": secret,
        "Match": "const key = '" + secret + "'", "Fingerprint": "src/app.js:aws-access-token:1"}}]))
    sys.exit(2)
open(rp, "w").write("[]"); sys.exit(0)
'''

FAKE_SEMGREP = '''#!{py}
import json, sys, time
a = sys.argv[1:]
mode = "{mode}"
if a[:1] == ["--version"]:
    print("1.99.0"); sys.exit(0)
if a[:2] == ["scan", "--help"]:
    print("--x-ignore-semgrepignore-files"); sys.exit(0)
if mode == "timeout":
    time.sleep(60)
if mode == "error":
    sys.stderr.write("boom"); sys.exit(2)
if mode == "invalid":
    print("<html>"); sys.exit(0)
res = []
if mode == "findings":
    res = [{{"check_id": "sc.python.eval-exec", "path": "app/main.py", "start": {{"line": 3}}, "end": {{"line": 3}},
            "extra": {{"severity": "ERROR", "message": "eval con datos externos", "metadata": {{"cwe": ["CWE-95"], "confidence": "HIGH"}}}}}}]
print(json.dumps({{"results": res, "errors": [{{"message": "parse"}}] if mode == "partial" else []}}))
'''

FAKE_OSV = '''#!{py}
import json, sys, time
a = sys.argv[1:]
mode = "{mode}"
if a[:1] == ["--version"]:
    print("osv-scanner version: 2.0.0"); sys.exit(0)
if a[:2] == ["scan", "--help"]:
    print("source\\n--config"); sys.exit(0)
if mode == "timeout":
    time.sleep(60)
if mode == "error":
    sys.exit(127)
if mode == "nopackages":
    sys.exit(128)
if mode == "invalid":
    print("garbage"); sys.exit(1)
vuln = [{{"id": "GHSA-xxxx-0000-0000", "summary": "Prototype pollution (sintético)", "aliases": ["CVE-2099-0001"]}}]
pkg = {{"package": {{"name": "lodash", "version": "4.0.0", "ecosystem": "npm"}}, "vulnerabilities": vuln if mode == "findings" else [],
       "groups": [{{"ids": ["GHSA-xxxx-0000-0000"], "max_severity": "9.8"}}] if mode == "findings" else []}}
print(json.dumps({{"results": [{{"source": {{"path": sys.argv[-1] + "/package-lock.json", "type": "lockfile"}}, "packages": [pkg]}}]}}))
sys.exit(1 if mode == "findings" else 0)
'''


def make_fake(tool: str, mode: str, dest_dir: Path) -> Path:
    tpl = {"gitleaks": FAKE_GITLEAKS, "semgrep": FAKE_SEMGREP, "osv": FAKE_OSV}[tool]
    p = dest_dir / f"fake-{tool}-{mode}"
    p.write_text(tpl.format(py=sys.executable, mode=mode, secret=SYNTHETIC_SECRET), encoding="utf-8")
    p.chmod(0o755)
    return p


class TmpCase(unittest.TestCase):
    """Base con directorio temporal por prueba (rutas con espacios y Unicode a propósito)."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="sc tést ñ ")
        self.tmp = Path(self._td.name).resolve()
        self.addCleanup(self._td.cleanup)
        self.out = self.tmp / "out"

    def project(self, fixture: str = "", name: str = "proyecto ñ", repo: bool = True, commit: bool = True) -> Path:
        dest = self.tmp / name
        if fixture:
            copy_fixture(fixture, dest)
        else:
            dest.mkdir()
        if repo:
            init_repo(dest, commit=commit and any(dest.iterdir()))
        return dest
