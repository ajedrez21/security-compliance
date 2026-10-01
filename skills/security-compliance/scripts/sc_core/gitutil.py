"""Acceso de solo lectura a Git (sin shell, sin hooks, sin red)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import GitError
from .redact import sanitize_text

_SAFE_CFG = ["-c", "core.fsmonitor=false", "-c", "core.quotepath=false", "-c", "gc.auto=0"]


def git_available() -> bool:
    return shutil.which("git") is not None


def _env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if k in ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_ASKPASS": "echo",
                "GIT_EXTERNAL_DIFF": "", "GIT_PAGER": "cat", "LC_ALL": "C"})
    return env


def run_git(root: Path, args: List[str], timeout: int = 60) -> Tuple[int, bytes, str]:
    if not git_available():
        raise GitError("git no está disponible en PATH")
    try:
        p = subprocess.run(["git", *_SAFE_CFG, "-C", str(root), *args], capture_output=True,
                           timeout=timeout, env=_env(), shell=False)
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args[:2])} excedió el timeout de {timeout}s") from exc
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace").strip()


def is_git_repo(root: Path) -> bool:
    if not git_available():
        return False
    rc, out, _ = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return rc == 0 and out.strip() == b"true"


def normalize_repo(url: str) -> str:
    """Normaliza un remoto/identificador a 'org/repo' en minúsculas (sin credenciales ni host)."""
    u = (url or "").strip()
    if not u:
        return ""
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", u)
    u = re.sub(r"^[^@/]+@", "", u)           # credenciales / usuario git@
    if re.match(r"^[^/:]+:[^/]", u):          # scp-like host:org/repo
        u = u.split(":", 1)[1]
    elif "/" in u and "." in u.split("/", 1)[0]:  # host.tld/org/repo
        u = u.split("/", 1)[1]
    u = re.sub(r"\.git$", "", u.strip("/"))
    parts = [p for p in u.split("/") if p and p != "_git"]
    return "/".join(parts).lower()


def git_info(root: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {"is_repo": False, "head_sha": None, "branch": None, "detached": False,
                            "has_commits": False, "shallow": False, "dirty": None,
                            "commit_time": None, "remote_repo": ""}
    if not is_git_repo(root):
        return info
    info["is_repo"] = True
    rc, out, _ = run_git(root, ["rev-parse", "--verify", "-q", "HEAD"])
    if rc == 0:
        info["head_sha"] = out.decode().strip()
        info["has_commits"] = True
        rc, out, _ = run_git(root, ["log", "-1", "--format=%cI"])
        if rc == 0:
            info["commit_time"] = out.decode().strip()
    rc, out, _ = run_git(root, ["symbolic-ref", "--short", "-q", "HEAD"])
    if rc == 0:
        info["branch"] = out.decode().strip()
    else:
        info["detached"] = info["has_commits"]
        info["branch"] = "(detached HEAD)" if info["has_commits"] else None
    rc, out, _ = run_git(root, ["rev-parse", "--is-shallow-repository"])
    info["shallow"] = rc == 0 and out.strip() == b"true"
    rc, out, _ = run_git(root, ["status", "--porcelain", "-z", "--untracked-files=normal", "--", "."])
    info["dirty"] = bool(out.strip(b"\0")) if rc == 0 else None
    rc, out, _ = run_git(root, ["config", "--get", "remote.origin.url"])
    if rc == 0:
        info["remote_repo"] = normalize_repo(out.decode().strip())
    return info


def list_files(root: Path) -> Optional[List[str]]:
    """Archivos rastreados + no ignorados (relativos a root). None si no es un repo Git."""
    if not is_git_repo(root):
        return None
    rc, out, err = run_git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
                           timeout=120)
    if rc != 0:
        raise GitError(f"git ls-files falló: {sanitize_text(err)}")
    return sorted({p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p})


def _parse_name_status(out: bytes) -> List[Dict[str, Any]]:
    toks = out.split(b"\0")
    files: List[Dict[str, Any]] = []
    i = 0
    while i < len(toks) and toks[i]:
        status = toks[i].decode()
        code = status[0]
        if code in "RC":
            old, new = toks[i + 1].decode("utf-8", "surrogateescape"), toks[i + 2].decode("utf-8", "surrogateescape")
            files.append({"path": new, "old_path": old, "status": code})
            i += 3
        else:
            files.append({"path": toks[i + 1].decode("utf-8", "surrogateescape"), "old_path": None,
                          "status": code})
            i += 2
    return files


def changed_files(root: Path, base: Optional[str] = None) -> Dict[str, Any]:
    """Cambios a revisar: staged + unstaged + untracked (+ commits desde merge-base si hay --base).

    Sin --base se compara contra HEAD. Con --base se compara el árbol de trabajo contra
    merge-base(base, HEAD), de modo que incluye commits propios, staged, unstaged y untracked.
    """
    if not is_git_repo(root):
        raise GitError("El proyecto no es un repositorio Git: no se puede calcular un diff.",
                       "Use 'audit' para revisar archivos sin trazabilidad Git.")
    info = git_info(root)
    notes: List[str] = []
    result: Dict[str, Any] = {"base": None, "merge_base": None, "notes": notes, "files": []}
    files: List[Dict[str, Any]] = []

    if not info["has_commits"]:
        notes.append("Repositorio sin commits: todos los archivos se consideran nuevos.")
        for p in list_files(root) or []:
            files.append({"path": p, "old_path": None, "status": "A"})
        result["files"] = files
        return result

    ref = "HEAD"
    if base:
        if info["shallow"]:
            notes.append("Clone superficial (shallow): el cálculo de merge-base puede ser inexacto.")
        rc, out, _ = run_git(root, ["rev-parse", "--verify", "-q", f"{base}^{{commit}}"])
        if rc != 0:
            hint = ("Haga fetch de la base manualmente (p. ej. 'git fetch --deepen=50 origin <base>'); "
                    "el skill no ejecuta fetch por sí solo.")
            raise GitError(f"La base {base!r} no existe en este clone.", hint)
        base_sha = out.decode().strip()
        rc, out, err = run_git(root, ["merge-base", base_sha, "HEAD"])
        if rc != 0 or not out.strip():
            raise GitError(f"No se pudo calcular merge-base entre {base!r} y HEAD"
                           + (" (clone superficial: historial insuficiente)" if info["shallow"] else ""),
                           "Profundice el historial (git fetch --unshallow) y repita; no se infiere un diff.")
        result["base"] = base
        result["merge_base"] = out.decode().strip()
        ref = result["merge_base"]
    rc, out, err = run_git(root, ["diff", "--name-status", "-z", "-M", "--no-ext-diff", "--no-textconv",
                                  "--relative", ref, "--", "."], timeout=120)
    if rc != 0:
        raise GitError(f"git diff falló: {sanitize_text(err)}")
    files = _parse_name_status(out)
    tracked = {f["path"] for f in files}
    rc, out, _ = run_git(root, ["ls-files", "-z", "--others", "--exclude-standard", "--", "."])
    for p in sorted({x.decode("utf-8", "surrogateescape") for x in out.split(b"\0") if x}):
        if p not in tracked:
            files.append({"path": p, "old_path": None, "status": "?"})
    result["files"] = files
    if not base:
        notes.append("Sin --base: se comparan staged + unstaged + untracked contra HEAD (no se "
                     "incluyen commits ya realizados en la rama).")
    return result
