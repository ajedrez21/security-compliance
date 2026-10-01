"""Inventario del alcance, identidad del snapshot, detección de stacks e inventario de dependencias."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import gitutil

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 200_000


def is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    rel = rel.replace("\\", "/")
    segs = rel.split("/")
    for pat in patterns:
        p = pat.replace("\\", "/").strip("/")
        if p in ("", "."):
            continue
        if any(c in p for c in "*?["):
            if fnmatch.fnmatch(rel, p) or any(fnmatch.fnmatch(s, p) for s in segs):
                return True
        elif "/" in p:
            if rel == p or rel.startswith(p + "/"):
                return True
        elif p in segs:
            return True
    return False


def _included(rel: str, include: List[str]) -> bool:
    inc = [i.replace("\\", "/").strip("/") for i in include]
    if not inc or any(i in ("", ".") for i in inc):
        return True
    return any(rel == i or rel.startswith(i + "/") for i in inc)


def _sha256_file(path: Path) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return False


def _walk(root: Path, excludes: List[str]) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in sorted(dirnames):
            rel = (rel_dir + "/" + d).lstrip("/")
            if is_excluded(rel, excludes):
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                out.append(rel)       # symlink a directorio: se registra como omitido, no se sigue
            else:
                kept.append(d)
        dirnames[:] = kept
        for f in sorted(filenames):
            out.append((rel_dir + "/" + f).lstrip("/"))
    return out


def build_inventory(root: Path, cfg: Dict[str, Any], excludes: List[str]) -> Dict[str, Any]:
    """Lista el alcance con hash de contenido. No ejecuta ni importa nada del proyecto."""
    root = root.resolve()
    git_files = gitutil.list_files(root)
    candidates = git_files if git_files is not None else _walk(root, excludes)
    include = cfg["paths"]["include"]

    entries: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    excluded_count = 0
    truncated = False
    for rel in candidates:
        if is_excluded(rel, excludes) or not _included(rel, include):
            excluded_count += 1
            continue
        full = root / rel
        try:
            if full.is_symlink():
                skipped.append({"path": rel, "reason": "symlink"})
                entries.append({"path": rel, "sha256": "symlink:" + os.readlink(full), "size": 0,
                                "binary": False, "skipped": "symlink"})
                continue
            if not full.is_file():  # borrado en el árbol de trabajo o submódulo
                continue
            size = full.stat().st_size
        except OSError:
            skipped.append({"path": rel, "reason": "unreadable"})
            continue
        if len(entries) >= MAX_FILES:
            truncated = True
            break
        if size > MAX_FILE_BYTES:
            skipped.append({"path": rel, "reason": "too_large", "size": size})
            entries.append({"path": rel, "sha256": f"too_large:{size}", "size": size,
                            "binary": False, "skipped": "too_large"})
            continue
        sha = _sha256_file(full)
        if sha is None:
            skipped.append({"path": rel, "reason": "unreadable"})
            continue
        entries.append({"path": rel, "sha256": sha, "size": size, "binary": _is_binary(full)})
    entries.sort(key=lambda e: e["path"])
    snap = hashlib.sha256()
    for e in entries:
        snap.update(f"{e['path']}\0{e['sha256']}\n".encode("utf-8", "surrogateescape"))
    return {
        "files": entries,
        "snapshot_hash": "sha256:" + snap.hexdigest(),
        "file_count": len(entries),
        "excluded_count": excluded_count,
        "skipped": skipped,
        "truncated": truncated,
        "source": "git" if git_files is not None else "filesystem",
        "include": include,
        "exclude": excludes,
    }


# --- detección de stacks (solo por archivos/metadatos presentes) -------------------------------

_K8S_KIND = re.compile(r"^kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|DeploymentConfig|Route)\b",
                       re.M)


def _read_head(path: Path, n: int = 65536) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def detect_stacks(root: Path, files: List[Dict[str, Any]]) -> Dict[str, Any]:
    stacks: Dict[str, List[str]] = {}

    def add(name: str, evidence: str) -> None:
        stacks.setdefault(name, [])
        if evidence not in stacks[name] and len(stacks[name]) < 20:
            stacks[name].append(evidence)

    for e in files:
        rel = e["path"]
        base = rel.rsplit("/", 1)[-1]
        low = base.lower()
        if e.get("skipped") or e.get("binary"):
            continue
        if low == "package.json":
            add("node", rel)
            try:
                pkg = json.loads(_read_head(root / rel, 1_000_000))
                deps = {}
                for k in ("dependencies", "devDependencies", "peerDependencies"):
                    deps.update(pkg.get(k) or {})
                for dep, stack in (("@nestjs/core", "nestjs"), ("express", "express"),
                                   ("react", "react"), ("next", "next"), ("@angular/core", "angular")):
                    if dep in deps:
                        add(stack, rel)
            except (ValueError, AttributeError):
                pass
        elif low.endswith((".csproj", ".fsproj", ".vbproj")) or low.endswith(".sln"):
            add("dotnet", rel)
        elif low in ("pyproject.toml", "requirements.txt", "setup.py", "pipfile", "setup.cfg"):
            add("python", rel)
        elif low in ("pom.xml", "build.gradle", "build.gradle.kts"):
            add("java", rel)
        elif low.endswith(".sql"):
            add("sql", rel)
        elif low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
            add("docker", rel)
        elif low.endswith((".yml", ".yaml")) and e["size"] < 200_000:
            head = _read_head(root / rel, 8192)
            if "apiVersion:" in head and _K8S_KIND.search(head):
                add("kubernetes", rel)
                if re.search(r"^kind:\s*(DeploymentConfig|Route)\b", head, re.M):
                    add("openshift", rel)
    return {k: sorted(v) for k, v in sorted(stacks.items())}


# --- inventario de dependencias --------------------------------------------------------------

LOCK_RULES = {
    "package.json": ("node", ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"]),
    "pyproject.toml": ("python", ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"]),
    "Pipfile": ("python", ["Pipfile.lock"]),
    "pom.xml": ("java", []),          # Maven no tiene lockfile estándar: no evaluable
    "build.gradle": ("java", ["gradle.lockfile"]),
    "build.gradle.kts": ("java", ["gradle.lockfile"]),
}


def dependency_inventory(root: Path, files: List[Dict[str, Any]]) -> Dict[str, Any]:
    paths = {e["path"] for e in files}
    manifests: List[Dict[str, Any]] = []
    deps: List[Dict[str, Any]] = []
    for e in files:
        rel = e["path"]
        d, _, base = rel.rpartition("/")
        if e.get("skipped") or e.get("binary"):
            continue
        if base == "package.json":
            ecosystem, locks = LOCK_RULES[base]
            manifests.append(_manifest(rel, ecosystem, d, locks, paths))
            try:
                pkg = json.loads(_read_head(root / rel, 1_000_000))
                for kind, direct_dev in (("dependencies", False), ("devDependencies", True)):
                    for name, ver in (pkg.get(kind) or {}).items():
                        deps.append({"ecosystem": "npm", "name": name, "version_spec": str(ver),
                                     "file": rel, "direct": True, "dev": direct_dev})
            except (ValueError, AttributeError):
                manifests[-1]["parse_error"] = True
        elif base in ("pyproject.toml", "Pipfile", "build.gradle", "build.gradle.kts", "pom.xml"):
            ecosystem, locks = LOCK_RULES[base]
            manifests.append(_manifest(rel, ecosystem, d, locks, paths))
            if base == "pom.xml":
                try:
                    tree = ET.fromstring(_read_head(root / rel, 2_000_000))
                    for dep in tree.iter():
                        if dep.tag.endswith("}dependency") or dep.tag == "dependency":
                            g = {c.tag.split("}")[-1]: (c.text or "").strip() for c in dep}
                            if g.get("artifactId"):
                                deps.append({"ecosystem": "Maven", "name": f"{g.get('groupId','')}:{g['artifactId']}",
                                             "version_spec": g.get("version", ""), "file": rel,
                                             "direct": True, "dev": g.get("scope") == "test"})
                except ET.ParseError:
                    manifests[-1]["parse_error"] = True
        elif base == "requirements.txt":
            manifests.append({"file": rel, "ecosystem": "python", "lockfile": rel if _pinned_requirements(root / rel) else None,
                              "lock_expected": True, "lock_candidates": ["requirements.txt (versiones fijadas con ==)"]})
            for line in _read_head(root / rel, 1_000_000).splitlines():
                line = line.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;]*)", line)
                if m and not line.startswith("-"):
                    deps.append({"ecosystem": "PyPI", "name": m.group(1), "version_spec": (m.group(2) or "") + (m.group(3) or ""),
                                 "file": rel, "direct": True, "dev": False})
        elif base.lower().endswith((".csproj", ".fsproj", ".vbproj")):
            lock = f"{d}/packages.lock.json".lstrip("/")
            manifests.append({"file": rel, "ecosystem": "nuget", "lockfile": lock if lock in paths else None,
                              "lock_expected": True, "lock_candidates": ["packages.lock.json"]})
            for m in re.finditer(r'<PackageReference\s+[^>]*Include="([^"]+)"[^>]*?(?:Version="([^"]*)")?[^>]*/?>',
                                 _read_head(root / rel, 1_000_000)):
                deps.append({"ecosystem": "NuGet", "name": m.group(1), "version_spec": m.group(2) or "",
                             "file": rel, "direct": True, "dev": False})
    return {"manifests": manifests, "dependencies": deps[:5000],
            "dependency_count": len(deps), "truncated": len(deps) > 5000}


def _pinned_requirements(path: Path) -> bool:
    lines = [l.split("#", 1)[0].strip() for l in _read_head(path, 1_000_000).splitlines()]
    reqs = [l for l in lines if l and not l.startswith("-")]
    return bool(reqs) and all("==" in l for l in reqs)


def _manifest(rel: str, ecosystem: str, directory: str, locks: List[str], paths: set) -> Dict[str, Any]:
    found = None
    for cand in locks:
        p = f"{directory}/{cand}".lstrip("/")
        if p in paths:
            found = p
            break
    return {"file": rel, "ecosystem": ecosystem, "lockfile": found,
            "lock_expected": bool(locks), "lock_candidates": locks}


# --- heurística de texto dirigido a agentes (prompt injection) ---------------------------------

_INJECTION = re.compile(
    r"(?i)(ignor(e|a|á)\s+(all\s+|todas?\s+)?(the\s+)?(previous|prior|anteriores|previas)\s+(instructions|instrucciones)"
    r"|disregard\s+(the\s+)?(above|previous)|you\s+are\s+now\s+(in\s+)?(admin|developer)\s+mode"
    r"|(mark|marc[aá]|set)\s+(the\s+)?(gate|result|resultado)\s+(as\s+|como\s+)?pass"
    r"|do\s+not\s+(report|mention)\s+(this|these)\s+(finding|issue)s?|no\s+reportes?\s+(este|estos)\s+hallazgos?"
    r"|\bAI\s+agents?:|\bnote\s+to\s+(the\s+)?(ai|assistant|agent)\b)")


def scan_agent_directed_text(root: Path, files: List[Dict[str, Any]], limit: int = 300) -> List[str]:
    hits: List[str] = []
    for e in files[:limit * 20]:
        if e.get("skipped") or e.get("binary") or e["size"] > 300_000:
            continue
        low = e["path"].lower()
        if not low.endswith((".md", ".txt", ".rst", ".yml", ".yaml", ".json", ".py", ".js", ".ts", ".cs", ".java")):
            continue
        if _INJECTION.search(_read_head(root / e["path"], 300_000)):
            hits.append(e["path"])
            if len(hits) >= 20:
                break
    return hits
