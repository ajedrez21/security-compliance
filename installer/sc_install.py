#!/usr/bin/env python3
"""Instalador de security-compliance para Cursor, Claude Code y Codex (solo biblioteca estándar).

Sin administrador/sudo, sin symlinks, sin tocar AGENTS.md/CLAUDE.md/reglas/hooks/configuración global.
Instalación idempotente, actualización atómica con rollback y desinstalación de lo propio.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
DEFAULT_SOURCE = HERE.parent / "skills" / "security-compliance"
sys.path.insert(0, str(DEFAULT_SOURCE / "scripts"))
sys.dont_write_bytecode = True

from sc_core import clients, skillcheck  # noqa: E402

MARKER = skillcheck.MARKER
OWNER = "security-compliance-installer/1"
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", MARKER)
FAULT: Optional[str] = None   # inyección de fallos para pruebas: "after_backup"


class InstallError(Exception):
    pass


def out(msg: str = "") -> None:
    sys.stdout.write(msg + "\n")


def sha256(path: Path) -> str:
    return skillcheck.sha256_file(path)


def tree_hashes(root: Path) -> Dict[str, str]:
    res = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != MARKER and "__pycache__" not in p.parts:
            res[p.relative_to(root).as_posix()] = sha256(p)
    return res


def read_marker(dest: Path) -> Optional[Dict[str, Any]]:
    mp = dest / MARKER
    if not mp.is_file():
        return None
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if data.get("owner") == OWNER else None


def modified_files(dest: Path, marker: Dict[str, Any]) -> List[str]:
    bad = []
    for rel, digest in marker.get("files", {}).items():
        p = dest / rel
        if not p.is_file() or sha256(p) != digest:
            bad.append(rel)
    return bad


def extra_files(dest: Path, marker: Dict[str, Any]) -> List[str]:
    owned = marker.get("files", {})
    return sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*")
                  if p.is_file() and p.name != MARKER and "__pycache__" not in p.parts
                  and p.relative_to(dest).as_posix() not in owned)


def patch_manual(stage: Path, client: str) -> None:
    """Invocación solo manual con el mecanismo real de cada cliente."""
    if client in ("cursor", "claude"):
        md = stage / "SKILL.md"
        text = md.read_text(encoding="utf-8")
        head, sep, rest = text[3:].partition("\n---")
        if not sep:
            raise InstallError("SKILL.md sin frontmatter; no se puede aplicar invocación manual")
        md.write_text("---" + head.rstrip("\n") + "\ndisable-model-invocation: true\n---" + rest, encoding="utf-8")
    else:  # codex
        (stage / "agents").mkdir(exist_ok=True)
        (stage / "agents" / "openai.yaml").write_text(
            "# Invocación solo explícita ($security-compliance); Codex no seleccionará el skill por contexto.\n"
            "policy:\n  allow_implicit_invocation: false\n", encoding="utf-8")


def stage_copy(source: Path, parent: Path, client: str, scope: str, invocation: str) -> Path:
    stage = parent / f".security-compliance.tmp-{secrets.token_hex(4)}"
    shutil.copytree(source, stage, ignore=IGNORE)
    if invocation == "manual":
        patch_manual(stage, client)
    version = (stage / "VERSION").read_text(encoding="utf-8").strip()
    marker = {"owner": OWNER, "name": clients.SKILL_NAME, "version": version, "client": client, "scope": scope,
              "invocation": invocation, "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "files": tree_hashes(stage)}
    (stage / MARKER).write_text(json.dumps(marker, indent=1) + "\n", encoding="utf-8")
    return stage


def backups_dir(base_root: Path) -> Path:
    d = base_root / ".security-compliance" / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def verify(dest: Path) -> Dict[str, Any]:
    pkg = skillcheck.validate_package(dest)
    ran = None
    try:
        p = subprocess.run([sys.executable, str(dest / "scripts" / "sc.py"), "help"], capture_output=True, timeout=60,
                           cwd=str(dest), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        ran = p.returncode == 0 and b"security-compliance" in p.stdout
    except (OSError, subprocess.TimeoutExpired):
        ran = False
    return {"package_ok": pkg["ok"], "errors": pkg["errors"], "help_ran": ran}


def first_command(client: str, dest: Path) -> str:
    slash = {"cursor": "/security-compliance help", "claude": "/security-compliance help", "codex": "$security-compliance help"}[client]
    return (f"En {client}: {slash}   (o: python3 {dest / 'scripts' / 'sc.py'} help)")


# ------------------------------------------------------------------ operaciones

def do_install(dest: Path, source: Path, client: str, scope: str, invocation: str, base_root: Path, *,
               update: bool, force: bool, dry: bool) -> str:
    parent = dest.parent
    new_version = (source / "VERSION").read_text(encoding="utf-8").strip()
    marker = read_marker(dest) if dest.exists() else None

    if dest.exists() and marker is None:
        if not force:
            raise InstallError(
                f"Ya existe {dest} y NO fue instalado por este instalador (otro skill del mismo nombre o copia manual). "
                "No se sobrescribe. Revíselo/renómbrelo, o use --force para reemplazarlo conservando un respaldo.")
        action = "reemplazar (respaldo del existente)"
    elif marker is not None:
        mods = modified_files(dest, marker)
        same = marker.get("version") == new_version and marker.get("invocation") == invocation
        if same and not mods:
            out(f"  = {dest}: ya instalado (v{new_version}, invocación {invocation}); sin cambios.")
            return "unchanged"
        if not update and not force:
            raise InstallError(f"Ya hay una instalación v{marker.get('version')} en {dest} (invocación {marker.get('invocation')}). "
                               "Use --update para actualizar (o cambiar la invocación).")
        if mods and not force:
            raise InstallError(f"{dest} tiene archivos modificados localmente ({', '.join(mods[:5])}). "
                               "Use --force para actualizar conservando un respaldo con sus cambios.")
        action = "actualizar" + (" (con cambios locales respaldados)" if mods else "")
    else:
        action = "instalar"

    out(f"  {'[dry-run] ' if dry else ''}{action}: {dest}  (v{new_version}, cliente {client}, alcance {scope}, invocación {invocation})")
    if dry:
        return "dry-run"

    parent.mkdir(parents=True, exist_ok=True)
    stage = stage_copy(source, parent, client, scope, invocation)
    backup: Optional[Path] = None
    keep_backup = False
    try:
        if dest.exists():
            clean = marker is not None and not modified_files(dest, marker) and not extra_files(dest, marker)
            backup = backups_dir(base_root) / f"{client}-{scope}-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(2)}"
            shutil.move(str(dest), str(backup))
            keep_backup = not clean
            if FAULT == "after_backup":
                raise InstallError("fallo inyectado (prueba de rollback)")
        os.replace(stage, dest)
        stage = None  # type: ignore[assignment]
    except Exception:
        if backup is not None and backup.exists() and not dest.exists():
            shutil.move(str(backup), str(dest))     # rollback
            out(f"  ↩ rollback: se restauró {dest}")
        raise
    finally:
        if stage is not None and Path(stage).exists():
            shutil.rmtree(stage, ignore_errors=True)
    if backup is not None:
        if keep_backup:
            out(f"  Respaldo conservado en {backup} (contenía contenido ajeno o modificado).")
        else:
            shutil.rmtree(backup, ignore_errors=True)
    return "installed"


def do_uninstall(dest: Path, *, force: bool, dry: bool) -> str:
    if not dest.exists():
        out(f"  = {dest}: no instalado.")
        return "absent"
    marker = read_marker(dest)
    if marker is None:
        raise InstallError(f"{dest} no fue instalado por este instalador: no se toca.")
    owned = marker.get("files", {})
    mods = set(modified_files(dest, marker))
    extra = []
    for p in dest.rglob("*"):
        if p.is_file() and p.name != MARKER and "__pycache__" not in p.parts:
            rel = p.relative_to(dest).as_posix()
            if rel not in owned:
                extra.append(rel)
    out(f"  {'[dry-run] ' if dry else ''}desinstalar: {dest}" +
        (f"; modificados (se preservan{' salvo --force' if not force else ''}): {sorted(mods)}" if mods else "") +
        (f"; ajenos (se preservan): {extra}" if extra else ""))
    if dry:
        return "dry-run"
    for rel in owned:
        p = dest / rel
        if not p.is_file():
            continue
        if rel in mods and not force:
            continue
        p.unlink()
    for pc in list(dest.rglob("__pycache__")):
        shutil.rmtree(pc, ignore_errors=True)
    for d in sorted((x for x in dest.rglob("*") if x.is_dir()), key=lambda x: len(x.parts), reverse=True):
        try:
            d.rmdir()
        except OSError:
            pass
    remaining = [p for p in dest.rglob("*") if p.is_file() and p.name != MARKER]
    if not remaining:
        try:
            (dest / MARKER).unlink()
            dest.rmdir()
        except OSError:
            pass
        out(f"  ✓ desinstalado {dest}")
        return "uninstalled"
    out(f"  ! quedaron archivos preservados en {dest}: {[p.relative_to(dest).as_posix() for p in remaining][:8]}")
    return "partial"


# ------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="install", description="Instala/actualiza/desinstala el skill security-compliance.")
    ap.add_argument("--client", action="append", choices=list(clients.CLIENTS) + ["all"],
                    help="cursor | claude | codex (repetible) | all (los tres a la vez)")
    ap.add_argument("--scope", choices=["global", "project"])
    ap.add_argument("--project-path", help="requerido con --scope project")
    ap.add_argument("--invocation", choices=["assisted", "manual"], default="assisted",
                    help="assisted (el agente puede elegir el skill) | manual (solo invocación explícita)")
    ap.add_argument("--update", action="store_true", help="actualizar una instalación existente")
    ap.add_argument("--uninstall", action="store_true", help="desinstalar solo lo instalado por este instalador")
    ap.add_argument("--dry-run", action="store_true", help="mostrar qué se haría sin escribir nada")
    ap.add_argument("--force", action="store_true", help="reemplazar contenido ajeno/modificado conservando respaldo")
    ap.add_argument("--non-interactive", action="store_true")
    ap.add_argument("--home", help="directorio home alternativo (pruebas/instalaciones portables)")
    ap.add_argument("--source", help="directorio del skill a instalar (por defecto el del paquete)")
    return ap


def prompt_missing(args) -> None:
    interactive = sys.stdin.isatty() and not args.non_interactive
    if not args.client:
        if not interactive:
            raise InstallError("Falta --client (cursor|claude|codex). Ejemplo: ./install.sh --client cursor --scope global")
        ans = input("Cliente [cursor/claude/codex]: ").strip().lower()
        if ans not in clients.CLIENTS:
            raise InstallError("Cliente inválido.")
        args.client = [ans]
    if not args.scope:
        if not interactive:
            raise InstallError("Falta --scope (global|project).")
        args.scope = input("Alcance [global/project]: ").strip().lower()
        if args.scope not in ("global", "project"):
            raise InstallError("Alcance inválido.")
    if args.scope == "project" and not args.project_path:
        if not interactive:
            raise InstallError("--scope project requiere --project-path.")
        args.project_path = input("Ruta del proyecto: ").strip()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.update and args.uninstall:
            raise InstallError("--update y --uninstall son excluyentes.")
        prompt_missing(args)
        if "all" in (args.client or []):
            args.client = list(clients.CLIENTS)
        home = Path(args.home).expanduser().resolve() if args.home else Path.home()
        project = Path(args.project_path).expanduser().resolve() if args.project_path else None
        if args.scope == "project" and (project is None or not project.is_dir()):
            raise InstallError(f"--project-path no existe o no es un directorio: {args.project_path}")
        source = Path(args.source).resolve() if args.source else DEFAULT_SOURCE
        if not args.uninstall:
            chk = skillcheck.validate_package(source)
            if not chk["ok"]:
                raise InstallError("El paquete fuente es inválido:\n  - " + "\n  - ".join(chk["errors"][:6]))
        base_root = project if args.scope == "project" else home
        results = []
        for client in dict.fromkeys(args.client):
            base = clients.install_target(client, args.scope, home, project)
            dest = base / clients.SKILL_NAME
            out(f"[{client}/{args.scope}]")
            if args.uninstall:
                results.append((client, dest, do_uninstall(dest, force=args.force, dry=args.dry_run)))
                continue
            st = do_install(dest, source, client, args.scope, args.invocation, base_root, update=args.update,
                            force=args.force, dry=args.dry_run)
            results.append((client, dest, st))
            if st in ("installed", "unchanged"):
                v = verify(dest)
                marker = read_marker(dest) or {}
                out(f"  versión instalada: {marker.get('version')}")
                out(f"  comprobación: paquete {'OK' if v['package_ok'] else 'CON ERRORES ' + str(v['errors'][:3])}; "
                    f"'sc.py help' {'ejecutó correctamente' if v['help_ran'] else 'NO ejecutó (¿Python >= 3.9?)'}")
                out("  descubrimiento dentro del cliente: NO comprobado (abra el cliente y pruebe el comando de abajo)")
                out("  primer comando: " + first_command(client, dest))
                if args.invocation == "manual":
                    out({"cursor": "  invocación manual: disable-model-invocation=true (el agente no lo elegirá por contexto).",
                         "claude": "  invocación manual: disable-model-invocation=true (la descripción no se carga en el contexto).",
                         "codex": "  invocación manual: agents/openai.yaml allow_implicit_invocation=false. Nota: Cursor también lee "
                                  ".agents/skills y no usa ese archivo."}[client])
        done = {r[0] for r in results if r[2] in ("installed", "unchanged")}
        if "cursor" in done and done & {"claude", "codex"} and not args.uninstall:
            out("\nNota: Cursor también lee .claude/skills y .agents/skills; en Cursor el skill puede aparecer más de una vez "
                "(es normal al instalar varios clientes; no se borra nada). Para evitarlo, instale solo claude y codex.")
        if not args.uninstall and not args.dry_run:
            others = [i for i in clients.find_installs(home, project)
                      if Path(str(i["skill_dir"])).resolve() not in {r[1].resolve() for r in results}]
            if others:
                out("\nAviso: hay OTRAS instalaciones de security-compliance (no se borró nada):")
                for i in others:
                    out(f"  - {i['skill_dir']}  ({i['scope']}; {i['clients']})")
                for c in sorted({r[0] for r in results}):
                    out("  · " + clients.PRECEDENCE_NOTES[c])
        return 0
    except InstallError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"error de E/S: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
