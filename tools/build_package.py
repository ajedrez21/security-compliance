#!/usr/bin/env python3
"""Construye el paquete distribuible local (sin publicación remota).

Salida en dist/: security-compliance-skill-<version>.zip + .manifest.json + SHA256SUMS.
El zip es determinístico (orden y fechas fijas) y contiene todo lo necesario para instalar desde otra
ubicación sin depender del checkout de desarrollo.
Uso: python tools/build_package.py [--out DIR]
"""
import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE_FILES = ["README.md", "CHANGELOG.md", "install.sh", "install.ps1"]
INCLUDE_DIRS = ["installer", "skills", "integrations", "docs"]
SKIP_PARTS = {"__pycache__", ".DS_Store", ".pytest_cache"}
FIXED_DATE = (2026, 9, 30, 0, 0, 0)


def collect():
    files = []
    for f in INCLUDE_FILES:
        if (ROOT / f).is_file():
            files.append(ROOT / f)
    for d in INCLUDE_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_PARTS) and not p.name.endswith(".pyc"):
                files.append(p)
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    version = (ROOT / "skills/security-compliance/VERSION").read_text().strip()
    prefix = f"security-compliance-skill-{version}"
    files = collect()
    manifest = {"name": "security-compliance-skill", "skill": "security-compliance", "version": version,
                "note": "Paquete local; no se publicó en ningún registro. Verifique los hashes antes de instalar.",
                "files": {p.relative_to(ROOT).as_posix(): sha(p) for p in files}}
    zpath = out / f"{prefix}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            rel = p.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{prefix}/{rel}", FIXED_DATE)
            mode = 0o755 if (p.suffix in (".sh",) or p.stat().st_mode & stat.S_IXUSR) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
        minfo = zipfile.ZipInfo(f"{prefix}/MANIFEST.json", FIXED_DATE)
        minfo.external_attr = (stat.S_IFREG | 0o644) << 16
        z.writestr(minfo, json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    archive_sha = sha(zpath)
    (out / f"{prefix}.manifest.json").write_text(json.dumps({**manifest, "archive": zpath.name, "archive_sha256": archive_sha},
                                                           indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "SHA256SUMS").write_text(f"{archive_sha}  {zpath.name}\n", encoding="utf-8")
    print(f"{zpath}  sha256={archive_sha}  ({len(files) + 1} archivos)")


if __name__ == "__main__":
    main()
