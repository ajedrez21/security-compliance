"""Documentación: guías por cliente (AC-28), honestidad de VALIDATION (AC-29) y consistencia del catálogo/mapeo (AC-22)."""
import json
import re
import unittest

from helpers import ROOT, SKILL

CLIENT_GUIDES = {"cursor": ROOT / "integrations" / "cursor" / "README.md", "claude": ROOT / "integrations" / "claude" / "README.md",
                 "codex": ROOT / "integrations" / "codex" / "README.md"}


class TestDocs(unittest.TestCase):
    def test_client_guides_cover_install_discovery_manual_update_uninstall(self):
        for client, path in CLIENT_GUIDES.items():
            text = path.read_text(encoding="utf-8")
            for needle in ("## Instalar", "## Verificar el descubrimiento", "## Uso", "## Actualizar / desinstalar", "--uninstall", "-Uninstall",
                           "security-compliance help", "## Límites", "-Scope project", "--scope project"):
                self.assertIn(needle, text, f"{client}: falta {needle!r}")

    def test_validation_doc_maps_every_acceptance_criterion_and_separates_levels(self):
        text = (ROOT / "docs" / "VALIDATION.md").read_text(encoding="utf-8")
        for i in range(1, 31):
            self.assertIn(f"AC-{i:02d}", text)
        for level in ("Simulado (fake)", "Fixture + código real", "Binario real", "Dentro del cliente", "Pendiente"):
            self.assertIn(level, text)

    def test_status_doc_lists_pending_items_without_hiding_optional_extensions(self):
        text = (ROOT / "docs" / "IMPLEMENTATION-STATUS.md").read_text(encoding="utf-8")
        for needle in ("Hooks", "SARIF", "Trivy", "Windows", "Binarios reales", "no implementado"):
            self.assertIn(needle, text)

    def test_control_mapping_is_in_sync_with_catalog(self):
        cat = json.loads((SKILL / "controls" / "catalog.json").read_text())
        mapping = (ROOT / "docs" / "CONTROL-MAPPING.md").read_text(encoding="utf-8")
        for c in cat["controls"]:
            self.assertIn(f"`{c['id']}`", mapping)

    def test_all_internal_markdown_links_resolve(self):
        broken = []
        for md in list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md")) + list((ROOT / "integrations").rglob("*.md")):
            for m in re.finditer(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", md.read_text(encoding="utf-8")):
                target = m.group(1)
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if not (md.parent / target).exists():
                    broken.append((md.name, target))
        self.assertEqual(broken, [])

    def test_docs_never_claim_certification(self):
        for p in list((ROOT / "docs").glob("*.md")) + [ROOT / "README.md", SKILL / "SKILL.md"] + list((SKILL / "references").rglob("*.md")):
            text = p.read_text(encoding="utf-8")
            for line in text.splitlines():
                if re.search(r"(?i)\b(sox[- ]compliant|iso 27001 certified|certificado iso)\b", line):
                    # solo se admite como ejemplo de lo que NO se debe afirmar
                    self.assertRegex(line, r"(?i)\b(nunca|no |never|ni )", f"{p.name}: {line}")


if __name__ == "__main__":
    unittest.main()
