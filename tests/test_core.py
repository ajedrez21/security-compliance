"""Pruebas del núcleo: YAML seguro, schemas, configuración, inventario/stack, catálogo, redacción (AC-08, AC-09, AC-22)."""
import copy
import json
import unittest
from pathlib import Path

from helpers import FIXTURES, SKILL, TmpCase, copy_fixture, init_repo, run_sc

from sc_core import catalog, config as cfgmod, inventory as inv, miniyaml, redact, schema as sch
from sc_core.errors import ConfigError


class TestMiniYaml(unittest.TestCase):
    def test_example_config_parses(self):
        data = miniyaml.loads((SKILL / "assets" / "config.example.yml").read_text(encoding="utf-8"))
        self.assertEqual(data["gate"]["block_severities"], ["critical", "high"])
        self.assertEqual(data["paths"]["include"], ["."])
        self.assertIs(data["network"]["allow_external_scanners"], False)

    def test_list_of_maps_and_comments(self):
        data = miniyaml.loads("exceptions:\n  - id: a # c\n    scope: {control_id: X-Y-001}\n  - id: b\n    reason: 'x # no comentario'\n")
        self.assertEqual(data["exceptions"][0]["scope"], {"control_id": "X-Y-001"})
        self.assertEqual(data["exceptions"][1]["reason"], "x # no comentario")

    def test_rejects_unsafe_constructs(self):
        for bad in ["a: &x 1\nb: *x\n", "a: !!python/object:os.system x\n", "a: |\n  texto\n", "a: 1\n---\nb: 2\n",
                    "a: 1\na: 2\n", "a:\n\tb: 1\n", "- a\nb: 1\n"]:
            with self.subTest(bad=bad):
                with self.assertRaises(miniyaml.YamlError):
                    miniyaml.loads(bad)


class TestSchema(unittest.TestCase):
    def test_basic_keywords(self):
        s = {"type": "object", "required": ["a"], "additionalProperties": False,
             "properties": {"a": {"enum": ["x", "y"]}, "b": {"type": "integer", "minimum": 1}}}
        self.assertEqual(sch.validate({"a": "x", "b": 2}, s), [])
        self.assertTrue(sch.validate({"a": "z"}, s))
        self.assertTrue(sch.validate({"a": "x", "c": 1}, s))
        self.assertTrue(sch.validate({"a": "x", "b": 0}, s))
        self.assertTrue(sch.validate({}, s))

    def test_unsupported_keyword_rejected_at_load(self):
        with self.assertRaises(sch.SchemaDefinitionError):
            sch.check_schema({"type": "object", "patternProperties": {}})

    def test_all_shipped_schemas_load(self):
        for f in (SKILL / "schemas").glob("*.json"):
            sch.load_schema(f)

    def test_cross_check_with_jsonschema_if_available(self):
        try:
            import jsonschema  # type: ignore
        except ImportError:
            self.skipTest("jsonschema no instalado (comprobación cruzada opcional)")
        cfg = json.loads((SKILL / "schemas" / "config.schema.json").read_text())
        for doc, expect in (({"schema_version": 1}, True), ({"schema_version": 2}, False), ({"schema_version": 1, "x": 1}, False)):
            ok = not list(jsonschema.Draft202012Validator(cfg).iter_errors(doc))
            self.assertEqual(ok, expect)
            self.assertEqual(not sch.validate(doc, cfg), expect)


class TestConfig(TmpCase):
    def write(self, text: str) -> Path:
        p = self.tmp / "p"
        p.mkdir(exist_ok=True)
        (p / ".security-compliance.yml").write_text(text, encoding="utf-8")
        return p

    def test_defaults_without_file(self):
        p = self.tmp / "vacio"
        p.mkdir()
        cfg, meta = cfgmod.load_effective(p)
        self.assertFalse(meta["config_found"])
        self.assertEqual(cfg["project"]["sox_scope"], "unknown")
        self.assertTrue(meta["config_hash"].startswith("sha256:"))

    def test_invalid_inputs_have_clear_errors(self):
        cases = {
            "unknown key": "schema_version: 1\nfoo: bar\n",
            "bad type": "schema_version: 1\ntools:\n  timeout_seconds: lento\n",
            "bad enum": "schema_version: 1\nproject:\n  sox_scope: tal-vez\n",
            "command field": "schema_version: 1\ntools:\n  command: rm -rf /\n",
            "hooks": "schema_version: 1\nhooks:\n  pre: x\n",
            "unsafe yaml": "schema_version: 1\nproject: &a\n  name: x\n",
            "path escape": "schema_version: 1\npaths:\n  exclude: ['../fuera']\n",
            "absolute path": "schema_version: 1\nreports:\n  directory: /etc\n",
            "unknown control": "schema_version: 1\ngate:\n  required_controls: [SEC-NADA-999]\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                p = self.write(text)
                with self.assertRaises(ConfigError) as cm:
                    cfgmod.load_effective(p)
                self.assertTrue(str(cm.exception))

    def test_precedence_defaults_project_flags(self):
        p = self.write("schema_version: 1\nreview:\n  mode: advisory\ngate:\n  block_severities: [critical]\n")
        cfg, _ = cfgmod.load_effective(p, flags={"review.mode": "advisory"})
        self.assertEqual(cfg["gate"]["block_severities"], ["critical"])
        self.assertEqual(cfg["gate"]["unknown_required"], "block")   # default conservado

    def test_trust_in_project_yaml_is_ignored(self):
        p = self.write("schema_version: 1\ntrust:\n  agent_review: false\n")
        cfg, meta = cfgmod.load_effective(p)
        self.assertTrue(cfg["trust"]["agent_review"])
        self.assertTrue(any("trust" in n for n in meta["notes"]))


class TestInventoryAndStacks(TmpCase):
    def test_monorepo_detects_only_present_stacks(self):
        p = self.project("monorepo")
        cfg = copy.deepcopy(cfgmod.DEFAULTS)
        inventory = inv.build_inventory(p, cfg, cfgmod.effective_excludes(cfg))
        stacks = inv.detect_stacks(p, inventory["files"])
        self.assertEqual(sorted(stacks), ["kubernetes", "node", "python", "react"])
        for absent in ("dotnet", "java", "docker", "sql", "angular", "nestjs", "next", "express", "openshift"):
            self.assertNotIn(absent, stacks)

    def test_empty_project_has_no_stacks(self):
        p = self.tmp / "e"
        p.mkdir()
        cfg = copy.deepcopy(cfgmod.DEFAULTS)
        inventory = inv.build_inventory(p, cfg, cfgmod.effective_excludes(cfg))
        self.assertEqual(inv.detect_stacks(p, inventory["files"]), {})
        self.assertEqual(inventory["file_count"], 0)

    def test_snapshot_changes_with_content_and_exclusions_apply(self):
        p = self.project("node_basic", repo=False)
        (p / "node_modules" / "x").mkdir(parents=True)
        (p / "node_modules" / "x" / "i.js").write_text("1")
        cfg = copy.deepcopy(cfgmod.DEFAULTS)
        ex = cfgmod.effective_excludes(cfg)
        a = inv.build_inventory(p, cfg, ex)
        self.assertFalse(any("node_modules" in f["path"] for f in a["files"]))
        (p / "src" / "index.js").write_text("// cambio")
        b = inv.build_inventory(p, cfg, ex)
        self.assertNotEqual(a["snapshot_hash"], b["snapshot_hash"])

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks")
    def test_symlinks_are_skipped_not_followed(self):
        p = self.project("node_basic", repo=False)
        try:
            (p / "link").symlink_to("/etc")
        except OSError:
            self.skipTest("sin permiso para symlinks")
        cfg = copy.deepcopy(cfgmod.DEFAULTS)
        i = inv.build_inventory(p, cfg, cfgmod.effective_excludes(cfg))
        self.assertTrue(any(s["reason"] == "symlink" for s in i["skipped"]))


class TestCatalog(unittest.TestCase):
    def setUp(self):
        self.cat = catalog.load_catalog()
        self.base = catalog.load_baselines()["owasp_asvs"]["requirement_levels"]

    def test_ids_unique_and_formatted(self):
        ids = [c["id"] for c in self.cat["controls"]]
        self.assertEqual(len(ids), len(set(ids)))
        import re
        for i in ids:
            self.assertRegex(i, r"^(SEC|ITGC|ISO)-[A-Z]+-[0-9]{3}$")

    def test_every_control_has_required_fields(self):
        for c in self.cat["controls"]:
            for k in ("title", "objective", "domain", "version", "applicability", "evidence_required", "states",
                      "limitations", "default_severity", "mappings", "method"):
                self.assertIn(k, c, c["id"])
            self.assertEqual(set(c["states"]), {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "NOT_RUN", "ERROR"})
            if c["method"] == "agent":
                self.assertTrue(c["review_procedure"], c["id"])

    def test_mappings_have_source_version_and_valid_ids(self):
        for c in self.cat["controls"]:
            for m in c["mappings"]:
                self.assertTrue(m["source"] and m["version"] and m["ref"], c["id"])
                self.assertIn(m["type"], ("exact", "thematic"))
                if m["framework"] == "owasp_asvs":
                    self.assertIn(m["ref"], self.base, f"{c['id']} referencia un ID ASVS inexistente")
                    self.assertTrue(m["validated"])
                    if m["type"] == "exact":
                        self.assertEqual(m["level"], self.base[m["ref"]])
                else:   # ISO y SOX: no hay fuente validada → nunca se presentan como referencia exacta oficial
                    self.assertFalse(m["validated"], c["id"])
                    self.assertEqual(m["type"], "thematic")

    def test_baseline_versions_pinned(self):
        self.assertEqual(self.cat["baselines"]["owasp_asvs"], "5.0.0")
        self.assertEqual(len(self.base), 345)

    def test_derived_controls_reference_existing_controls(self):
        ids = {c["id"] for c in self.cat["controls"]}
        for c in self.cat["controls"]:
            for d in c["derived_from"]:
                self.assertIn(d, ids)

    def test_selection_per_command(self):
        fw = ["security", "iso27001", "sox_itgc", "owasp_asvs"]
        self.assertEqual([c["id"] for c in catalog.select_controls("secrets", fw)], ["SEC-SECRETS-001"])
        self.assertTrue(all(c["domain"] == "itgc" for c in catalog.select_controls("sox", fw)))
        iso = catalog.select_controls("iso", fw)
        self.assertTrue(any(c["selection"].startswith("soporte") for c in iso))   # cierre de derivaciones
        self.assertEqual(len(catalog.select_controls("audit", fw)), len(self.cat["controls"]))


class TestRedaction(unittest.TestCase):
    def test_redacts_known_patterns(self):
        samples = ["https://user:pa55word@host/x", "key AKIAABCDEFGHIJKLMNOP end", "ghp_" + "a" * 36,
                   "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "password = 'hunter2hunter2'"]
        for s in samples:
            out = redact.sanitize_text(s)
            self.assertIn("[REDACTED]", out, s)
            for needle in ("pa55word", "AKIAABCDEFGHIJKLMNOP", "hunter2hunter2", "MIIE"):
                self.assertNotIn(needle, out)

    def test_markdown_escape_blocks_html_and_links(self):
        from sc_core.report import md, code
        out = md("<script>alert(1)</script> [x](javascript:alert(1)) | col")
        self.assertNotIn("<script>", out)
        self.assertIn("\\[x\\]", out)   # corchetes escapados: no se forma un enlace activo
        self.assertEqual(code("a`b<c>|"), "`a'b‹c›¦`")


if __name__ == "__main__":
    unittest.main()
