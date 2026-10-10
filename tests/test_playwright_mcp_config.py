import json
import re
import unittest
from pathlib import Path


class PlaywrightMcpConfigTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "opencode.jsonc.template").read_text(encoding="utf-8")
        self.config = json.loads(re.sub(r"(?m)^\s*//.*$", "", source))

    def test_playwright_is_opt_in_and_isolated(self):
        server = self.config["mcp"]["playwright"]
        self.assertFalse(server["enabled"])
        self.assertEqual(server["type"], "local")
        self.assertIn("@playwright/mcp@0.0.83", server["command"])
        self.assertIn("--isolated", server["command"])
        self.assertIn("--headless", server["command"])
        self.assertIn("--block-service-workers", server["command"])

    def test_config_does_not_enable_stealth_or_shared_browser_state(self):
        command = self.config["mcp"]["playwright"]["command"]
        unsafe_options = {
            "--cdp-endpoint",
            "--extension",
            "--proxy-server",
            "--storage-state",
            "--user-agent",
            "--user-data-dir",
        }
        self.assertFalse(unsafe_options.intersection(command))

    def test_default_model_is_left_to_opencode(self):
        self.assertNotIn("model", self.config)
        self.assertNotIn("small_model", self.config)

    def test_browser_commands_are_scope_gated_and_non_evasive(self):
        commands = self.config["command"]
        browser_check = commands["browser-check"]["template"].lower()
        setup = commands["playwright-setup"]["template"].lower()
        self.assertIn("scope_check.sh", browser_check)
        self.assertIn("do not", browser_check)
        self.assertIn("bot", browser_check)
        self.assertIn("ask before", setup)
        self.assertIn("ai_playwright_mcp_setup_prompt.md", setup)


if __name__ == "__main__":
    unittest.main()
