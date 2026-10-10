import unittest
from pathlib import Path

from scripts.hydra_skill_router import select_skills


class SkillRouterTests(unittest.TestCase):
    def test_js_analysis_and_scope_guard_are_always_loaded(self):
        selected = select_skills("Write a BugBase report for a payment race condition")
        names = {str(item["name"]) for item in selected}
        self.assertIn("scope-guard", names)
        self.assertIn("js-analysis", names)
        self.assertIn("javascript-analysis-methodology", names)
        self.assertTrue(all(Path(str(item["path"])).is_file() for item in selected))
        self.assertTrue(
            any(
                str(item["path"]).endswith("05_javascript_analysis.md")
                for item in selected
            )
        )

    def test_vector_keywords_select_matching_skills(self):
        selected = select_skills(
            "Check JWT none-algorithm and key-confusion validation"
        )
        names = {str(item["name"]) for item in selected}
        self.assertTrue(any("jwt" in name for name in names))
        self.assertIn("js-analysis", names)

    def test_empty_task_is_rejected(self):
        with self.assertRaises(ValueError):
            select_skills("   ")


if __name__ == "__main__":
    unittest.main()
