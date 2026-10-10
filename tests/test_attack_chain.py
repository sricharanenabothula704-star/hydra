import unittest

from core.attack_chain import AttackChainEngine


class AttackChainTests(unittest.TestCase):
    def test_listed_chain_names_are_retrievable(self):
        engine = AttackChainEngine()
        for item in engine.list_chains():
            with self.subTest(name=item["name"]):
                self.assertIsNotNone(engine.get_chain(item["name"]))


if __name__ == "__main__":
    unittest.main()
