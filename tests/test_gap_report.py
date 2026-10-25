"""scripts/gap_report.py on a fixture (the real targets are not redistributed)."""
import json
import os
import subprocess
import tempfile
import unittest

from recompiler import decoder as dec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(dec.capstone is not None, "capstone required")
class GapReportTests(unittest.TestCase):
    def test_fixture_is_fully_covered(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "r.json")
            r = subprocess.run(["python3", os.path.join(ROOT, "scripts", "gap_report.py"),
                                os.path.join(ROOT, "test", "vec.exe"), "--json", out],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr)
            rep = json.load(open(out))
        self.assertGreater(rep["functions"], 0)
        self.assertEqual(rep["instructions_not_liftable"], 0)
        self.assertEqual(rep["functions_all_instructions_liftable"], rep["functions"] - rep["functions_undecodable"])
        self.assertEqual(rep["imports_supported"], rep["imports_total"])


if __name__ == "__main__":
    unittest.main()
