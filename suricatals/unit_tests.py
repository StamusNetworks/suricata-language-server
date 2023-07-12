import unittest
from langserver import LangServer

class TestSyntax(unittest.TestCase):

    def test_cleanrules(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/clean.rules")
        self.assertTrue(len(diags) == 3)
        for diag in diags:
            self.assertTrue(diag.severity == 4)

    def test_invalid_multilines(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/invalid-multiline.rules")
        self.assertTrue(len(diags) == 2)
        has_missing = False
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing = True
        self.assertTrue(has_missing)

    def test_missing_incomplete(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/missing-incomplete.rules")
        has_missing = 0
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing += 1
        self.assertEqual(has_missing, 2)

    def test_fast_pattern_analysis(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/fast-pattern-analysis.rules")
        self.assertEqual(len(diags), 3)
        for diag in diags:
            self.assertEqual(diag.severity, 4)
            if diag.range.line_start in [0, 1]:
                self.assertTrue('is used in' in diag.message)
            if diag.range.line_start == 2:
                self.assertTrue(diag.message.startswith("Fast Pattern"))
                self.assertFalse('is used in' in diag.message)

    def test_invalid_http_host(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/invalid-http-host.rules")
        self.assertEqual(len(diags), 1)
        for diag in diags:
            self.assertEqual(diag.severity, 1)

    def test_pattern_error(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/pattern-syntax.rules")
        self.assertEqual(len(diags), 3)
        for diag in diags:
            self.assertEqual(diag.severity, 4)

    def test_sig_shadow(self):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file("tests/sig-shadow.rules")
        self.assertEqual(len(diags), 1)
        for diag in diags:
            self.assertEqual(diag.severity, 2)


if __name__ == '__main__':
    unittest.main()
