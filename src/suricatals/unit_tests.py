import os
import unittest
from suricatals.langserver import LangServer


class TestSyntax(unittest.TestCase):

    def _test_rules_file(self, filename, expected_diags):
        s = LangServer(conn=None, settings=None)
        _, diags = s.analyse_file(os.path.join(os.getcwd(), "tests", filename))
        if expected_diags is not None:
            self.assertEqual(len(diags), expected_diags)
        return diags

    def test_cleanrules(self):
        diags = self._test_rules_file("clean.rules", 6)
        for diag in diags:
            self.assertTrue(diag.severity == 4)

    def test_invalid_multilines(self):
        diags = self._test_rules_file("invalid-multiline.rules", 3)
        has_missing = False
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing = True
        self.assertTrue(has_missing)

    def test_missing_incomplete(self):
        diags = self._test_rules_file("missing-incomplete.rules", None)
        has_missing = 0
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing += 1
        self.assertEqual(has_missing, 2)

    def test_fast_pattern_analysis(self):
        diags = self._test_rules_file("fast-pattern-analysis.rules", 7)
        for diag in diags:
            self.assertEqual(diag.severity, 4)
            if "Rule type" in diag.message:
                continue
            if diag.range.line_start in [0, 1]:
                self.assertTrue("is used in" in diag.message)
            if diag.range.line_start == 2:
                self.assertTrue(diag.message.startswith("Fast Pattern"))
                self.assertFalse("is used in" in diag.message)

    def test_invalid_http_host(self):
        diags = self._test_rules_file("invalid-http-host.rules", 1)
        for diag in diags:
            self.assertEqual(diag.severity, 1)

    def test_pattern_error(self):
        diags = self._test_rules_file("pattern-syntax.rules", 7)
        fast_pattern_diags = 0
        for diag in diags:
            if "Rule type" in diag.message:
                continue
            if diag.severity == 4 and diag.message.startswith("Fast Pattern"):
                fast_pattern_diags += 1
        self.assertEqual(fast_pattern_diags, 3)

    def test_sig_shadow(self):
        diags = self._test_rules_file("sig-shadow.rules", 2)
        for diag in diags:
            if "Rule type" in diag.message:
                continue
            self.assertEqual(diag.severity, 2)
            self.assertTrue("Signature with newer revision" in diag.message)

    def test_dataset_load(self):
        diags = self._test_rules_file("datasets.rules", 1)
        self.assertEqual(len(diags), 1)
        for diag in diags:
            self.assertEqual(diag.severity, 4)

    def test_datajson(self):
        diags = self._test_rules_file("datajson.rules", 3)
        for diag in diags:
            self.assertEqual(diag.severity, 4)

    def test_pcap_parse(self):
        diags = self._test_rules_file("pcap.rules", 7)
        number_of_alerts = 0
        for diag in diags:
            self.assertEqual(diag.severity, 4)
            if diag.message.startswith("Alerts"):
                self.assertTrue(diag.message == "Alerts: 1")
                number_of_alerts += 1
        self.assertEqual(number_of_alerts, 2)

    def test_empty_sticky(self):
        diags = self._test_rules_file("empty_sticky.rules", 1)
        for diag in diags:
            self.assertEqual(diag.severity, 1)
            self.assertTrue("sticky buffer" in diag.message)

    def test_api_usage(self):
        signature_buffer = """
alert http any any -> any any (msg:"Test API usage"; content:"test"; sid:1;)
        """
        testor = LangServer(conn=None)
        if not testor.rules_tester:
            self.fail("Rules tester is not initialized")
        result = testor.rules_tester.check_rule_buffer(
            signature_buffer, engine_analysis=True
        )
        self.assertEqual(len(result["errors"]), 0)
        self.assertEqual(len(result["warnings"]), 1)


if __name__ == "__main__":
    unittest.main()
