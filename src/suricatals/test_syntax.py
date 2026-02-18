"""
Copyright(C) 2026 Stamus Networks SAS
Written by Eric Leblond <el@stamus-networks.com>

This file is part of Suricata Language Server.

Suricata Language Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Suricata Language Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import pytest
from functools import wraps
from suricatals.langserver import LangServer


def min_version(version_str):
    """Decorator to skip tests if Suricata version is below the minimum.

    Args:
        version_str: Minimum version string (e.g., "8.0.0")

    Usage:
        @min_version("8.0.0")
        def test_something(self):
            ...
    """

    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self):
            s = LangServer(batch_mode=True, settings=None)
            current_version = (
                s.rules_tester.get_suricata_version() if s.rules_tester else "6.0.0"
            )

            def version_tuple(v):
                return tuple(map(int, v.split(".")))

            if version_tuple(current_version) < version_tuple(version_str):
                pytest.skip(
                    f"Suricata version {current_version} < {version_str} (required)"
                )

            return test_func(self)

        return wrapper

    return decorator


def get_suricata_version():
    """Helper function to get the Suricata version for use in tests.

    Returns:
        list: Suricata version tuple (e.g., [8, 0, 0])
    """
    s = LangServer(batch_mode=True, settings=None)
    suri_version = s.rules_tester.get_suricata_version() if s.rules_tester else "6.0.0"
    tuple_version = tuple(map(int, suri_version.split(".")))
    return tuple_version


class TestSyntax:

    def _test_rules_file(self, filename, expected_diags):
        s = LangServer(batch_mode=True, settings=None)
        _, _, diags = s.analyse_file(os.path.join(os.getcwd(), "tests", filename))
        if expected_diags is not None:
            assert len(diags) == expected_diags
        return diags

    def test_cleanrules(self):
        diags = self._test_rules_file("clean.rules", 6)
        for diag in diags:
            assert diag.severity == 4

    def test_invalid_multilines(self):
        diags = self._test_rules_file("invalid-multiline.rules", 3)
        has_missing = False
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing = True
        assert has_missing

    def test_missing_incomplete(self):
        diags = self._test_rules_file("missing-incomplete.rules", None)
        has_missing = 0
        for diag in diags:
            if diag.severity == 2 and diag.message.startswith("Missing closing"):
                has_missing += 1
        assert has_missing == 2

    def test_fast_pattern_analysis(self):
        diags = self._test_rules_file("fast-pattern-analysis.rules", 7)
        for diag in diags:
            assert diag.severity == 4
            if "Rule type" in diag.message:
                continue
            if diag.range.start.line in [0, 1]:
                assert "is used in" in diag.message
            if diag.range.start.line == 2:
                assert diag.message.startswith("Fast Pattern")
                assert "is used in" not in diag.message

    def test_invalid_http_host(self):
        diags = self._test_rules_file("invalid-http-host.rules", 1)
        for diag in diags:
            assert diag.severity == 1

    def test_pattern_error(self):
        diags = self._test_rules_file("pattern-syntax.rules", 7)
        fast_pattern_diags = 0
        for diag in diags:
            if "Rule type" in diag.message:
                continue
            if diag.severity == 4 and diag.message.startswith("Fast Pattern"):
                fast_pattern_diags += 1
        assert fast_pattern_diags == 3

    def test_sig_shadow(self):
        diags = self._test_rules_file("sig-shadow.rules", 2)
        for diag in diags:
            if "Rule type" in diag.message:
                continue
            assert diag.severity == 2
            assert "Signature with newer revision" in diag.message

    def test_dataset_load(self):
        diags = self._test_rules_file("datasets.rules", 1)
        assert len(diags) == 1
        for diag in diags:
            assert diag.severity == 4

    @min_version("8.0.0")
    def test_datajson(self):
        diags = self._test_rules_file("datajson.rules", 5)
        for diag in diags:
            assert diag.severity == 4

    def test_pcap_parse(self):
        if get_suricata_version() < (7, 0, 0):
            diag_count = 7
        else:
            diag_count = 10
        diags = self._test_rules_file("pcap.rules", diag_count)
        number_of_alerts = 0
        for diag in diags:
            assert diag.severity == 4
            if diag.message.startswith("Alerts"):
                assert diag.message == "Alerts: 1"
                number_of_alerts += 1
        assert number_of_alerts == 2

    def test_pcap_no_file(self):
        if get_suricata_version() < (7, 0, 0):
            diag_count = 3
        else:
            diag_count = 6
        diags = self._test_rules_file("pcap_absent.rules", diag_count)
        for diag in diags:
            if diag.severity == 2:
                assert "not found for rules" in diag.message
            else:
                assert diag.severity == 4

    def test_empty_sticky(self):
        diags = self._test_rules_file("empty_sticky.rules", 1)
        for diag in diags:
            assert diag.severity == 1
            assert "sticky buffer" in diag.message

    def test_api_usage(self):
        signature_buffer = """
alert http any any -> any any (msg:"Test API usage"; content:"test"; sid:1;)
        """
        testor = LangServer(batch_mode=True)
        if not testor.rules_tester:
            pytest.fail("Rules tester is not initialized")
        result = testor.rules_tester.check_rule_buffer(
            signature_buffer, engine_analysis=True
        )
        assert len(result["errors"]) == 0
        assert len(result["warnings"]) == 1
