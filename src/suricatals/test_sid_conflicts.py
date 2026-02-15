"""
Unit tests for SID conflict detection across workspace files.

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

# pylint: disable=W0212  # Allow testing protected methods

import pytest
from unittest.mock import MagicMock

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile, DiagnosticBuilder


class TestMpmCacheSidConflicts:
    """Tests for MpmCache SID conflict detection"""

    def test_get_sid_conflicts_no_conflicts(self):
        """Test get_sid_conflicts with no conflicts"""
        cache = MpmCache()

        # Add file with SIDs 1000, 2000, 3000
        cache.add_file(
            "/path/file1.rules", {"buffer": {}, "sids": {1000: {}, 2000: {}, 3000: {}}}
        )

        # Check for conflicts with different SIDs (4000, 5000)
        current_sids = {4000: {}, 5000: {}}
        conflicts = cache.get_sid_conflicts(current_sids)

        assert len(conflicts) == 0

    def test_get_sid_conflicts_with_conflicts(self):
        """Test get_sid_conflicts with conflicts"""
        cache = MpmCache()

        # Add file1 with SIDs 1000, 2000, 3000
        cache.add_file(
            "/path/file1.rules", {"buffer": {}, "sids": {1000: {}, 2000: {}, 3000: {}}}
        )

        # Add file2 with SIDs 4000, 5000
        cache.add_file(
            "/path/file2.rules", {"buffer": {}, "sids": {4000: {}, 5000: {}}}
        )

        # Check for conflicts with SIDs 2000 (in file1) and 4000 (in file2)
        current_sids = {2000: {}, 4000: {}, 6000: {}}
        conflicts = cache.get_sid_conflicts(current_sids)

        assert len(conflicts) == 2
        assert 2000 in conflicts
        assert 4000 in conflicts
        assert "/path/file1.rules" in conflicts[2000]
        assert "/path/file2.rules" in conflicts[4000]
        assert 6000 not in conflicts  # No conflict for 6000

    def test_get_sid_conflicts_exclude_file(self):
        """Test get_sid_conflicts with file exclusion"""
        cache = MpmCache()

        # Add two files with same SID
        cache.add_file("/path/file1.rules", {"buffer": {}, "sids": {1000: {}}})
        cache.add_file("/path/file2.rules", {"buffer": {}, "sids": {1000: {}}})

        # Check conflicts excluding file2
        current_sids = {1000: {}}
        conflicts = cache.get_sid_conflicts(
            current_sids, exclude_file="/path/file2.rules"
        )

        assert len(conflicts) == 1
        assert 1000 in conflicts
        assert "/path/file1.rules" in conflicts[1000]
        assert "/path/file2.rules" not in conflicts[1000]

    def test_get_sid_conflicts_skip_sid_zero(self):
        """Test get_sid_conflicts skips SID 0"""
        cache = MpmCache()

        cache.add_file("/path/file1.rules", {"buffer": {}, "sids": {0: {}, 1000: {}}})

        # SID 0 should be skipped
        current_sids = {0: {}, 1000: {}}
        conflicts = cache.get_sid_conflicts(current_sids)

        assert 0 not in conflicts
        assert 1000 in conflicts

    def test_get_sid_conflicts_multiple_files(self):
        """Test get_sid_conflicts with same SID in multiple files"""
        cache = MpmCache()

        # Add three files with same SID 9999
        cache.add_file("/path/file1.rules", {"buffer": {}, "sids": {9999: {}}})
        cache.add_file("/path/file2.rules", {"buffer": {}, "sids": {9999: {}}})
        cache.add_file("/path/file3.rules", {"buffer": {}, "sids": {9999: {}}})

        current_sids = {9999: {}}
        conflicts = cache.get_sid_conflicts(current_sids)

        assert len(conflicts) == 1
        assert 9999 in conflicts
        assert len(conflicts[9999]) == 3
        assert "/path/file1.rules" in conflicts[9999]
        assert "/path/file2.rules" in conflicts[9999]
        assert "/path/file3.rules" in conflicts[9999]


class TestSuricataFileSidConflicts:
    """Tests for SuricataFile SID conflict detection"""

    mock_tester = None

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up mock rules_tester for tests"""
        self.mock_tester = MagicMock()
        self.mock_tester.get_semantic_token_definitions.return_value = {}

    def test_compute_sid_conflicts_no_workspace(self):
        """Test _compute_sid_conflicts with empty workspace"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file.load_from_buffer(contents)

        conflicts = suri_file._compute_sid_conflicts({})
        assert len(conflicts) == 0

    def test_compute_sid_conflicts_no_conflicts(self):
        """Test _compute_sid_conflicts with no conflicts"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file.load_from_buffer(contents)

        workspace = {"/path/other.rules": {"buffer": {}, "sids": {2000: {}, 3000: {}}}}

        conflicts = suri_file._compute_sid_conflicts(workspace)
        assert len(conflicts) == 0

    def test_compute_sid_conflicts_with_conflicts(self):
        """Test _compute_sid_conflicts with conflicts"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = """alert tcp any any -> any any (msg:"Test1"; sid:1000;)
alert tcp any any -> any any (msg:"Test2"; sid:2000;)
alert tcp any any -> any any (msg:"Test3"; sid:3000;)"""
        suri_file.load_from_buffer(contents)

        workspace = {
            "/path/other1.rules": {"buffer": {}, "sids": {1000: {}, 4000: {}}},
            "/path/other2.rules": {"buffer": {}, "sids": {3000: {}, 5000: {}}},
        }

        conflicts = suri_file._compute_sid_conflicts(workspace)

        assert len(conflicts) == 2
        assert 1000 in conflicts
        assert 3000 in conflicts
        assert 2000 not in conflicts
        assert "/path/other1.rules" in conflicts[1000]
        assert "/path/other2.rules" in conflicts[3000]

    def test_compute_sid_conflicts_skip_sid_zero(self):
        """Test _compute_sid_conflicts skips signatures without SID"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test";)'  # No SID
        suri_file.load_from_buffer(contents)

        workspace = {"/path/other.rules": {"buffer": {}, "sids": {0: {}}}}

        conflicts = suri_file._compute_sid_conflicts(workspace)
        assert len(conflicts) == 0

    def test_build_sid_conflict_diagnostics(self):
        """Test build_sid_conflict_diagnostics"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = """alert tcp any any -> any any (msg:"Test1"; sid:1000;)
alert tcp any any -> any any (msg:"Test2"; sid:2000;)"""
        suri_file.load_from_buffer(contents)

        conflicts = {
            1000: ["/path/other1.rules"],
            2000: ["/path/other2.rules", "/path/other3.rules"],
        }

        diags = suri_file.build_sid_conflict_diagnostics(conflicts)

        assert len(diags) == 2

        # Check first diagnostic
        diag1 = next(d for d in diags if d.sid == 1000)
        assert diag1.severity == DiagnosticBuilder.WARNING_LEVEL
        assert diag1.source == "Suricata Language Server"
        assert "1000" in diag1.message
        assert "other1.rules" in diag1.message
        assert diag1.range is not None

        # Check second diagnostic
        diag2 = next(d for d in diags if d.sid == 2000)
        assert "2000" in diag2.message
        assert "other2.rules" in diag2.message
        assert "other3.rules" in diag2.message

    def test_build_sid_conflict_diagnostics_many_files(self):
        """Test build_sid_conflict_diagnostics with many conflicting files"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file.load_from_buffer(contents)

        # Conflict with 5 files
        conflicts = {
            1000: [
                "/path/file1.rules",
                "/path/file2.rules",
                "/path/file3.rules",
                "/path/file4.rules",
                "/path/file5.rules",
            ]
        }

        diags = suri_file.build_sid_conflict_diagnostics(conflicts)

        assert len(diags) == 1
        assert "file1.rules" in diags[0].message
        assert "file2.rules" in diags[0].message
        assert "file3.rules" in diags[0].message
        # Should show "and X more" for files beyond the first 3
        assert "and 2 more" in diags[0].message

    def test_build_sid_conflict_diagnostics_empty(self):
        """Test build_sid_conflict_diagnostics with no conflicts"""
        suri_file = SuricataFile("/path/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file.load_from_buffer(contents)

        diags = suri_file.build_sid_conflict_diagnostics({})
        assert len(diags) == 0
