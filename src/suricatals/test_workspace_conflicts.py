"""
Pytest tests for workspace SID conflict detection.

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

import os
import glob
import pytest

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import TestRules


class TestWorkspaceSidConflicts:
    """Integration tests for workspace SID conflict detection"""

    @pytest.fixture
    def workspace_dir(self):
        """Get workspace test directory path"""
        test_dir = os.path.dirname(__file__)
        workspace = os.path.join(
            test_dir, "..", "..", "tests", "workspace_conflict_test"
        )
        return os.path.abspath(workspace)

    @pytest.fixture
    def rules_files(self, workspace_dir):
        """Get list of rules files in workspace"""
        return sorted(glob.glob(os.path.join(workspace_dir, "*.rules")))

    @pytest.fixture
    def workspace_cache(self, rules_files):
        """Create and populate workspace cache with all rules files"""
        cache = MpmCache()
        rules_tester = TestRules()

        for filepath in rules_files:
            s_file = SuricataFile(filepath, rules_tester)
            s_file.load_from_disk()
            s_file.parse_file()

            # Build MPM data (simulates workspace analysis)
            mpm_data = {"buffer": {}, "sids": {}}
            for sig in s_file.sigset.signatures:
                if sig.sid != 0:
                    mpm_data["sids"][sig.sid] = {}

            cache.add_file(filepath, mpm_data)

        return cache

    def test_workspace_has_test_files(self, workspace_dir, rules_files):
        """Verify workspace test directory exists and contains rules files"""
        assert os.path.isdir(
            workspace_dir
        ), f"Workspace directory not found: {workspace_dir}"
        assert len(rules_files) >= 2, "Expected at least 2 rules files in workspace"
        assert any("emerging-threats.rules" in f for f in rules_files)
        assert any("local-custom.rules" in f for f in rules_files)

    def test_workspace_cache_populated(self, workspace_cache):
        """Test that workspace cache is properly populated"""
        stats = workspace_cache.get_statistics()
        assert stats["file_count"] >= 2, "Expected at least 2 files in cache"
        assert stats["total_sids"] >= 5, "Expected multiple SIDs in cache"

    def test_sid_conflicts_detected(self, workspace_dir, workspace_cache):
        """Test that SID conflicts are detected across workspace files"""
        rules_tester = TestRules()

        # Check emerging-threats.rules
        et_file = os.path.join(workspace_dir, "emerging-threats.rules")
        s_file = SuricataFile(et_file, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        workspace = workspace_cache.get_workspace_view(exclude_file=et_file)
        conflicts = s_file._compute_sid_conflicts(workspace)

        # Should detect conflicts (SID 1000001 and 2025002 are in both files)
        assert len(conflicts) > 0, "Expected to find SID conflicts"
        assert 1000001 in conflicts, "Expected SID 1000001 to be flagged as conflict"
        assert 2025002 in conflicts, "Expected SID 2025002 to be flagged as conflict"

    def test_conflict_diagnostics_generated(self, workspace_dir, workspace_cache):
        """Test that conflict diagnostics are properly generated"""
        rules_tester = TestRules()

        local_file = os.path.join(workspace_dir, "local-custom.rules")
        s_file = SuricataFile(local_file, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        workspace = workspace_cache.get_workspace_view(exclude_file=local_file)
        conflicts = s_file._compute_sid_conflicts(workspace)

        assert len(conflicts) > 0, "Expected conflicts"

        # Build diagnostics
        diags = s_file.build_sid_conflict_diagnostics(conflicts)

        assert len(diags) > 0, "Expected diagnostic messages"

        # Verify diagnostic properties
        for diag in diags:
            assert diag.message is not None
            assert "conflicts" in diag.message.lower()
            assert diag.range is not None
            assert diag.sid != 0
            assert "emerging-threats.rules" in diag.message

    def test_no_self_conflicts(self, workspace_dir, workspace_cache):
        """Test that a file doesn't report conflicts with itself"""
        rules_tester = TestRules()

        et_file = os.path.join(workspace_dir, "emerging-threats.rules")
        s_file = SuricataFile(et_file, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        # Get workspace INCLUDING current file
        workspace_with_self = workspace_cache.get_workspace_view()
        conflicts_with_self = s_file._compute_sid_conflicts(workspace_with_self)

        # Get workspace EXCLUDING current file
        workspace_without_self = workspace_cache.get_workspace_view(
            exclude_file=et_file
        )
        conflicts_without_self = s_file._compute_sid_conflicts(workspace_without_self)

        # When we include the file, we should see MORE conflicts (self-conflicts)
        # When we exclude it, we should only see conflicts with OTHER files
        assert len(conflicts_with_self) >= len(conflicts_without_self)

        # The SIDs that appear only in this file should only conflict when including self
        file_sids = {sig.sid for sig in s_file.sigset.signatures if sig.sid != 0}
        workspace_sids = set()
        for file_data in workspace_without_self.values():
            workspace_sids.update(file_data.get("sids", {}).keys())

        unique_to_file = file_sids - workspace_sids
        for sid in unique_to_file:
            # These SIDs should NOT appear in conflicts when file is excluded
            assert sid not in conflicts_without_self

    def test_multiple_file_conflicts(self, workspace_cache):
        """Test detection when SID appears in multiple files"""
        # Add a third file with same conflict
        import tempfile

        rules_tester = TestRules()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            tmp.write(
                'alert tcp any any -> any any (msg:"Another conflict"; sid:1000001;)\n'
            )
            tmp.flush()
            tmp_path = tmp.name

        try:
            # Add to cache
            s_file = SuricataFile(tmp_path, rules_tester)
            s_file.load_from_disk()
            s_file.parse_file()

            mpm_data = {"buffer": {}, "sids": {1000001: {}}}
            workspace_cache.add_file(tmp_path, mpm_data)

            # Now check if 1000001 conflicts are reported from multiple files
            # Build current file SIDs
            current_sids = {1000001: {}}
            conflicts = workspace_cache.get_sid_conflicts(
                current_sids, exclude_file=tmp_path
            )

            assert 1000001 in conflicts
            # Should find at least 2 files with this SID
            assert len(conflicts[1000001]) >= 2

        finally:
            os.unlink(tmp_path)
            workspace_cache.remove_file(tmp_path)
