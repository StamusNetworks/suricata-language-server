#!/usr/bin/env python3
"""Test script for SID conflict detection across workspace files."""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import TestRules


def test_sid_conflicts():
    """Test SID conflict detection."""
    print("Testing SID conflict detection...")

    # Create MPM cache
    cache = MpmCache()

    # Create rules tester (without engine analysis for this test)
    rules_tester = TestRules()

    # Load first file
    file1_path = os.path.join(os.path.dirname(__file__), "conflict-file1.rules")
    file1 = SuricataFile(file1_path, rules_tester)
    file1.load_from_disk()
    file1.parse_file()

    # Manually create mpm_data for file1 (simulate workspace analysis)
    mpm_data1 = {"buffer": {}, "sids": {}}
    for sig in file1.sigset.signatures:
        if sig.sid != 0:
            mpm_data1["sids"][sig.sid] = {}

    cache.add_file(file1_path, mpm_data1)
    print(f"Added {file1_path} with SIDs: {list(mpm_data1['sids'].keys())}")

    # Load second file
    file2_path = os.path.join(os.path.dirname(__file__), "conflict-file2.rules")
    file2 = SuricataFile(file2_path, rules_tester)
    file2.load_from_disk()
    file2.parse_file()

    # Get workspace view (excluding file2)
    workspace = cache.get_workspace_view(exclude_file=file2_path)
    print(f"Workspace (excluding file2): {list(workspace.keys())}")

    # Compute SID conflicts for file2
    conflicts = file2._compute_sid_conflicts(workspace)
    print(f"SID conflicts detected: {conflicts}")

    # Build diagnostics
    if conflicts:
        diags = file2.build_sid_conflict_diagnostics(conflicts)
        print(f"\nGenerated {len(diags)} conflict diagnostic(s):")
        for diag in diags:
            print(f"  - SID {diag.sid}: {diag.message}")
            print(f"    Severity: {diag.severity}")
            print(f"    Range: line {diag.range.start.line}")
    else:
        print("No conflicts detected (unexpected!)")
        return False

    # Test get_sid_conflicts method on MpmCache
    print("\nTesting MpmCache.get_sid_conflicts()...")
    file2_sids = {sig.sid: sig for sig in file2.sigset.signatures if sig.sid != 0}
    cache_conflicts = cache.get_sid_conflicts(file2_sids, exclude_file=file2_path)
    print(f"MpmCache detected conflicts: {cache_conflicts}")

    # Verify we found the expected conflict (SID 9999999)
    if 9999999 in conflicts and 9999999 in cache_conflicts:
        print("\n✓ Test passed: SID 9999999 conflict detected correctly!")
        return True
    else:
        print("\n✗ Test failed: Expected SID 9999999 conflict not found")
        return False


if __name__ == "__main__":
    success = test_sid_conflicts()
    sys.exit(0 if success else 1)
