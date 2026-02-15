#!/usr/bin/env python3
"""Integration test for workspace SID conflict detection."""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import TestRules


def test_workspace_integration():
    """Test full workspace SID conflict detection workflow."""
    print("=" * 70)
    print("Testing Workspace SID Conflict Detection (Full Integration)")
    print("=" * 70)

    # Create MPM cache (simulates workspace_mpm in langserver)
    cache = MpmCache()
    print(f"\nInitial cache state: {cache}")

    # Create rules tester
    rules_tester = TestRules()

    # Simulate workspace analysis - analyze file1
    print("\n--- Phase 1: Workspace Analysis (Initial Scan) ---")
    file1_path = os.path.join(os.path.dirname(__file__), "conflict-file1.rules")
    print(f"Analyzing: {file1_path}")

    file1 = SuricataFile(file1_path, rules_tester)
    file1.load_from_disk()
    file1.parse_file()

    # Add to workspace cache
    mpm_data1 = {"buffer": {}, "sids": {}}
    for sig in file1.sigset.signatures:
        if sig.sid != 0:
            mpm_data1["sids"][sig.sid] = {}

    cache.add_file(file1_path, mpm_data1)
    print(f"  ✓ File 1 SIDs: {sorted(mpm_data1['sids'].keys())}")
    print(f"  Cache state: {cache}")

    # Simulate opening/editing file2 in editor
    print("\n--- Phase 2: File Check (User Opens/Edits File) ---")
    file2_path = os.path.join(os.path.dirname(__file__), "conflict-file2.rules")
    print(f"Checking: {file2_path}")

    file2 = SuricataFile(file2_path, rules_tester)
    file2.load_from_disk()
    file2.parse_file()

    file2_sids = [sig.sid for sig in file2.sigset.signatures if sig.sid != 0]
    print(f"  File 2 SIDs: {sorted(file2_sids)}")

    # Get workspace view (excluding current file)
    workspace = cache.get_workspace_view(exclude_file=file2_path)
    print(f"  Workspace (excluding current file): {len(workspace)} files")

    # Check for SID conflicts
    conflicts = file2._compute_sid_conflicts(workspace)
    print(f"\n  SID Conflicts Detected: {conflicts}")

    # Build diagnostics
    if conflicts:
        diags = file2.build_sid_conflict_diagnostics(conflicts)
        print(f"\n  Generated {len(diags)} diagnostic(s):")
        for diag in diags:
            print(f"    ⚠️  Line {diag.range.start.line + 1}: {diag.message}")
            print(f"       Severity: {diag.severity.name}")
    else:
        print("  ℹ️  No conflicts detected")

    # Add file2 to cache (simulates workspace_mpm update)
    mpm_data2 = {"buffer": {}, "sids": {}}
    for sig in file2.sigset.signatures:
        if sig.sid != 0:
            mpm_data2["sids"][sig.sid] = {}

    cache.add_file(file2_path, mpm_data2)
    print(f"\n  ✓ Added file 2 to cache")
    print(f"  Final cache state: {cache}")

    # Test get_sid_conflicts method directly on cache
    print("\n--- Phase 3: Verify MpmCache.get_sid_conflicts() ---")
    file2_sids_dict = {sig.sid: sig for sig in file2.sigset.signatures if sig.sid != 0}
    cache_conflicts = cache.get_sid_conflicts(file2_sids_dict, exclude_file=file2_path)
    print(f"  Conflicts via cache method: {cache_conflicts}")

    # Verify statistics
    print("\n--- Phase 4: Cache Statistics ---")
    stats = cache.get_statistics()
    print(f"  Files in cache: {stats['file_count']}")
    print(f"  Total SIDs: {stats['total_sids']}")
    print(f"  Files with MPM: {stats['files_with_mpm']}")

    # Verify we found the expected conflict
    print("\n" + "=" * 70)
    if 9999999 in conflicts and 9999999 in cache_conflicts:
        print("✅ TEST PASSED: SID 9999999 conflict detected correctly!")
        print("=" * 70)
        return True
    else:
        print("❌ TEST FAILED: Expected SID 9999999 conflict not found")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = test_workspace_integration()
    sys.exit(0 if success else 1)
