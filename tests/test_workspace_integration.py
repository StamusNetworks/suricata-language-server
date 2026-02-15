#!/usr/bin/env python3
"""
Integration test for workspace SID conflict detection.

Simulates the language server's workspace analysis workflow:
1. Add a workspace folder
2. Analyze all rules files in the workspace
3. Open/edit a file and detect SID conflicts

Copyright(C) 2026 Stamus Networks SAS
"""

import sys
import os
import glob

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import TestRules


def analyze_workspace_files(workspace_dir, cache, rules_tester):
    """Simulate workspace analysis - analyze all .rules files in directory."""
    print(f"\n{'='*70}")
    print(f"WORKSPACE ANALYSIS: {workspace_dir}")
    print("=" * 70)

    rules_files = glob.glob(os.path.join(workspace_dir, "*.rules"))
    print(f"Found {len(rules_files)} rules files")

    for filepath in sorted(rules_files):
        filename = os.path.basename(filepath)
        print(f"\n--- Analyzing: {filename} ---")

        s_file = SuricataFile(filepath, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        # Extract SID list
        sids = [sig.sid for sig in s_file.sigset.signatures if sig.sid != 0]
        print(f"  SIDs found: {sorted(sids)}")

        # Build MPM data structure (simulate what worker_pool does)
        mpm_data = {"buffer": {}, "sids": {}}
        for sig in s_file.sigset.signatures:
            if sig.sid != 0:
                mpm_data["sids"][sig.sid] = {}

        # Add to workspace cache
        cache.add_file(filepath, mpm_data)
        print(f"  ✓ Added to workspace cache")

    # Show cache statistics
    print(f"\n{'-'*70}")
    stats = cache.get_statistics()
    print(
        f"Workspace cache: {stats['file_count']} files, {stats['total_sids']} total SIDs"
    )
    print(f"{'-'*70}")


def check_file_for_conflicts(filepath, cache, rules_tester):
    """Simulate checking a file for SID conflicts (like when user opens/edits it)."""
    filename = os.path.basename(filepath)
    print(f"\n{'='*70}")
    print(f"FILE CHECK: {filename}")
    print("=" * 70)

    # Load and parse the file
    s_file = SuricataFile(filepath, rules_tester)
    s_file.load_from_disk()
    s_file.parse_file()

    file_sids = [sig.sid for sig in s_file.sigset.signatures if sig.sid != 0]
    print(f"File SIDs: {sorted(file_sids)}")

    # Get workspace view (excluding current file)
    workspace = cache.get_workspace_view(exclude_file=filepath)
    print(f"Checking against {len(workspace)} other workspace file(s)")

    # Compute conflicts
    conflicts = s_file._compute_sid_conflicts(workspace)

    if conflicts:
        print(f"\n⚠️  CONFLICTS DETECTED: {len(conflicts)} SID(s)")

        # Build diagnostics
        diags = s_file.build_sid_conflict_diagnostics(conflicts)

        for diag in diags:
            # Get the signature to show line number
            sig = s_file.sigset.get_sig_by_sid(diag.sid)
            line_num = sig.line + 1 if sig else "?"

            print(f"\n  SID {diag.sid} (line {line_num}):")
            print(f"    Message: {diag.message}")
            print(f"    Severity: {diag.severity.name}")
            if sig:
                print(f"    Rule: {sig.content[:80]}...")

        return conflicts
    else:
        print("\n✓ No conflicts detected")
        return {}


def main():
    """Run the integration test."""
    print("\n" + "=" * 70)
    print("SURICATA LANGUAGE SERVER - WORKSPACE SID CONFLICT TEST")
    print("=" * 70)

    # Setup
    workspace_dir = os.path.join(os.path.dirname(__file__), "workspace_conflict_test")
    cache = MpmCache()
    rules_tester = TestRules()

    # Phase 1: Analyze workspace (simulates WORKSPACE_DID_CHANGE_WORKSPACE_FOLDERS)
    analyze_workspace_files(workspace_dir, cache, rules_tester)

    # Phase 2: Check each file for conflicts (simulates opening files in editor)
    all_conflicts = {}

    for filename in ["emerging-threats.rules", "local-custom.rules"]:
        filepath = os.path.join(workspace_dir, filename)
        conflicts = check_file_for_conflicts(filepath, cache, rules_tester)
        if conflicts:
            all_conflicts[filename] = conflicts

    # Summary
    print(f"\n{'='*70}")
    print("TEST SUMMARY")
    print("=" * 70)

    if all_conflicts:
        print(f"\n✓ SID conflicts detected in {len(all_conflicts)} file(s):")
        for filename, conflicts in all_conflicts.items():
            print(f"  - {filename}: SIDs {sorted(conflicts.keys())}")

        # Verify expected conflicts
        expected_conflicts = {1000001, 2025002}
        all_conflict_sids = set()
        for conflicts in all_conflicts.values():
            all_conflict_sids.update(conflicts.keys())

        if all_conflict_sids == expected_conflicts:
            print(f"\n✅ TEST PASSED: All expected conflicts detected!")
            print(f"   Expected SIDs: {sorted(expected_conflicts)}")
            print(f"   Found SIDs: {sorted(all_conflict_sids)}")
            return True
        else:
            print(f"\n❌ TEST FAILED: Conflict mismatch")
            print(f"   Expected: {sorted(expected_conflicts)}")
            print(f"   Found: {sorted(all_conflict_sids)}")
            return False
    else:
        print("\n❌ TEST FAILED: No conflicts detected (expected 2)")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
