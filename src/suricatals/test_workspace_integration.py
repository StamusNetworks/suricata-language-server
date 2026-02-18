"""
Integration test for workspace SID conflict detection.

Simulates the language server's workspace analysis workflow:
1. Add a workspace folder
2. Analyze all rules files in the workspace
3. Open/edit a file and detect SID conflicts

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import glob
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import SignaturesTester

logger = logging.getLogger(__name__)


def analyze_workspace_files(workspace_dir, cache, rules_tester):
    """Simulate workspace analysis - analyze all .rules files in directory."""
    logger.info("WORKSPACE ANALYSIS: %s", workspace_dir)

    rules_files = glob.glob(os.path.join(workspace_dir, "*.rules"))
    logger.info("Found %d rules files", len(rules_files))

    for filepath in sorted(rules_files):
        filename = os.path.basename(filepath)
        logger.info("Analyzing: %s", filename)

        s_file = SuricataFile(filepath, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        # Extract SID list
        sids = [sig.sid for sig in s_file.sigset.signatures if sig.sid != 0]
        logger.debug("SIDs found: %s", sorted(sids))

        # Build MPM data structure (simulate what worker_pool does)
        mpm_data = {"buffer": {}, "sids": {}}
        for sig in s_file.sigset.signatures:
            if sig.sid != 0:
                mpm_data["sids"][sig.sid] = {}

        # Add to workspace cache
        cache.add_file(filepath, mpm_data)
        logger.debug("Added to workspace cache")

    # Show cache statistics
    stats = cache.get_statistics()
    logger.info(
        "Workspace cache: %d files, %d total SIDs",
        stats["file_count"],
        stats["total_sids"],
    )


def check_file_for_conflicts(filepath, cache, rules_tester):
    """Simulate checking a file for SID conflicts (like when user opens/edits it)."""
    filename = os.path.basename(filepath)
    logger.info("FILE CHECK: %s", filename)

    # Load and parse the file
    s_file = SuricataFile(filepath, rules_tester)
    s_file.load_from_disk()
    s_file.parse_file()

    file_sids = [sig.sid for sig in s_file.sigset.signatures if sig.sid != 0]
    logger.debug("File SIDs: %s", sorted(file_sids))

    # Get workspace view (excluding current file)
    workspace = cache.get_workspace_view(exclude_file=filepath)
    logger.debug("Checking against %d other workspace file(s)", len(workspace))

    # Compute conflicts
    conflicts = s_file._compute_sid_conflicts(workspace)

    if conflicts:
        logger.warning("CONFLICTS DETECTED: %d SID(s)", len(conflicts))

        # Build diagnostics
        diags = s_file.build_sid_conflict_diagnostics(conflicts)

        for diag in diags:
            # Get the signature to show line number
            sig = s_file.sigset.get_sig_by_sid(diag.sid)
            line_num = sig.line + 1 if sig else "?"

            logger.debug("SID %d (line %s):", diag.sid, line_num)
            logger.debug("  Message: %s", diag.message)
            logger.debug("  Severity: %s", diag.severity.name)
            if sig:
                logger.debug("  Rule: %s...", sig.content[:80])

        return conflicts

    logger.info("No conflicts detected")
    return {}


def main():
    """Run the integration test."""
    logger.info("SURICATA LANGUAGE SERVER - WORKSPACE SID CONFLICT TEST")

    # Setup
    workspace_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "tests", "workspace_conflict_test"
    )
    workspace_dir = os.path.abspath(workspace_dir)
    cache = MpmCache()
    rules_tester = SignaturesTester()

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
    logger.info("TEST SUMMARY")

    if all_conflicts:
        logger.info("SID conflicts detected in %d file(s):", len(all_conflicts))
        for filename, conflicts in all_conflicts.items():
            logger.info("  - %s: SIDs %s", filename, sorted(conflicts.keys()))

        # Verify expected conflicts
        expected_conflicts = {1000001, 2025002}
        all_conflict_sids = set()
        for conflicts in all_conflicts.values():
            all_conflict_sids.update(conflicts.keys())

        if all_conflict_sids == expected_conflicts:
            logger.info("TEST PASSED: All expected conflicts detected!")
            logger.debug("Expected SIDs: %s", sorted(expected_conflicts))
            logger.debug("Found SIDs: %s", sorted(all_conflict_sids))
        else:
            logger.error("TEST FAILED: Conflict mismatch")
            logger.error("Expected: %s", sorted(expected_conflicts))
            logger.error("Found: %s", sorted(all_conflict_sids))

        assert all_conflict_sids == expected_conflicts, (
            f"Conflict mismatch: expected {sorted(expected_conflicts)}, "
            f"found {sorted(all_conflict_sids)}"
        )
    else:
        logger.error("TEST FAILED: No conflicts detected (expected 2)")

    assert all_conflicts, "No conflicts detected (expected 2)"
