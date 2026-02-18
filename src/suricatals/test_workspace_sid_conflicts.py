"""Integration test for workspace SID conflict detection."""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from suricatals.mpm_cache import MpmCache
from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import SignaturesTester

logger = logging.getLogger(__name__)


def test_workspace_integration():
    """Test full workspace SID conflict detection workflow."""
    logger.info("Testing Workspace SID Conflict Detection (Full Integration)")

    # Create MPM cache (simulates workspace_mpm in langserver)
    cache = MpmCache()
    logger.debug("Initial cache state: %s", cache)

    # Create rules tester
    rules_tester = SignaturesTester()

    # Simulate workspace analysis - analyze file1
    logger.info("Phase 1: Workspace Analysis (Initial Scan)")
    file1_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "tests", "conflict-file1.rules"
    )
    file1_path = os.path.abspath(file1_path)
    logger.info("Analyzing: %s", file1_path)

    file1 = SuricataFile(file1_path, rules_tester)
    file1.load_from_disk()
    file1.parse_file()

    # Add to workspace cache
    mpm_data1 = {"buffer": {}, "sids": {}}
    for sig in file1.sigset.signatures:
        if sig.sid != 0:
            mpm_data1["sids"][sig.sid] = {}

    cache.add_file(file1_path, mpm_data1)
    logger.debug("File 1 SIDs: %s", sorted(mpm_data1["sids"].keys()))
    logger.debug("Cache state: %s", cache)

    # Simulate opening/editing file2 in editor
    logger.info("Phase 2: File Check (User Opens/Edits File)")
    file2_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "tests", "conflict-file2.rules"
    )
    file2_path = os.path.abspath(file2_path)
    logger.info("Checking: %s", file2_path)

    file2 = SuricataFile(file2_path, rules_tester)
    file2.load_from_disk()
    file2.parse_file()

    file2_sids = [sig.sid for sig in file2.sigset.signatures if sig.sid != 0]
    logger.debug("File 2 SIDs: %s", sorted(file2_sids))

    # Get workspace view (excluding current file)
    workspace = cache.get_workspace_view(exclude_file=file2_path)
    logger.debug("Workspace (excluding current file): %d files", len(workspace))

    # Check for SID conflicts
    conflicts = file2._compute_sid_conflicts(workspace)
    logger.info("SID Conflicts Detected: %s", conflicts)

    # Build diagnostics
    if conflicts:
        diags = file2.build_sid_conflict_diagnostics(conflicts)
        logger.info("Generated %d diagnostic(s)", len(diags))
        for diag in diags:
            logger.debug(
                "Line %d: %s (Severity: %s)",
                diag.range.start.line + 1,
                diag.message,
                diag.severity.name,
            )
    else:
        logger.info("No conflicts detected")

    # Add file2 to cache (simulates workspace_mpm update)
    mpm_data2 = {"buffer": {}, "sids": {}}
    for sig in file2.sigset.signatures:
        if sig.sid != 0:
            mpm_data2["sids"][sig.sid] = {}

    cache.add_file(file2_path, mpm_data2)
    logger.debug("Added file 2 to cache")
    logger.debug("Final cache state: %s", cache)

    # Test get_sid_conflicts method directly on cache
    logger.info("Phase 3: Verify MpmCache.get_sid_conflicts()")
    file2_sids_dict = {sig.sid: sig for sig in file2.sigset.signatures if sig.sid != 0}
    cache_conflicts = cache.get_sid_conflicts(file2_sids_dict, exclude_file=file2_path)
    logger.debug("Conflicts via cache method: %s", cache_conflicts)

    # Verify statistics
    logger.info("Phase 4: Cache Statistics")
    stats = cache.get_statistics()
    logger.debug("Files in cache: %d", stats["file_count"])
    logger.debug("Total SIDs: %d", stats["total_sids"])
    logger.debug("Files with MPM: %d", stats["files_with_mpm"])

    # Verify we found the expected conflict
    if 9999999 in conflicts and 9999999 in cache_conflicts:
        logger.info("TEST PASSED: SID 9999999 conflict detected correctly!")
        assert True, "Expected SID conflict should be detected"
    else:
        logger.error("TEST FAILED: Expected SID 9999999 conflict not found")
        assert False, "Expected SID conflict not detected"
