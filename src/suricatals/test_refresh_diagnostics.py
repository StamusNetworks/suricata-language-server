"""
Test script for automatic diagnostic refresh when workspace changes.

This simulates:
1. Opening files in the editor
2. Analyzing workspace (which detects SID conflicts)
3. Verifying that open files get their diagnostics automatically refreshed

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from unittest.mock import Mock

from suricatals.langserver import LangServer, path_from_uri

logger = logging.getLogger(__name__)


def test_refresh_diagnostics_on_workspace_update():
    """Test that open files get diagnostics refreshed after workspace analysis."""
    logger.info("TEST: Automatic Diagnostic Refresh on Workspace Update")

    # Create langserver instance
    logger.info("1. Creating LangServer instance")
    lang_server = LangServer(None)

    # Initialize rules tester
    from suricatals.signature_validator import SignaturesTester

    lang_server.rules_tester = SignaturesTester()

    # Set workspace dir
    workspace_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "tests", "workspace_conflict_test"
    )
    workspace_dir = os.path.abspath(workspace_dir)
    lang_server.source_dirs.append(workspace_dir)

    # Mock the pygls server and workspace
    lang_server.server = Mock()
    lang_server.server.workspace = Mock()

    # Simulate opening a file in the editor
    file_uri = f"file://{os.path.join(workspace_dir, 'local-custom.rules')}"
    filepath = path_from_uri(file_uri)

    logger.info("2. Simulating opened file: %s", os.path.basename(filepath))

    # Mock text_documents dictionary
    mock_text_doc = Mock()
    mock_text_doc.uri = file_uri
    mock_text_doc.source = """# Local custom rules
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH Brute Force"; sid:1000001;)
alert tcp any any -> $HOME_NET 3389 (msg:"LOCAL RDP Connection"; sid:1000002;)
alert tcp any any -> any 443 (msg:"LOCAL TLS 1.0"; sid:2025002;)
"""
    mock_text_doc.lines = mock_text_doc.source.split("\n")

    lang_server.server.workspace.text_documents = {file_uri: mock_text_doc}
    lang_server.server.workspace.get_text_document = lambda uri: (
        mock_text_doc if uri == file_uri else None
    )

    # Track diagnostic publish calls
    published_diagnostics = []

    def mock_publish_diagnostics(params):
        published_diagnostics.append(
            {
                "uri": params.uri,
                "count": len(params.diagnostics),
                "diagnostics": params.diagnostics,
            }
        )
        logger.debug(
            "Published %d diagnostic(s) for %s",
            len(params.diagnostics),
            os.path.basename(path_from_uri(params.uri)),
        )

    lang_server.server.text_document_publish_diagnostics = mock_publish_diagnostics

    # First, check the file without workspace context (no conflicts expected)
    logger.info("3. Initial file check (before workspace analysis)")
    diag_results, _ = lang_server.get_diagnostics(file_uri)

    if diag_results is not None:
        # Count SID conflict warnings
        conflict_warnings = [d for d in diag_results if "conflict" in d.message.lower()]
        logger.debug(
            "Initial diagnostics: %d total, %d SID conflicts",
            len(diag_results),
            len(conflict_warnings),
        )
    else:
        logger.debug("No diagnostics generated")

    published_diagnostics.clear()

    # Now analyze the workspace
    logger.info("4. Analyzing workspace")
    rules_files = [
        os.path.join(workspace_dir, "emerging-threats.rules"),
        os.path.join(workspace_dir, "local-custom.rules"),
    ]

    # Manually populate workspace cache (simulate workspace analysis)
    from suricatals.signature_parser import SuricataFile

    rules_tester = SignaturesTester()
    for rules_file in rules_files:
        s_file = SuricataFile(rules_file, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        mpm_data = {"buffer": {}, "sids": {}}
        for sig in s_file.sigset.signatures:
            if sig.sid != 0:
                mpm_data["sids"][sig.sid] = {}

        lang_server.workspace_mpm.add_file(rules_file, mpm_data)

    logger.debug(
        "Workspace cache: %d SIDs",
        lang_server.workspace_mpm.get_statistics()["total_sids"],
    )

    # Manually trigger diagnostic refresh (simulates what happens after workspace analysis)
    logger.info("5. Triggering automatic diagnostic refresh")
    lang_server._refresh_open_file_diagnostics()

    # Verify diagnostics were republished
    logger.info("6. Verifying results")
    if len(published_diagnostics) > 0:
        logger.info(
            "Diagnostics were automatically refreshed for %d file(s)",
            len(published_diagnostics),
        )

        # Check for SID conflict warnings
        for pub in published_diagnostics:
            conflict_count = sum(
                1 for d in pub["diagnostics"] if "conflict" in d.message.lower()
            )
            if conflict_count > 0:
                logger.info(
                    "Found %d SID conflict warning(s) in refreshed diagnostics",
                    conflict_count,
                )
                logger.debug("Conflicts detected:")
                for diag in pub["diagnostics"]:
                    if "conflict" in diag.message.lower():
                        logger.debug(
                            "Line %d: %s", diag.range.start.line + 1, diag.message
                        )
    else:
        logger.warning("No diagnostics were republished")

    assert len(published_diagnostics) > 0, "Diagnostics should be republished"

    # Final verification
    if len(published_diagnostics) > 0:
        conflict_count = sum(
            1
            for pub in published_diagnostics
            for d in pub["diagnostics"]
            if "conflict" in d.message.lower()
        )
        if conflict_count >= 2:
            logger.info("TEST PASSED: Found %d SID conflicts", conflict_count)
        else:
            logger.error(
                "TEST FAILED: Expected at least 2 SID conflicts, found %d",
                conflict_count,
            )
        assert conflict_count >= 2, "Expected at least 2 SID conflicts"
    else:
        logger.error("TEST FAILED: Diagnostics were not refreshed")
        assert False, "Diagnostics were not refreshed"
