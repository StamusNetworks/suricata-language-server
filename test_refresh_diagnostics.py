#!/usr/bin/env python3
"""
Test script for automatic diagnostic refresh when workspace changes.

This simulates:
1. Opening files in the editor
2. Analyzing workspace (which detects SID conflicts)
3. Verifying that open files get their diagnostics automatically refreshed

Copyright(C) 2026 Stamus Networks SAS
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock, Mock
from lsprotocol import types

from suricatals.langserver import LangServer, path_from_uri


def test_refresh_diagnostics_on_workspace_update():
    """Test that open files get diagnostics refreshed after workspace analysis."""
    print("=" * 70)
    print("TEST: Automatic Diagnostic Refresh on Workspace Update")
    print("=" * 70)

    # Create langserver instance
    print("\n1. Creating LangServer instance...")
    lang_server = LangServer(None)

    # Initialize rules tester
    from suricatals.signature_validator import TestRules

    lang_server.rules_tester = TestRules()

    # Set workspace dir
    workspace_dir = os.path.join(os.path.dirname(__file__), "workspace_conflict_test")
    lang_server.source_dirs.append(workspace_dir)

    # Mock the pygls server and workspace
    lang_server.server = Mock()
    lang_server.server.workspace = Mock()

    # Simulate opening a file in the editor
    file_uri = f"file://{os.path.join(workspace_dir, 'local-custom.rules')}"
    filepath = path_from_uri(file_uri)

    print(f"2. Simulating opened file: {os.path.basename(filepath)}")

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
        print(
            f"   ✓ Published {len(params.diagnostics)} diagnostic(s) for {os.path.basename(path_from_uri(params.uri))}"
        )

    lang_server.server.text_document_publish_diagnostics = mock_publish_diagnostics

    # First, check the file without workspace context (no conflicts expected)
    print("\n3. Initial file check (before workspace analysis)...")
    diag_results, _ = lang_server.get_diagnostics(file_uri)

    if diag_results is not None:
        # Count SID conflict warnings
        conflict_warnings = [d for d in diag_results if "conflict" in d.message.lower()]
        print(
            f"   Initial diagnostics: {len(diag_results)} total, {len(conflict_warnings)} SID conflicts"
        )
    else:
        print("   No diagnostics generated")

    published_diagnostics.clear()

    # Now analyze the workspace
    print("\n4. Analyzing workspace...")
    rules_files = [
        os.path.join(workspace_dir, "emerging-threats.rules"),
        os.path.join(workspace_dir, "local-custom.rules"),
    ]

    # Manually populate workspace cache (simulate workspace analysis)
    from suricatals.signature_parser import SuricataFile
    from suricatals.signature_validator import TestRules

    rules_tester = TestRules()
    for rules_file in rules_files:
        s_file = SuricataFile(rules_file, rules_tester)
        s_file.load_from_disk()
        s_file.parse_file()

        mpm_data = {"buffer": {}, "sids": {}}
        for sig in s_file.sigset.signatures:
            if sig.sid != 0:
                mpm_data["sids"][sig.sid] = {}

        lang_server.workspace_mpm.add_file(rules_file, mpm_data)

    print(
        f"   Workspace cache: {lang_server.workspace_mpm.get_statistics()['total_sids']} SIDs"
    )

    # Manually trigger diagnostic refresh (simulates what happens after workspace analysis)
    print("\n5. Triggering automatic diagnostic refresh...")
    lang_server._refresh_open_file_diagnostics()

    # Verify diagnostics were republished
    print("\n6. Verifying results...")
    if len(published_diagnostics) > 0:
        print(
            f"   ✓ Diagnostics were automatically refreshed for {len(published_diagnostics)} file(s)"
        )

        # Check for SID conflict warnings
        for pub in published_diagnostics:
            conflict_count = sum(
                1 for d in pub["diagnostics"] if "conflict" in d.message.lower()
            )
            if conflict_count > 0:
                print(
                    f"   ✓ Found {conflict_count} SID conflict warning(s) in refreshed diagnostics"
                )
                print(f"   Conflicts detected:")
                for diag in pub["diagnostics"]:
                    if "conflict" in diag.message.lower():
                        print(
                            f"     - Line {diag.range.start.line + 1}: {diag.message}"
                        )
    else:
        print("   ✗ No diagnostics were republished")
        return False

    # Final verification
    print("\n" + "=" * 70)
    if len(published_diagnostics) > 0:
        conflict_count = sum(
            1
            for pub in published_diagnostics
            for d in pub["diagnostics"]
            if "conflict" in d.message.lower()
        )
        if (
            conflict_count >= 2
        ):  # We expect at least 2 conflicts (SID 1000001 and 2025002)
            print(
                "✅ TEST PASSED: Diagnostics automatically refreshed with SID conflicts!"
            )
            print(f"   Open files: 1")
            print(f"   Diagnostics refreshed: {len(published_diagnostics)}")
            print(f"   SID conflicts detected: {conflict_count}")
            print("=" * 70)
            return True
        else:
            print("❌ TEST FAILED: Expected at least 2 SID conflicts")
            print("=" * 70)
            return False
    else:
        print("❌ TEST FAILED: Diagnostics were not refreshed")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = test_refresh_diagnostics_on_workspace_update()
    sys.exit(0 if success else 1)
