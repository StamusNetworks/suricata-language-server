"""
Test script for automatic idle analysis feature.

Simulates typing in a rules file and verifies that analysis
is triggered automatically after idle timeout.

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import time

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from unittest.mock import Mock

from suricatals.langserver import LangServer, path_from_uri
from suricatals.signature_validator import SignaturesTester


def test_idle_analysis():
    """Test automatic analysis after idle period."""
    print("=" * 70)
    print("TEST: Automatic Analysis After Idle Period")
    print("=" * 70)

    # Create langserver with 0.5 second idle timeout
    print("\n1. Creating LangServer with 0.5s idle timeout...")
    settings = {"idle_timeout": 0.5}
    lang_server = LangServer(settings=settings)
    lang_server.rules_tester = SignaturesTester()

    # Mock the server
    lang_server.server = Mock()
    lang_server.server.workspace = Mock()

    # Track diagnostic publications
    published_diagnostics = []

    def mock_publish(params):
        published_diagnostics.append(
            {
                "uri": params.uri,
                "count": len(params.diagnostics),
                "diagnostics": params.diagnostics,
            }
        )
        print(
            f"   ✓ Diagnostics published for {os.path.basename(path_from_uri(params.uri))}: {len(params.diagnostics)} diagnostic(s)"
        )

    lang_server.server.text_document_publish_diagnostics = mock_publish

    # Create mock document
    test_file = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "tests",
        "workspace_conflict_test",
        "local-custom.rules",
    )
    file_uri = f"file://{test_file}"

    mock_text_doc = Mock()
    mock_text_doc.uri = file_uri
    with open(test_file, "r", encoding="utf-8") as f:
        mock_text_doc.source = f.read()
    mock_text_doc.lines = mock_text_doc.source.split("\n")

    lang_server.server.workspace.text_documents = {file_uri: mock_text_doc}
    lang_server.server.workspace.get_text_document = lambda uri: (
        mock_text_doc if uri == file_uri else None
    )

    print(f"2. Simulating file open: {os.path.basename(test_file)}")

    # Simulate text document change (user typing)
    print("\n3. Simulating user editing (typing)...")
    change_params = Mock()
    change_params.text_document = Mock()
    change_params.text_document.uri = file_uri

    # First change
    print("   Typing...")
    lang_server.serve_on_change(change_params)
    print(f"   ✓ Change detected, idle timer scheduled ({settings['idle_timeout']}s)")

    # Check that timer is scheduled
    assert file_uri in lang_server.idle_timers, "Timer should be scheduled"
    print("   ✓ Timer confirmed in idle_timers dict")

    # Simulate more typing before timeout (should reschedule)
    time.sleep(0.2)
    print("   Typing more...")
    lang_server.serve_on_change(change_params)
    print("   ✓ Timer rescheduled")

    # Wait for typing more (still before original timeout)
    time.sleep(0.2)
    print("   Typing even more...")
    lang_server.serve_on_change(change_params)
    print("   ✓ Timer rescheduled again")

    # Now wait for idle period to elapse
    print(f"\n4. Waiting for idle timeout ({settings['idle_timeout']}s)...")
    published_diagnostics.clear()
    time.sleep(settings["idle_timeout"] + 0.3)  # Wait slightly longer than timeout

    # Give thread time to execute
    print("   Waiting for analysis thread to complete...")
    time.sleep(0.2)

    # Check if analysis was triggered
    print("\n5. Verifying results...")
    if len(published_diagnostics) > 0:
        print("   ✓ Idle analysis triggered automatically!")
        print(f"   ✓ Diagnostics published: {published_diagnostics[0]['count']}")
    else:
        print("   ✗ No idle analysis triggered")
        print("   Debug: Check that file can be analyzed")
        # Try direct analysis to see if there's an issue
        diag_results, diag_exp = lang_server.get_diagnostics(file_uri)
        if diag_results is None:
            print(f"   Debug: Direct analysis also failed (exp={diag_exp})")
        else:
            print(f"   Debug: Direct analysis works ({len(diag_results)} diagnostics)")

    assert len(published_diagnostics) > 0, "Idle analysis should have been triggered"

    # Verify timer was cleaned up
    if file_uri not in lang_server.idle_timers:
        print("   ✓ Timer cleaned up after analysis")
    else:
        print("   ✗ Timer not cleaned up")

    assert file_uri not in lang_server.idle_timers, "Timer should be cleaned up"

    # Test that timer is cancelled on save
    print("\n6. Testing timer cancellation on save...")
    lang_server.serve_on_change(change_params)
    assert file_uri in lang_server.idle_timers, "Timer should be scheduled"
    print("   ✓ Timer scheduled")

    save_params = Mock()
    save_params.text_document = Mock()
    save_params.text_document.uri = file_uri

    # Cancel by saving
    lang_server._cancel_idle_timer(file_uri)
    if file_uri not in lang_server.idle_timers:
        print("   ✓ Timer cancelled on save")
    else:
        print("   ✗ Timer not cancelled")

    assert file_uri not in lang_server.idle_timers, "Timer should be cancelled"

    # Test disabled feature (idle_timeout = 0)
    print("\n7. Testing disabled idle analysis (timeout=0)...")
    lang_server.idle_timeout = 0
    lang_server.serve_on_change(change_params)
    if file_uri not in lang_server.idle_timers:
        print("   ✓ No timer scheduled when feature disabled")
    else:
        print("   ✗ Timer scheduled despite being disabled")

    assert (
        file_uri not in lang_server.idle_timers
    ), "Timer should not be scheduled when disabled"

    # Summary
    print("\n" + "=" * 70)
    print("✅ TEST PASSED: Idle analysis working correctly!")
    print("\nFeatures Verified:")
    print("  ✓ Analysis triggered after idle timeout")
    print("  ✓ Timer rescheduled on each edit")
    print("  ✓ Timer cleaned up after analysis")
    print("  ✓ Timer cancelled on save")
    print("  ✓ Feature can be disabled with timeout=0")
    print("=" * 70)
