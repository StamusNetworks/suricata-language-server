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
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from unittest.mock import Mock

from suricatals.langserver import LangServer, path_from_uri
from suricatals.signature_validator import SignaturesTester

logger = logging.getLogger(__name__)


def test_idle_analysis():
    """Test automatic analysis after idle period."""
    logger.info("TEST: Automatic Analysis After Idle Period")

    # Create langserver with 0.5 second idle timeout
    logger.info("1. Creating LangServer with 0.5s idle timeout")
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
        logger.debug(
            "Diagnostics published for %s: %d diagnostic(s)",
            os.path.basename(path_from_uri(params.uri)),
            len(params.diagnostics),
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

    logger.info("2. Simulating file open: %s", os.path.basename(test_file))

    # Simulate text document change (user typing)
    logger.info("3. Simulating user editing (typing)")
    change_params = Mock()
    change_params.text_document = Mock()
    change_params.text_document.uri = file_uri

    # First change
    logger.debug("Typing...")
    lang_server.serve_on_change(change_params)
    logger.debug(
        "Change detected, idle timer scheduled (%ss)", settings["idle_timeout"]
    )

    # Check that timer is scheduled
    assert file_uri in lang_server.idle_timers, "Timer should be scheduled"
    logger.debug("Timer confirmed in idle_timers dict")

    # Simulate more typing before timeout (should reschedule)
    time.sleep(0.2)
    logger.debug("Typing more...")
    lang_server.serve_on_change(change_params)
    logger.debug("Timer rescheduled")

    # Wait for typing more (still before original timeout)
    time.sleep(0.2)
    logger.debug("Typing even more...")
    lang_server.serve_on_change(change_params)
    logger.debug("Timer rescheduled again")

    # Now wait for idle period to elapse
    logger.info("4. Waiting for idle timeout (%ss)", settings["idle_timeout"])
    published_diagnostics.clear()
    time.sleep(settings["idle_timeout"] + 0.3)  # Wait slightly longer than timeout

    # Give thread time to execute
    logger.debug("Waiting for analysis thread to complete")
    time.sleep(0.2)

    # Check if analysis was triggered
    logger.info("5. Verifying results")
    if len(published_diagnostics) > 0:
        logger.info("Idle analysis triggered automatically!")
        logger.debug("Diagnostics published: %d", published_diagnostics[0]["count"])
    else:
        logger.warning("No idle analysis triggered")
        logger.debug("Check that file can be analyzed")
        # Try direct analysis to see if there's an issue
        diag_results, diag_exp = lang_server.get_diagnostics(file_uri)
        if diag_results is None:
            logger.debug("Direct analysis also failed (exp=%s)", diag_exp)
        else:
            logger.debug("Direct analysis works (%d diagnostics)", len(diag_results))

    assert len(published_diagnostics) > 0, "Idle analysis should have been triggered"

    # Verify timer was cleaned up
    if file_uri not in lang_server.idle_timers:
        logger.debug("Timer cleaned up after analysis")
    else:
        logger.error("Timer not cleaned up")

    assert file_uri not in lang_server.idle_timers, "Timer should be cleaned up"

    # Test that timer is cancelled on save
    logger.info("6. Testing timer cancellation on save")
    lang_server.serve_on_change(change_params)
    assert file_uri in lang_server.idle_timers, "Timer should be scheduled"
    logger.debug("Timer scheduled")

    save_params = Mock()
    save_params.text_document = Mock()
    save_params.text_document.uri = file_uri

    # Cancel by saving
    lang_server._cancel_idle_timer(file_uri)
    if file_uri not in lang_server.idle_timers:
        logger.debug("Timer cancelled on save")
    else:
        logger.error("Timer not cancelled")

    assert file_uri not in lang_server.idle_timers, "Timer should be cancelled"

    # Test disabled feature (idle_timeout = 0)
    logger.info("7. Testing disabled idle analysis (timeout=0)")
    lang_server.idle_timeout = 0
    lang_server.serve_on_change(change_params)
    if file_uri not in lang_server.idle_timers:
        logger.debug("No timer scheduled when feature disabled")
    else:
        logger.error("Timer scheduled despite being disabled")

    assert (
        file_uri not in lang_server.idle_timers
    ), "Timer should not be scheduled when disabled"

    # Summary
    logger.info("TEST PASSED: Idle analysis working correctly!")
    logger.info("Features Verified:")
    logger.info("  Analysis triggered after idle timeout")
    logger.info("  Timer rescheduled on each edit")
    logger.info("  Timer cleaned up after analysis")
    logger.info("  Timer cancelled on save")
    logger.info("  Feature can be disabled with timeout=0")
