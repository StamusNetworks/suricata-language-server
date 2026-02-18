"""
Simple test for idle timer mechanism (without full Suricata analysis).

Tests the timer scheduling/cancellation logic without actually
running Suricata analysis.

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import time
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from unittest.mock import Mock, patch

from suricatals.langserver import LangServer

logger = logging.getLogger(__name__)


def test_idle_timer_logic():
    """Test idle timer scheduling and cancellation logic."""
    logger.info("TEST: Idle Timer Scheduling and Cancellation")

    # Create langserver with short timeout
    logger.info("1. Creating LangServer with 0.3s idle timeout")
    settings = {"idle_timeout": 0.3}
    lang_server = LangServer(settings=settings)

    # Mock server
    lang_server.server = Mock()

    # Test file URI
    file_uri = "file:///test/test.rules"

    # Test 1: Timer scheduling
    logger.info("2. Testing timer scheduling")
    change_params = Mock()
    change_params.text_document = Mock()
    change_params.text_document.uri = file_uri

    lang_server.serve_on_change(change_params)

    if file_uri in lang_server.idle_timers:
        logger.debug("Timer scheduled successfully")
    else:
        logger.error("Timer not scheduled")

    assert file_uri in lang_server.idle_timers, "Timer should be scheduled"

    # Test 2: Timer rescheduling (cancel + new timer)
    logger.info("3. Testing timer rescheduling")
    first_timer = lang_server.idle_timers[file_uri]

    time.sleep(0.1)  # Wait a bit
    lang_server.serve_on_change(change_params)

    second_timer = lang_server.idle_timers.get(file_uri)

    if second_timer != first_timer:
        logger.debug("New timer scheduled (old timer replaced)")
    else:
        logger.error("Timer not rescheduled")

    assert second_timer != first_timer, "Timer should be rescheduled"

    # Test 3: Timer cancellation
    logger.info("4. Testing timer cancellation")
    lang_server._cancel_idle_timer(file_uri)

    if file_uri not in lang_server.idle_timers:
        logger.debug("Timer cancelled successfully")
    else:
        logger.error("Timer not cancelled")

    assert file_uri not in lang_server.idle_timers, "Timer should be cancelled"

    # Test 4: Timer execution (with mocked analysis)
    logger.info("5. Testing timer execution")
    analysis_called = []

    def mock_get_diagnostics(uri):
        analysis_called.append(uri)
        return [], None  # Return empty diagnostics

    with patch.object(lang_server, "get_diagnostics", side_effect=mock_get_diagnostics):
        with patch.object(lang_server.server, "text_document_publish_diagnostics"):
            # Schedule timer
            lang_server.serve_on_change(change_params)
            logger.debug("Timer scheduled, waiting for execution")

            # Wait for timer to fire
            time.sleep(0.5)

            if len(analysis_called) > 0:
                logger.debug(
                    "Analysis called after idle period: %s", analysis_called[0]
                )
            else:
                logger.error("Analysis not called")

            assert (
                len(analysis_called) > 0
            ), "Analysis should be called after idle period"

    # Test 5: Timer cleanup after execution
    logger.info("6. Testing timer cleanup")
    if file_uri not in lang_server.idle_timers:
        logger.debug("Timer removed after execution")
    else:
        logger.error("Timer not removed")

    assert file_uri not in lang_server.idle_timers, "Timer should be removed"

    # Test 6: Disabled feature (timeout=0)
    logger.info("7. Testing disabled feature (timeout=0)")
    lang_server.idle_timeout = 0
    lang_server.serve_on_change(change_params)

    if file_uri not in lang_server.idle_timers:
        logger.debug("No timer scheduled when disabled")
    else:
        logger.error("Timer scheduled despite being disabled")

    assert (
        file_uri not in lang_server.idle_timers
    ), "Timer should not be scheduled when disabled"

    # Test 7: Non-.rules file (should be ignored)
    logger.info("8. Testing non-.rules file")
    python_params = Mock()
    python_params.text_document = Mock()
    python_params.text_document.uri = "file:///test/test.py"

    lang_server.idle_timeout = 0.3  # Re-enable
    lang_server.serve_on_change(python_params)

    if "file:///test/test.py" not in lang_server.idle_timers:
        logger.debug("Non-.rules files ignored")
    else:
        logger.error("Timer scheduled for non-.rules file")

    assert (
        "file:///test/test.py" not in lang_server.idle_timers
    ), "Non-.rules files should be ignored"

    # Summary
    logger.info("TEST PASSED: Idle timer logic working correctly!")
    logger.info("Features Verified:")
    logger.info("  Timer scheduling on text change")
    logger.info("  Timer rescheduling on subsequent changes")
    logger.info("  Manual timer cancellation")
    logger.info("  Timer execution after idle period")
    logger.info("  Timer cleanup after execution")
    logger.info("  Feature can be disabled (timeout=0)")
    logger.info("  Only .rules files processed")
    assert True, "Idle timer logic should work correctly"
