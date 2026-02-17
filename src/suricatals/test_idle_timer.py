#!/usr/bin/env python3
"""
Simple test for idle timer mechanism (without full Suricata analysis).

Tests the timer scheduling/cancellation logic without actually
running Suricata analysis.

Copyright(C) 2026 Stamus Networks SAS
"""

import sys
import os
import time

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from unittest.mock import Mock, patch
from lsprotocol import types

from suricatals.langserver import LangServer


def test_idle_timer_logic():
    """Test idle timer scheduling and cancellation logic."""
    print("=" * 70)
    print("TEST: Idle Timer Scheduling and Cancellation")
    print("=" * 70)

    # Create langserver with short timeout
    print("\n1. Creating LangServer with 0.3s idle timeout...")
    settings = {"idle_timeout": 0.3}
    lang_server = LangServer(settings=settings)

    # Mock server
    lang_server.server = Mock()

    # Test file URI
    file_uri = "file:///test/test.rules"

    # Test 1: Timer scheduling
    print("\n2. Testing timer scheduling...")
    change_params = Mock()
    change_params.text_document = Mock()
    change_params.text_document.uri = file_uri

    lang_server.serve_on_change(change_params)

    if file_uri in lang_server.idle_timers:
        print("   ✓ Timer scheduled successfully")
    else:
        print("   ✗ Timer not scheduled")
        return False

    # Test 2: Timer rescheduling (cancel + new timer)
    print("\n3. Testing timer rescheduling...")
    first_timer = lang_server.idle_timers[file_uri]

    time.sleep(0.1)  # Wait a bit
    lang_server.serve_on_change(change_params)

    second_timer = lang_server.idle_timers.get(file_uri)

    if second_timer != first_timer:
        print("   ✓ New timer scheduled (old timer replaced)")
    else:
        print("   ✗ Timer not rescheduled")
        return False

    # Test 3: Timer cancellation
    print("\n4. Testing timer cancellation...")
    lang_server._cancel_idle_timer(file_uri)

    if file_uri not in lang_server.idle_timers:
        print("   ✓ Timer cancelled successfully")
    else:
        print("   ✗ Timer not cancelled")
        return False

    # Test 4: Timer execution (with mocked analysis)
    print("\n5. Testing timer execution...")
    analysis_called = []

    def mock_get_diagnostics(uri):
        analysis_called.append(uri)
        return [], None  # Return empty diagnostics

    with patch.object(lang_server, "get_diagnostics", side_effect=mock_get_diagnostics):
        with patch.object(lang_server.server, "text_document_publish_diagnostics"):
            # Schedule timer
            lang_server.serve_on_change(change_params)
            print("   Timer scheduled, waiting for execution...")

            # Wait for timer to fire
            time.sleep(0.5)

            if len(analysis_called) > 0:
                print(f"   ✓ Analysis called after idle period: {analysis_called[0]}")
            else:
                print("   ✗ Analysis not called")
                return False

    # Test 5: Timer cleanup after execution
    print("\n6. Testing timer cleanup...")
    if file_uri not in lang_server.idle_timers:
        print("   ✓ Timer removed after execution")
    else:
        print("   ✗ Timer not removed")
        return False

    # Test 6: Disabled feature (timeout=0)
    print("\n7. Testing disabled feature (timeout=0)...")
    lang_server.idle_timeout = 0
    lang_server.serve_on_change(change_params)

    if file_uri not in lang_server.idle_timers:
        print("   ✓ No timer scheduled when disabled")
    else:
        print("   ✗ Timer scheduled despite being disabled")
        return False

    # Test 7: Non-.rules file (should be ignored)
    print("\n8. Testing non-.rules file...")
    python_params = Mock()
    python_params.text_document = Mock()
    python_params.text_document.uri = "file:///test/test.py"

    lang_server.idle_timeout = 0.3  # Re-enable
    lang_server.serve_on_change(python_params)

    if "file:///test/test.py" not in lang_server.idle_timers:
        print("   ✓ Non-.rules files ignored")
    else:
        print("   ✗ Timer scheduled for non-.rules file")
        return False

    # Summary
    print("\n" + "=" * 70)
    print("✅ TEST PASSED: Idle timer logic working correctly!")
    print("\nFeatures Verified:")
    print("  ✓ Timer scheduling on text change")
    print("  ✓ Timer rescheduling on subsequent changes")
    print("  ✓ Manual timer cancellation")
    print("  ✓ Timer execution after idle period")
    print("  ✓ Timer cleanup after execution")
    print("  ✓ Feature can be disabled (timeout=0)")
    print("  ✓ Only .rules files processed")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = test_idle_timer_logic()
    sys.exit(0 if success else 1)
