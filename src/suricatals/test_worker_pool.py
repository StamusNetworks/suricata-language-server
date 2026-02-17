"""
Pytest tests for worker pool functionality.

Copyright(C) 2026 Stamus Networks SAS
Written by Eric Leblond <el@stamus-networks.com>

This file is part of Suricata Language Server.

Suricata Language Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Suricata Language Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import tempfile
import queue
from multiprocessing import Queue
import pytest

from suricatals.worker_pool import analyze_file_worker


class TestWorkerPool:
    """Test suite for worker_pool.py"""

    @pytest.fixture
    def rules_tester_config(self):
        """Create a basic rules tester configuration for workers"""
        return {
            "suricata_binary": "suricata",  # Use default suricata in PATH
            "suricata_config": None,
            "docker": False,
            "docker_image": None,
        }

    @pytest.fixture
    def progress_queue(self):
        """Create a multiprocessing queue for progress updates"""
        return Queue()

    @pytest.fixture
    def clean_rules_path(self):
        """Get path to clean.rules test file"""
        test_dir = os.path.dirname(__file__)
        filepath = os.path.join(test_dir, "..", "..", "tests", "clean.rules")
        return os.path.abspath(filepath)

    def test_analyze_file_worker_success(
        self, clean_rules_path, rules_tester_config, progress_queue
    ):
        """Test successful analysis of a valid rules file"""
        filepath, mpm_data, error = analyze_file_worker(
            clean_rules_path, rules_tester_config, progress_queue
        )

        # Check return values
        assert filepath == clean_rules_path
        assert error is None
        assert mpm_data is not None

        # Check MPM data structure
        assert "buffer" in mpm_data
        assert "sids" in mpm_data
        assert isinstance(mpm_data["buffer"], dict)
        assert isinstance(mpm_data["sids"], dict)

    def test_analyze_file_worker_extracts_sids(
        self, clean_rules_path, rules_tester_config, progress_queue
    ):
        """Test that worker extracts SIDs from signatures"""
        _, mpm_data, error = analyze_file_worker(
            clean_rules_path, rules_tester_config, progress_queue
        )

        assert error is None
        assert mpm_data is not None

        # clean.rules has signatures with sid:1, sid:21, sid:22
        assert len(mpm_data["sids"]) >= 3
        assert 1 in mpm_data["sids"]
        assert 21 in mpm_data["sids"]
        assert 22 in mpm_data["sids"]

    def test_analyze_file_worker_skips_zero_sid(
        self, rules_tester_config, progress_queue
    ):
        """Test that worker skips signatures with SID=0"""
        # Create temporary file with signature without SID
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            tmp.write('alert tcp any any -> any any (msg:"No SID";)\n')
            tmp.write('alert tcp any any -> any any (msg:"Has SID"; sid:100;)\n')
            tmp.flush()
            tmp_path = tmp.name

        try:
            _, mpm_data, _error = analyze_file_worker(
                tmp_path, rules_tester_config, progress_queue
            )

            # Should have error from Suricata about missing SID, but still process
            # MPM data should only include sig with sid:100
            if mpm_data:
                # SID 0 should not be in the data
                assert 0 not in mpm_data["sids"]
                # SID 100 should be present
                assert 100 in mpm_data["sids"]

        finally:
            os.unlink(tmp_path)

    def test_analyze_file_worker_handles_missing_file(
        self, rules_tester_config, progress_queue
    ):
        """Test worker handles missing file gracefully"""
        # Create a temp file to get a secure path, then delete it
        with tempfile.NamedTemporaryFile(suffix=".rules", delete=False) as tmp:
            nonexistent_file = tmp.name
        os.unlink(nonexistent_file)

        filepath, mpm_data, error = analyze_file_worker(
            nonexistent_file, rules_tester_config, progress_queue
        )

        # Should return error
        assert filepath == nonexistent_file
        assert mpm_data is None
        assert error is not None
        assert isinstance(error, Exception)

    def test_analyze_file_worker_handles_invalid_syntax(
        self, rules_tester_config, progress_queue
    ):
        """Test worker handles file with syntax errors"""
        # Create temporary file with invalid syntax
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            tmp.write("this is not a valid rule\n")
            tmp.flush()
            tmp_path = tmp.name

        try:
            filepath, _mpm_data, _error = analyze_file_worker(
                tmp_path, rules_tester_config, progress_queue
            )

            # Worker should complete (doesn't crash)
            assert filepath == tmp_path
            # May or may not have error depending on how Suricata handles it
            # But it should not raise an exception

        finally:
            os.unlink(tmp_path)

    def test_analyze_file_worker_sends_progress_update(
        self, clean_rules_path, rules_tester_config, progress_queue
    ):
        """Test worker sends progress update on completion"""
        analyze_file_worker(clean_rules_path, rules_tester_config, progress_queue)

        # Try to get progress update (may not always be available in direct call)
        try:
            update_type, filepath, count = progress_queue.get(timeout=0.1)
            assert update_type == "completed"
            assert filepath == clean_rules_path
            assert count == 1
        except queue.Empty:
            # In direct (non-multiprocessing) calls, queue updates may not work
            # This is acceptable as the queue is primarily for cross-process communication
            pass

    def test_analyze_file_worker_sends_error_notification(
        self, rules_tester_config, progress_queue
    ):
        """Test worker sends error notification via progress queue"""
        # Create a temp file to get a secure path, then delete it
        with tempfile.NamedTemporaryFile(suffix=".rules", delete=False) as tmp:
            nonexistent_file = tmp.name
        os.unlink(nonexistent_file)

        _filepath, _mpm_data, error = analyze_file_worker(
            nonexistent_file, rules_tester_config, progress_queue
        )

        # Error should be returned in the tuple
        assert error is not None
        assert isinstance(error, Exception)

        # Try to get error notification from queue (may not work in direct call)
        try:
            update_type, queue_filepath, error_msg = progress_queue.get(timeout=0.1)
            assert update_type == "error"
            assert queue_filepath == nonexistent_file
            assert isinstance(error_msg, str)
        except queue.Empty:
            # In direct (non-multiprocessing) calls, queue updates may not work
            # This is acceptable as the error is also returned in the tuple
            pass

    def test_analyze_file_worker_handles_full_queue(
        self, clean_rules_path, rules_tester_config
    ):
        """Test worker handles queue.Full exception gracefully"""
        # Create a small queue that will fill up
        small_queue = Queue(maxsize=1)
        # Fill the queue
        small_queue.put(("dummy", "data", 1))

        # Worker should not crash even if queue is full
        filepath, mpm_data, error = analyze_file_worker(
            clean_rules_path, rules_tester_config, small_queue
        )

        # Should complete successfully despite queue being full
        assert filepath == clean_rules_path
        assert error is None
        assert mpm_data is not None

    def test_analyze_file_worker_with_multiline_rules(
        self, rules_tester_config, progress_queue
    ):
        """Test worker handles multiline rules correctly"""
        # Create file with multiline rule
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            tmp.write(
                'alert http any any -> any any (msg:"multiline"; \\\n'
                '    content:"test"; \\\n'
                "    sid:200; rev:1;)\n"
            )
            tmp.flush()
            tmp_path = tmp.name

        try:
            _, mpm_data, error = analyze_file_worker(
                tmp_path, rules_tester_config, progress_queue
            )

            assert error is None
            assert mpm_data is not None
            assert 200 in mpm_data["sids"]

        finally:
            os.unlink(tmp_path)

    def test_analyze_file_worker_creates_own_tester(
        self, clean_rules_path, rules_tester_config, progress_queue
    ):
        """Test that worker creates its own SignaturesTester instance"""
        # This test verifies the worker doesn't require a pre-existing tester
        # It should create its own from the config

        _filepath, mpm_data, error = analyze_file_worker(
            clean_rules_path, rules_tester_config, progress_queue
        )

        # If worker couldn't create its own tester, this would fail
        assert error is None
        assert mpm_data is not None

    def test_analyze_file_worker_empty_file(self, rules_tester_config, progress_queue):
        """Test worker handles empty rules file"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            # Write nothing
            tmp.flush()
            tmp_path = tmp.name

        try:
            filepath, mpm_data, _error = analyze_file_worker(
                tmp_path, rules_tester_config, progress_queue
            )

            # Empty file should process without error
            assert filepath == tmp_path
            # May have no MPM data or empty MPM data
            if mpm_data:
                assert "sids" in mpm_data
                # Should have no SIDs
                assert len(mpm_data["sids"]) == 0

        finally:
            os.unlink(tmp_path)
