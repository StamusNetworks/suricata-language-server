"""
Comprehensive tests for langserver.py to improve code coverage.

This test suite covers:
- URI path conversion (Windows, UNC paths, Unix)
- LSP feature registration via decorators
- Server initialization and configuration
- Workspace analysis (parallel and sequential)
- LSP handlers (semantic tokens, completion, diagnostics)
- Workspace folder management
- File analysis and rules info methods

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import sys
import os
import tempfile
import logging
from unittest.mock import Mock, patch, MagicMock
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from suricatals.langserver import (
    LangServer,
    path_from_uri,
    register_feature,
)
from lsprotocol import types

logger = logging.getLogger(__name__)


class TestPathFromUri:
    """Test URI to filesystem path conversion."""

    def test_unix_file_uri(self):
        """Test converting Unix file URI to path."""
        uri = "file:///home/user/test.rules"
        result = path_from_uri(uri)
        assert result == "/home/user/test.rules"

    def test_unix_file_uri_with_spaces(self):
        """Test converting Unix file URI with URL-encoded spaces."""
        uri = "file:///home/user/test%20file.rules"
        result = path_from_uri(uri)
        assert result == "/home/user/test file.rules"

    @patch("os.name", "nt")
    def test_windows_file_uri(self):
        """Test converting Windows file URI with drive letter."""
        uri = "file:///C:/Users/test/file.rules"
        result = path_from_uri(uri)
        # On Windows, this should return C:\Users\test\file.rules
        assert "C:" in result or "c:" in result
        assert "test" in result
        assert "file.rules" in result

    @patch("os.name", "nt")
    def test_windows_unc_path(self):
        """Test converting Windows UNC path URI."""
        uri = "file://server/share/file.rules"
        result = path_from_uri(uri)
        # UNC path should be preserved
        assert "server" in result
        assert "share" in result

    def test_non_file_uri(self):
        """Test that non-file URIs are returned as-is."""
        uri = "/absolute/path/to/file.rules"
        result = path_from_uri(uri)
        assert result == uri


class TestRegisterFeature:
    """Test the register_feature decorator."""

    def test_decorator_adds_attributes(self):
        """Test that decorator adds lsp_type and lsp_options attributes."""

        @register_feature(types.TEXT_DOCUMENT_COMPLETION, options="test_options")
        def test_method(self):
            pass

        assert hasattr(test_method, "lsp_type")
        assert hasattr(test_method, "lsp_options")
        assert test_method.lsp_type == types.TEXT_DOCUMENT_COMPLETION
        assert test_method.lsp_options == "test_options"

    def test_decorator_without_options(self):
        """Test decorator without options parameter."""

        @register_feature(types.TEXT_DOCUMENT_DID_SAVE)
        def test_method(self):
            pass

        assert test_method.lsp_type == types.TEXT_DOCUMENT_DID_SAVE
        assert test_method.lsp_options is None


class TestLangServerInit:
    """Test LangServer initialization and configuration."""

    def test_default_initialization(self):
        """Test LangServer with default settings."""
        with patch("suricatals.langserver.LanguageServer"):
            server = LangServer()
            assert server.running is True
            assert server.nthreads == 4
            assert server.notify_init is False
            assert server.suricata_binary == "suricata"
            assert server.max_lines == 1000
            assert server.docker is False

    def test_custom_settings(self):
        """Test LangServer with custom settings."""
        settings = {
            "nthreads": 8,
            "notify_init": True,
            "suricata_binary": "/usr/local/bin/suricata",
            "max_lines": 2000,
            "docker_mode": True,
            "docker_image": "custom/suricata:latest",
            "idle_timeout": 5.0,
        }
        with patch("suricatals.langserver.LanguageServer"):
            server = LangServer(settings=settings)
            assert server.nthreads == 8
            assert server.notify_init is True
            assert server.suricata_binary == "/usr/local/bin/suricata"
            assert server.max_lines == 2000
            assert server.docker is True
            assert server.docker_image == "custom/suricata:latest"
            assert server.idle_timeout == 5.0

    def test_batch_mode_initialization(self):
        """Test LangServer in batch mode."""
        with patch(
            "suricatals.langserver.LangServer.create_rule_tester"
        ) as mock_create:
            mock_tester = Mock()
            mock_create.return_value = mock_tester
            server = LangServer(batch_mode=True)
            assert server.batch_mode is True
            assert server.rules_tester == mock_tester
            mock_create.assert_called_once()

    def test_debug_log_setting(self):
        """Test debug_log parameter."""
        with patch("suricatals.langserver.LanguageServer"):
            server = LangServer(debug_log=True)
            assert server.debug_log is True


class TestLangServerMethods:
    """Test LangServer main methods."""

    @patch("suricatals.langserver.LanguageServer")
    def test_create_rule_tester(self, _mock_ls):
        """Test create_rule_tester method."""
        settings = {
            "suricata_binary": "/usr/bin/suricata",
            "suricata_config": "/etc/suricata/suricata.yaml",
            "docker_mode": True,
            "docker_image": "test/suricata:7.0",
        }
        server = LangServer(settings=settings)

        with patch("suricatals.langserver.SignaturesTester") as mock_tester:
            tester = server.create_rule_tester()
            mock_tester.assert_called_once_with(
                suricata_binary="/usr/bin/suricata",
                suricata_config="/etc/suricata/suricata.yaml",
                docker=True,
                docker_image="test/suricata:7.0",
            )

    @patch("suricatals.langserver.LanguageServer")
    def test_get_suricata_file(self, _mock_ls):
        """Test get_suricata_file method."""
        server = LangServer()
        server.server = Mock()

        # Mock workspace and document
        mock_doc = Mock()
        mock_doc.lines = ['alert tcp any any -> any any (msg:"test"; sid:1;)']
        server.server.workspace.get_text_document.return_value = mock_doc

        with patch(
            "suricatals.langserver.SignaturesTester"
        ) as mock_tester_class, patch(
            "suricatals.langserver.SuricataFile"
        ) as mock_file:
            mock_tester = Mock()
            mock_tester_class.return_value = mock_tester
            mock_s_file = Mock()
            mock_file.return_value = mock_s_file

            uri = "file:///test/file.rules"
            result = server.get_suricata_file(uri)

            assert result == mock_s_file
            mock_s_file.load_from_lsp.assert_called_once_with(mock_doc)

    @patch("suricatals.langserver.LanguageServer")
    def test_find_rules_files(self, _mock_ls):
        """Test find_rules_files method."""
        server = LangServer()

        # Create a temporary directory with some .rules files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            rules_file1 = os.path.join(tmpdir, "test1.rules")
            rules_file2 = os.path.join(tmpdir, "test2.rule")
            non_rules_file = os.path.join(tmpdir, "test.txt")

            with open(rules_file1, "w", encoding="utf-8") as f:
                f.write("# test rule 1\n")
            with open(rules_file2, "w", encoding="utf-8") as f:
                f.write("# test rule 2\n")
            with open(non_rules_file, "w", encoding="utf-8") as f:
                f.write("not a rules file\n")

            # Create subdirectory with rules file
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            rules_file3 = os.path.join(subdir, "test3.rules")
            with open(rules_file3, "w", encoding="utf-8") as f:
                f.write("# test rule 3\n")

            # Find rules files
            found_files = server.find_rules_files(tmpdir)

            # Should find 3 .rules/.rule files
            assert len(found_files) == 3
            assert rules_file1 in found_files
            assert rules_file2 in found_files
            assert rules_file3 in found_files
            assert non_rules_file not in found_files

    @patch("suricatals.langserver.LanguageServer")
    def test_analyse_file(self, _mock_ls):
        """Test analyse_file method."""
        server = LangServer()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False
        ) as tmp:
            tmp.write('alert tcp any any -> any any (msg:"test"; sid:1; rev:1;)\n')
            tmp.flush()
            tmp_path = tmp.name

        try:
            with patch(
                "suricatals.langserver.SignaturesTester"
            ) as mock_tester_class, patch(
                "suricatals.langserver.SuricataFile"
            ) as mock_file_class:
                mock_tester = Mock()
                mock_tester_class.return_value = mock_tester

                mock_file = Mock()
                mock_file_class.return_value = mock_file
                mock_file.check_file.return_value = (True, [])

                file_obj, status, diags = server.analyse_file(
                    tmp_path, engine_analysis=True
                )

                assert file_obj == mock_file
                assert status is True
                assert diags == []
                mock_file.load_from_disk.assert_called_once()
                mock_file.check_file.assert_called_once_with(engine_analysis=True)
        finally:
            os.unlink(tmp_path)

    @patch("suricatals.langserver.LanguageServer")
    def test_rules_infos(self, _mock_ls):
        """Test rules_infos method."""
        server = LangServer()

        with patch("suricatals.langserver.SignaturesTester") as mock_tester_class:
            mock_tester = Mock()
            mock_tester_class.return_value = mock_tester
            mock_tester.rules_infos.return_value = {"test": "info"}

            rule_buffer = 'alert tcp any any -> any any (msg:"test"; sid:1;)'
            result = server.rules_infos(rule_buffer)

            assert result == {"test": "info"}
            mock_tester.rules_infos.assert_called_once_with(rule_buffer)


class TestLangServerLSPHandlers:
    """Test LSP protocol handlers."""

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_on_change_schedules_idle(self, _mock_ls):
        """Test that serve_on_change schedules idle analysis for .rules files."""
        server = LangServer()
        server.server = Mock()
        server.idle_timeout = 1.0

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"

        with patch.object(server, "_schedule_idle_analysis") as mock_schedule:
            server.serve_on_change(params)
            mock_schedule.assert_called_once_with("file:///test/file.rules")

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_on_change_ignores_non_rules(self, _mock_ls):
        """Test that serve_on_change ignores non-.rules files."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.txt"

        with patch.object(server, "_schedule_idle_analysis") as mock_schedule:
            server.serve_on_change(params)
            mock_schedule.assert_not_called()

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_on_open(self, _mock_ls):
        """Test serve_on_open delegates to serve_on_save."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        with patch.object(server, "serve_on_save") as mock_save:
            server.serve_on_open(params)
            mock_save.assert_called_once_with(params)

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_on_close(self, _mock_ls):
        """Test serve_on_close cancels idle timer and delegates to serve_on_save."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"

        with patch.object(server, "_cancel_idle_timer") as mock_cancel, patch.object(
            server, "serve_on_save"
        ) as mock_save:
            server.serve_on_close(params)
            mock_cancel.assert_called_once_with("file:///test/file.rules")
            mock_save.assert_called_once_with(params)

    @patch("suricatals.langserver.LanguageServer")
    def test_get_diagnostics_skips_large_files(self, _mock_ls):
        """Test that get_diagnostics skips files larger than max_lines."""
        server = LangServer(settings={"max_lines": 10})
        server.server = Mock()

        # Create a mock document with too many lines
        mock_doc = Mock()
        mock_doc.lines = ["line"] * 20  # More than max_lines
        server.server.workspace.get_text_document.return_value = mock_doc

        uri = "file:///test/file.rules"
        diags, error = server.get_diagnostics(uri)

        assert diags is None
        assert error is None

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_semantic_tokens(self, _mock_ls):
        """Test serve_semantic_tokens returns semantic tokens."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"

        with patch.object(server, "get_suricata_file") as mock_get_file:
            mock_file = Mock()
            mock_file.get_semantic_tokens.return_value = [1, 2, 3, 4, 5]
            mock_get_file.return_value = mock_file

            result = server.serve_semantic_tokens(params)

            assert isinstance(result, types.SemanticTokens)
            assert result.data == [1, 2, 3, 4, 5]
            mock_file.get_semantic_tokens.assert_called_once()

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_semantic_tokens_range(self, _mock_ls):
        """Test serve_semantic_tokens_range returns semantic tokens for range."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"
        params.range = Mock()

        with patch.object(server, "get_suricata_file") as mock_get_file:
            mock_file = Mock()
            mock_file.get_semantic_tokens.return_value = [1, 2, 3]
            mock_get_file.return_value = mock_file

            result = server.serve_semantic_tokens_range(params)

            assert isinstance(result, types.SemanticTokens)
            assert result.data == [1, 2, 3]
            mock_file.get_semantic_tokens.assert_called_once_with(
                file_range=params.range
            )

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_semantic_tokens_returns_empty_on_none(self, _mock_ls):
        """Test serve_semantic_tokens returns empty when file is None."""
        server = LangServer()
        server.server = Mock()

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"

        with patch.object(server, "get_suricata_file") as mock_get_file:
            mock_get_file.return_value = None

            result = server.serve_semantic_tokens(params)

            assert isinstance(result, types.SemanticTokens)
            assert result.data == []


class TestWorkspaceAnalysis:
    """Test workspace analysis functionality."""

    @patch("suricatals.langserver.LanguageServer")
    def test_store_file_mpm_data(self, _mock_ls):
        """Test _store_file_mpm_data stores data in workspace cache."""
        server = LangServer()

        mock_file = Mock()
        mock_file.mpm = {"http_uri": {"patterns": {}}}
        mock_sigset = Mock()
        mock_sig = Mock()
        mock_sig.sid = 1
        mock_sigset.signatures = [mock_sig]
        mock_file.sigset = mock_sigset

        result = server._store_file_mpm_data("/test/file.rules", mock_file)

        assert result is True

    @patch("suricatals.langserver.LanguageServer")
    def test_setup_workspace_analysis(self, _mock_ls):
        """Test _setup_workspace_analysis creates progress tracking."""
        server = LangServer()
        server.server = Mock()

        rules_files = ["/test/file1.rules", "/test/file2.rules"]
        progress_token = server._setup_workspace_analysis(rules_files)

        assert progress_token is not None
        server.server.work_done_progress.create.assert_called_once()
        server.server.work_done_progress.begin.assert_called_once()

    @patch("suricatals.langserver.LanguageServer")
    def test_report_analysis_progress(self, _mock_ls):
        """Test _report_analysis_progress reports progress at intervals."""
        server = LangServer()
        server.server = Mock()

        progress_token = "test-token"

        # Should report at multiples of 10
        server._report_analysis_progress(progress_token, 10, 0, 100)
        assert server.server.work_done_progress.report.call_count >= 1

        # Should report at total
        server._report_analysis_progress(progress_token, 95, 5, 100)
        assert server.server.work_done_progress.report.call_count >= 2

        # Test that it includes error message when errors > 0
        call_args = server.server.work_done_progress.report.call_args
        report = call_args[0][1]
        assert "errors" in report.message

    @patch("suricatals.langserver.LanguageServer")
    def test_finalize_workspace_analysis(self, _mock_ls):
        """Test _finalize_workspace_analysis completes progress and logs stats."""
        server = LangServer()
        server.server = Mock()

        with patch.object(server, "_refresh_open_file_diagnostics") as mock_refresh:
            server._finalize_workspace_analysis("test-token", 50, 2)

            server.server.work_done_progress.end.assert_called_once()
            mock_refresh.assert_called_once()

    @patch("suricatals.langserver.LanguageServer")
    def test_drain_progress_queue(self, _mock_ls):
        """Test _drain_progress_queue empties the queue."""
        import queue

        server = LangServer()
        progress_queue = queue.Queue()

        # Add some items
        progress_queue.put("item1")
        progress_queue.put("item2")

        server._drain_progress_queue(progress_queue)

        assert progress_queue.empty()


class TestWorkspaceFolderManagement:
    """Test workspace folder change handling."""

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_workspace_did_change_adds_folder(self, _mock_ls):
        """Test adding workspace folder triggers analysis."""
        server = LangServer()
        server.server = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test rules file
            rules_file = os.path.join(tmpdir, "test.rules")
            with open(rules_file, "w", encoding="utf-8") as f:
                f.write('alert tcp any any -> any any (msg:"test"; sid:1;)\n')

            params = Mock()
            params.event = Mock()

            # Mock folder to add
            folder = Mock()
            folder.uri = f"file://{tmpdir}"
            params.event.added = [folder]
            params.event.removed = []

            with patch.object(server, "analyze_workspace_files") as mock_analyze:
                server.serve_workspace_did_change_workspace_folders(params)

                assert tmpdir in server.source_dirs
                mock_analyze.assert_called_once()
                # Check that rules file was found
                args = mock_analyze.call_args[0]
                assert len(args[0]) == 1
                assert rules_file in args[0]

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_workspace_did_change_removes_folder(self, _mock_ls):
        """Test removing workspace folder removes MPM data."""
        server = LangServer()
        server.server = Mock()

        test_dir = "/test/workspace"
        server.source_dirs.append(test_dir)

        params = Mock()
        params.event = Mock()

        folder = Mock()
        folder.uri = f"file://{test_dir}"
        params.event.added = []
        params.event.removed = [folder]

        with patch.object(server, "_refresh_open_file_diagnostics") as mock_refresh:
            # Add some mock data to workspace_mpm
            server.workspace_mpm.add_file(
                f"{test_dir}/test.rules", {"buffer": {}, "sids": {}}
            )

            server.serve_workspace_did_change_workspace_folders(params)

            assert test_dir not in server.source_dirs
            # Check that MPM data was removed (key is "file_count" not "total_files")
            stats = server.workspace_mpm.get_statistics()
            assert stats["file_count"] == 0


class TestIdleAnalysis:
    """Test idle analysis functionality."""

    @patch("suricatals.langserver.LanguageServer")
    def test_schedule_idle_analysis_disabled(self, _mock_ls):
        """Test that idle analysis is skipped when timeout is 0."""
        server = LangServer(settings={"idle_timeout": 0})
        server.server = Mock()

        uri = "file:///test/file.rules"
        server._schedule_idle_analysis(uri)

        # No timer should be created
        assert uri not in server.idle_timers

    @patch("suricatals.langserver.LanguageServer")
    def test_cancel_idle_timer_removes_timer(self, _mock_ls):
        """Test that cancel_idle_timer removes and cancels the timer."""
        server = LangServer()
        server.server = Mock()

        uri = "file:///test/file.rules"
        mock_timer = Mock()
        server.idle_timers[uri] = mock_timer

        server._cancel_idle_timer(uri)

        assert uri not in server.idle_timers
        mock_timer.cancel.assert_called_once()


class TestAutocompletion:
    """Test autocompletion functionality."""

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_autocomplete_returns_none_for_missing_doc(self, _mock_ls):
        """Test serve_autocomplete returns None when document not found."""
        server = LangServer()
        server.server = Mock()
        server.server.workspace.get_text_document.return_value = None

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"

        result = server.serve_autocomplete(params)
        assert result is None

    @patch("suricatals.langserver.LanguageServer")
    def test_serve_autocomplete_initializes_handler(self, _mock_ls):
        """Test serve_autocomplete initializes completion handler if needed."""
        server = LangServer()
        server.server = Mock()
        server.completion_handler = None

        mock_doc = Mock()
        mock_doc.lines = ['alert tcp any any -> any any (msg:"test"; sid:']
        server.server.workspace.get_text_document.return_value = mock_doc

        params = Mock()
        params.text_document = Mock()
        params.text_document.uri = "file:///test/file.rules"
        params.position = Mock()
        params.position.line = 0
        params.position.character = 50

        with patch(
            "suricatals.langserver.SignaturesTester"
        ) as mock_tester_class, patch(
            "suricatals.langserver.SignatureCompletion"
        ) as mock_completion:
            mock_tester = Mock()
            mock_tester.ACTIONS_ITEMS = []
            mock_tester_class.return_value = mock_tester

            mock_handler = Mock()
            mock_handler.is_before_content_section.return_value = False
            mock_handler.is_sid_completion_context.return_value = False
            mock_handler.get_keyword_completion.return_value = None
            mock_completion.return_value = mock_handler

            server.serve_autocomplete(params)

            # Completion handler should have been initialized
            assert server.completion_handler is not None


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
