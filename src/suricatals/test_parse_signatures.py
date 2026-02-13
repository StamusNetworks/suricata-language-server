"""
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

import pytest
from unittest.mock import MagicMock
from lsprotocol import types

from suricatals.signature_parser import (
    DiagnosticBuilder,
    Signature,
    SignatureSet,
    SuricataFile,
)


class TestDiagnosticBuilder:
    """Tests for DiagnosticBuilder class"""

    def test_init_defaults(self):
        """Test DiagnosticBuilder initialization with default values"""
        builder = DiagnosticBuilder()
        assert builder.range is None
        assert builder.message is None
        assert builder.severity == types.DiagnosticSeverity.Error
        assert builder.source == "Suricata Language Server"
        assert builder.sid == 0
        assert builder.content == ""

    def test_severity_levels(self):
        """Test severity level constants"""
        assert DiagnosticBuilder.INFO_LEVEL == types.DiagnosticSeverity.Hint
        assert DiagnosticBuilder.WARNING_LEVEL == types.DiagnosticSeverity.Warning
        assert DiagnosticBuilder.ERROR_LEVEL == types.DiagnosticSeverity.Error

    def test_to_message_valid(self):
        """Test to_message() with valid data"""
        builder = DiagnosticBuilder()
        builder.range = types.Range(
            start=types.Position(line=1, character=5),
            end=types.Position(line=1, character=10),
        )
        builder.message = "Test error"
        builder.severity = DiagnosticBuilder.ERROR_LEVEL
        builder.sid = 12345
        builder.content = "alert tcp any any -> any any (sid:12345;)"

        msg = builder.to_message()
        assert msg is not None
        assert msg["range"]["start"]["line"] == 1
        assert msg["range"]["start"]["character"] == 5
        assert msg["range"]["end"]["line"] == 1
        assert msg["range"]["end"]["character"] == 10
        assert msg["message"] == "Test error"
        assert msg["source"] == "Suricata Language Server"
        assert msg["severity"] == types.DiagnosticSeverity.Error.value
        assert msg["sid"] == 12345
        assert msg["content"] == "alert tcp any any -> any any (sid:12345;)"

    def test_to_message_no_range(self):
        """Test to_message() returns None when range is missing"""
        builder = DiagnosticBuilder()
        builder.message = "Test error"
        msg = builder.to_message()
        assert msg is None

    def test_to_message_no_message(self):
        """Test to_message() returns None when message is missing"""
        builder = DiagnosticBuilder()
        builder.range = types.Range(
            start=types.Position(line=1, character=5),
            end=types.Position(line=1, character=10),
        )
        msg = builder.to_message()
        assert msg is None

    def test_to_diagnostic_valid(self):
        """Test to_diagnostic() with valid data"""
        builder = DiagnosticBuilder()
        builder.range = types.Range(
            start=types.Position(line=2, character=0),
            end=types.Position(line=2, character=50),
        )
        builder.message = "Invalid syntax"
        builder.severity = DiagnosticBuilder.WARNING_LEVEL
        builder.source = "Test Source"

        diag = builder.to_diagnostic()
        assert diag is not None
        assert isinstance(diag, types.Diagnostic)
        assert diag.range.start.line == 2
        assert diag.range.start.character == 0
        assert diag.message == "Invalid syntax"
        assert diag.severity == types.DiagnosticSeverity.Warning
        assert diag.source == "Test Source"

    def test_to_diagnostic_no_range(self):
        """Test to_diagnostic() returns None when range is missing"""
        builder = DiagnosticBuilder()
        builder.message = "Test error"
        diag = builder.to_diagnostic()
        assert diag is None

    def test_to_diagnostic_no_message(self):
        """Test to_diagnostic() returns None when message is missing"""
        builder = DiagnosticBuilder()
        builder.range = types.Range(
            start=types.Position(line=1, character=5),
            end=types.Position(line=1, character=10),
        )
        diag = builder.to_diagnostic()
        assert diag is None


class TestSignature:
    """Tests for Signature class"""

    def test_single_line_init(self):
        """Test single-line signature initialization"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000; rev:1;)'
        sig = Signature(line=0, content=content, multiline=False)

        assert sig.line == 0
        assert sig.line_end == 0
        assert sig.content == content
        assert sig.raw_content == [content]
        assert sig.multiline is False
        assert sig.sid == 1000
        assert sig.rev == 1
        assert sig.mpm is None
        assert sig.has_error is False

    def test_multiline_init(self):
        """Test multiline signature initialization strips backslash"""
        content = "alert tcp any any -> any any \\"
        sig = Signature(line=0, content=content, multiline=True)

        assert sig.line == 0
        assert sig.line_end == 0
        assert sig.content == "alert tcp any any -> any any "
        assert sig.raw_content == [content]
        assert sig.multiline is True

    def test_sid_extraction(self):
        """Test SID extraction from content"""
        test_cases = [
            ('alert tcp any any -> any any (msg:"Test"; sid:12345;)', 12345),
            ('alert tcp any any -> any any (msg:"Test"; sid :5000;)', 5000),
            ('alert tcp any any -> any any (msg:"Test";)', 0),  # No SID
            ('alert tcp any any -> any any (msg:"Test"; sid:999;)', 999),
        ]

        for content, expected_sid in test_cases:
            sig = Signature(line=0, content=content, multiline=False)
            assert sig.sid == expected_sid, f"Failed for content: {content}"

    def test_rev_extraction(self):
        """Test REV extraction from content"""
        test_cases = [
            ('alert tcp any any -> any any (msg:"Test"; rev:5;)', 5),
            ('alert tcp any any -> any any (msg:"Test"; rev :3;)', 3),
            ('alert tcp any any -> any any (msg:"Test";)', 0),  # No REV
            ('alert tcp any any -> any any (msg:"Test"; rev:10;)', 10),
        ]

        for content, expected_rev in test_cases:
            sig = Signature(line=0, content=content, multiline=False)
            assert sig.rev == expected_rev, f"Failed for content: {content}"

    def test_append_content(self):
        """Test appending continuation lines to multiline signature"""
        sig = Signature(
            line=0, content="alert tcp any any -> any any \\", multiline=True
        )
        sig.append_content('(msg:"Test"; \\', line=1)
        sig.append_content("sid:2000; rev:3;)", line=2)

        assert sig.line == 0
        assert sig.line_end == 2
        assert (
            sig.content == 'alert tcp any any -> any any (msg:"Test"; sid:2000; rev:3;)'
        )
        assert len(sig.raw_content) == 3
        assert sig.sid == 2000
        assert sig.rev == 3

    def test_get_diag_range_all(self):
        """Test get_diag_range with mode='all'"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = Signature(line=5, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="all")
        assert range_obj is not None
        assert range_obj.start.line == 5
        assert range_obj.start.character == 0
        assert range_obj.end.line == 5
        assert range_obj.end.character == len(content)

    def test_get_diag_range_all_multiline(self):
        """Test get_diag_range with mode='all' for multiline signature"""
        sig = Signature(
            line=0, content="alert tcp any any -> any any \\", multiline=True
        )
        sig.append_content('(msg:"Test"; \\', line=1)
        sig.append_content("sid:2000;)   ", line=2)

        range_obj = sig.get_diag_range(mode="all")
        assert range_obj is not None
        assert range_obj.start.line == 0
        assert range_obj.start.character == 0
        assert range_obj.end.line == 2
        assert range_obj.end.character == 10  # Stripped whitespace

    def test_get_diag_range_sid(self):
        """Test get_diag_range with mode='sid'"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = Signature(line=3, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="sid")
        assert range_obj is not None
        assert range_obj.start.line == 3
        assert range_obj.start.character == content.index("sid:")
        assert range_obj.end.character == content.index("sid:") + 4

    def test_get_diag_range_msg(self):
        """Test get_diag_range with mode='msg'"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = Signature(line=2, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="msg")
        assert range_obj is not None
        assert range_obj.start.line == 2
        assert range_obj.start.character == content.index("msg:")
        assert range_obj.end.character == content.index("msg:") + 4

    def test_get_diag_range_msg_fallback_to_sid(self):
        """Test get_diag_range with mode='msg' falls back to sid when no msg"""
        content = "alert tcp any any -> any any (sid:1000;)"
        sig = Signature(line=1, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="msg")
        assert range_obj is not None
        assert range_obj.start.character == content.index("sid:")

    def test_get_diag_range_pattern(self):
        """Test get_diag_range with mode='pattern'"""
        content = (
            'alert tcp any any -> any any (msg:"Test"; content:"badstuff"; sid:1000;)'
        )
        sig = Signature(line=0, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="pattern", pattern="badstuff")
        assert range_obj is not None
        assert range_obj.start.line == 0
        # Should highlight the content:"badstuff" part
        assert range_obj.start.character >= content.index("content:")

    def test_get_diag_range_pattern_not_found(self):
        """Test get_diag_range with mode='pattern' when pattern not found"""
        content = (
            'alert tcp any any -> any any (msg:"Test"; content:"other"; sid:1000;)'
        )
        sig = Signature(line=0, content=content, multiline=False)

        range_obj = sig.get_diag_range(mode="pattern", pattern="notfound")
        # Should fall back to msg:
        assert range_obj is not None
        assert range_obj.start.character == content.index("msg:")

    def test_get_content_keyword_count(self):
        """Test counting content keywords in signature"""
        test_cases = [
            ('alert tcp any any -> any any (content:"test"; sid:1;)', 1),
            ('alert tcp any any -> any any (content:"a"; content:"b"; sid:1;)', 2),
            ('alert tcp any any -> any any (content :"a"; content: "b"; sid:1;)', 2),
            ('alert tcp any any -> any any (msg:"Test"; sid:1;)', 0),
        ]

        for content, expected_count in test_cases:
            sig = Signature(line=0, content=content, multiline=False)
            count = sig.get_content_keyword_count()
            assert count == expected_count, f"Failed for content: {content}"

    def test_sls_syntax_check_valid(self):
        """Test sls_syntax_check with valid signature"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = Signature(line=0, content=content, multiline=False)

        diagnostics = sig.sls_syntax_check()
        assert len(diagnostics) == 0

    def test_sls_syntax_check_incomplete(self):
        """Test sls_syntax_check with incomplete signature (missing closing paren)"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;'
        sig = Signature(line=0, content=content, multiline=False)

        diagnostics = sig.sls_syntax_check()
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == DiagnosticBuilder.WARNING_LEVEL
        assert "Missing closing parenthesis" in diagnostics[0].message

    def test_str_repr(self):
        """Test __str__ and __repr__ methods"""
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = Signature(line=0, content=content, multiline=False)

        assert str(sig) == f"1000:{content}"
        assert repr(sig) == "Signature()"


class TestSignatureSet:
    """Tests for SignatureSet class"""

    def test_init(self):
        """Test SignatureSet initialization"""
        sigset = SignatureSet()
        assert len(sigset.content_map) == 0
        assert len(sigset.line_map) == 0
        assert len(sigset.sid_map) == 0
        assert len(sigset.signatures) == 0

    def test_add_signature(self):
        """Test adding a signature"""
        sigset = SignatureSet()
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        sig = sigset.add_signature(line=0, content=content, multiline=False)

        assert sig is not None
        assert len(sigset.signatures) == 1
        assert sigset.line_map[0] == sig
        assert sigset.content_map[content] == sig
        assert sigset.sid_map[1000] == sig

    def test_add_signature_no_sid(self):
        """Test adding a signature without SID"""
        sigset = SignatureSet()
        content = 'alert tcp any any -> any any (msg:"Test";)'
        sig = sigset.add_signature(line=0, content=content, multiline=False)

        assert sig is not None
        assert len(sigset.signatures) == 1
        assert len(sigset.sid_map) == 0

    def test_add_content_to_signature(self):
        """Test appending content to multiline signature"""
        sigset = SignatureSet()
        sig = sigset.add_signature(
            line=0, content="alert tcp any any -> any any \\", multiline=True
        )

        sigset.add_content_to_signature(sig_line=0, line=1, content='(msg:"Test"; \\')
        sigset.add_content_to_signature(sig_line=0, line=2, content="sid:2000;)")

        assert sig.line_end == 2
        assert sig.sid == 2000
        assert sigset.sid_map[2000] == sig

    def test_get_sig_by_line(self):
        """Test retrieving signature by line number"""
        sigset = SignatureSet()
        content1 = 'alert tcp any any -> any any (msg:"Test1"; sid:1000;)'
        content2 = 'alert tcp any any -> any any (msg:"Test2"; sid:2000;)'
        sig1 = sigset.add_signature(line=0, content=content1, multiline=False)
        sig2 = sigset.add_signature(line=5, content=content2, multiline=False)

        assert sigset.get_sig_by_line(0) == sig1
        assert sigset.get_sig_by_line(5) == sig2
        assert sigset.get_sig_by_line(10) is None

    def test_get_sig_by_content(self):
        """Test retrieving signature by content"""
        sigset = SignatureSet()
        content1 = 'alert tcp any any -> any any (msg:"Test1"; sid:1000;)'
        content2 = 'alert tcp any any -> any any (msg:"Test2"; sid:2000;)'
        sig1 = sigset.add_signature(line=0, content=content1, multiline=False)
        sig2 = sigset.add_signature(line=5, content=content2, multiline=False)

        assert sigset.get_sig_by_content(content1) == sig1
        assert sigset.get_sig_by_content(content2) == sig2
        assert sigset.get_sig_by_content("nonexistent") is None

    def test_get_sig_by_sid(self):
        """Test retrieving signature by SID"""
        sigset = SignatureSet()
        content1 = 'alert tcp any any -> any any (msg:"Test1"; sid:1000;)'
        content2 = 'alert tcp any any -> any any (msg:"Test2"; sid:2000;)'
        sig1 = sigset.add_signature(line=0, content=content1, multiline=False)
        sig2 = sigset.add_signature(line=5, content=content2, multiline=False)

        assert sigset.get_sig_by_sid(1000) == sig1
        assert sigset.get_sig_by_sid(2000) == sig2
        assert sigset.get_sig_by_sid(9999) is None

    def test_revision_conflict_newer_first(self):
        """Test revision conflict detection when newer revision is added first"""
        sigset = SignatureSet()
        content1 = 'alert tcp any any -> any any (msg:"Test"; sid:1000; rev:2;)'
        content2 = 'alert tcp any any -> any any (msg:"Test"; sid:1000; rev:1;)'

        sig1 = sigset.add_signature(line=0, content=content1, multiline=False)
        sig2 = sigset.add_signature(line=5, content=content2, multiline=False)

        assert sig1.has_error is False
        assert sig2.has_error is True  # Older revision should be marked as error

    def test_revision_conflict_older_first(self):
        """Test revision conflict detection when older revision is added first"""
        sigset = SignatureSet()
        content1 = 'alert tcp any any -> any any (msg:"Test"; sid:1000; rev:1;)'
        content2 = 'alert tcp any any -> any any (msg:"Test"; sid:1000; rev:2;)'

        sig1 = sigset.add_signature(line=0, content=content1, multiline=False)
        sig2 = sigset.add_signature(line=5, content=content2, multiline=False)

        assert sig1.has_error is True  # Older revision should be marked as error
        assert sig2.has_error is False


class TestSuricataFile:
    """Tests for SuricataFile class"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up mock rules_tester for tests"""
        self.mock_tester = MagicMock()
        self.mock_tester.get_semantic_token_definitions.return_value = {}

    def test_init(self):
        """Test SuricataFile initialization"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)

        assert suri_file.path == "/path/to/test.rules"
        assert suri_file.rules_tester == self.mock_tester
        assert suri_file.semantic_tokens_parser is not None
        assert len(suri_file.contents_split) == 0
        assert suri_file.sigset is not None
        assert len(suri_file.mpm) == 0
        assert suri_file.diagnosis is None

    def test_parse_file_single_line(self):
        """Test parsing file with single-line signatures"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """alert tcp any any -> any any (msg:"Test1"; sid:1000;)
alert tcp any any -> any any (msg:"Test2"; sid:2000;)"""
        suri_file._load_file(contents)

        assert len(suri_file.sigset.signatures) == 2
        assert suri_file.sigset.get_sig_by_sid(1000).line == 0
        assert suri_file.sigset.get_sig_by_sid(2000).line == 1

    def test_parse_file_multiline(self):
        """Test parsing file with multiline signatures"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """alert tcp any any -> any any \\
(msg:"Test"; \\
sid:1000;)"""
        suri_file._load_file(contents)

        assert len(suri_file.sigset.signatures) == 1
        sig = suri_file.sigset.get_sig_by_sid(1000)
        assert sig is not None
        assert sig.line == 0
        assert sig.line_end == 2
        assert len(sig.raw_content) == 3

    def test_parse_file_with_comments(self):
        """Test parsing file with comments"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """# This is a comment
alert tcp any any -> any any (msg:"Test1"; sid:1000;)
  # Another comment with leading spaces
alert tcp any any -> any any (msg:"Test2"; sid:2000;)"""
        suri_file._load_file(contents)

        assert len(suri_file.sigset.signatures) == 2
        # Comments should not create signatures
        assert suri_file.sigset.get_sig_by_sid(1000).line == 1
        assert suri_file.sigset.get_sig_by_sid(2000).line == 3

    def test_parse_file_mixed_content(self):
        """Test parsing file with mixed single-line, multiline, and comments"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """# Comment
alert tcp any any -> any any (msg:"Single"; sid:1000;)
alert tcp any any -> any any \\
(msg:"Multi"; sid:2000;)
# Another comment
alert tcp any any -> any any (msg:"Another"; sid:3000;)"""
        suri_file._load_file(contents)

        assert len(suri_file.sigset.signatures) == 3
        assert suri_file.sigset.get_sig_by_sid(1000) is not None
        assert suri_file.sigset.get_sig_by_sid(2000) is not None
        assert suri_file.sigset.get_sig_by_sid(3000) is not None

    def test_extract_range_single_line(self):
        """Test extracting content from a single line"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(contents)

        file_range = types.Range(
            start=types.Position(line=0, character=6),
            end=types.Position(line=0, character=9),
        )
        extracted = suri_file.extract_range(file_range)
        assert extracted == "tcp"

    def test_extract_range_multiline(self):
        """Test extracting content across multiple lines"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """line one
line two
line three"""
        suri_file._load_file(contents)

        file_range = types.Range(
            start=types.Position(line=0, character=5),
            end=types.Position(line=2, character=4),
        )
        extracted = suri_file.extract_range(file_range)
        assert extracted == "one\nline two\nline"

    def test_extract_range_empty_end_line(self):
        """Test extracting range with empty line at end"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """line one
line two
line three"""
        suri_file._load_file(contents)

        file_range = types.Range(
            start=types.Position(line=0, character=0),
            end=types.Position(line=2, character=0),
        )
        extracted = suri_file.extract_range(file_range)
        assert extracted == "line one\nline two"

    def test_build_errors_diagnostics_with_signature(self):
        """Test building error diagnostics when signature is found"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(contents)

        errors = [
            {
                "line": 0,
                "message": "Invalid keyword",
                "source": "Suricata",
            }
        ]

        diagnostics = suri_file.build_errors_diagnostics(errors)
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == DiagnosticBuilder.ERROR_LEVEL
        assert diagnostics[0].message == "Invalid keyword"
        assert diagnostics[0].sid == 1000
        assert diagnostics[0].range is not None

    def test_build_errors_diagnostics_without_signature(self):
        """Test building error diagnostics when signature not found"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = ""
        suri_file._load_file(contents)

        errors = [
            {
                "line": 5,
                "message": "Unknown error",
                "source": "Suricata",
                "content": "some content",
                "sid": "UNKNOWN",
            }
        ]

        diagnostics = suri_file.build_errors_diagnostics(errors)
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == DiagnosticBuilder.ERROR_LEVEL
        assert diagnostics[0].sid == "UNKNOWN"
        assert diagnostics[0].content == "some content"

    def test_build_warnings_diagnostics_by_line(self):
        """Test building warning diagnostics using line number"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(contents)

        warnings = [
            {
                "line": 0,
                "message": "Deprecated keyword",
                "source": "Suricata",
            }
        ]

        diagnostics = suri_file.build_warnings_diagnostics(warnings)
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == DiagnosticBuilder.WARNING_LEVEL
        assert diagnostics[0].message == "Deprecated keyword"

    def test_build_warnings_diagnostics_by_content(self):
        """Test building warning diagnostics using content"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(content)

        warnings = [
            {
                "content": content,
                "message": "Performance warning",
                "source": "Suricata",
            }
        ]

        diagnostics = suri_file.build_warnings_diagnostics(warnings)
        assert len(diagnostics) == 1
        assert diagnostics[0].message == "Performance warning"
        assert diagnostics[0].sid == 1000

    def test_build_warnings_diagnostics_by_sid(self):
        """Test building warning diagnostics using SID"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(contents)

        warnings = [
            {
                "sid": 1000,
                "message": "Rule warning",
                "source": "Suricata",
            }
        ]

        diagnostics = suri_file.build_warnings_diagnostics(warnings)
        assert len(diagnostics) == 1
        assert diagnostics[0].message == "Rule warning"
        assert diagnostics[0].sid == 1000

    def test_sort_diagnosis(self):
        """Test sorting diagnostics by severity"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)

        diag1 = DiagnosticBuilder()
        diag1.severity = DiagnosticBuilder.INFO_LEVEL

        diag2 = DiagnosticBuilder()
        diag2.severity = DiagnosticBuilder.ERROR_LEVEL

        diag3 = DiagnosticBuilder()
        diag3.severity = DiagnosticBuilder.WARNING_LEVEL

        diags = [diag1, diag2, diag3]
        sorted_diags = sorted(diags, key=suri_file.sort_diagnosis)

        # Should be sorted by -severity, which puts higher values first
        # Hint (4) > Warning (2) > Error (1)
        assert sorted_diags[0].severity == DiagnosticBuilder.INFO_LEVEL
        assert sorted_diags[1].severity == DiagnosticBuilder.WARNING_LEVEL
        assert sorted_diags[2].severity == DiagnosticBuilder.ERROR_LEVEL

    def test_build_pcap_diagnostics(self):
        """Test building PCAP diagnostics"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = """alert tcp any any -> any any (msg:"Test1"; sid:1000;)
alert tcp any any -> any any (msg:"Test2"; sid:2000;)"""
        suri_file._load_file(contents)

        pcap_results = {1000: 5, 2000: 3}

        diagnostics = suri_file.build_pcap_diagnostics(pcap_results)
        assert len(diagnostics) == 2

        for diag in diagnostics:
            assert diag.severity == DiagnosticBuilder.INFO_LEVEL
            assert diag.source == "Suricata Pcap Analysis"
            if diag.sid == 1000:
                assert diag.message == "Alerts: 5"
            elif diag.sid == 2000:
                assert diag.message == "Alerts: 3"

    def test_build_profiling_diagnostics(self):
        """Test building profiling diagnostics"""
        suri_file = SuricataFile("/path/to/test.rules", self.mock_tester)
        contents = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)'
        suri_file._load_file(contents)

        profiling_results = [
            {
                "signature_id": 1000,
                "checks": 100,
                "ticks_total": 5000,
                "ticks_max": 100,
                "ticks_avg": 50,
            }
        ]

        diagnostics = suri_file.build_profiling_diagnostics(profiling_results)
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == DiagnosticBuilder.INFO_LEVEL
        assert diagnostics[0].source == "Suricata Pcap Profiling"
        assert "Checks: 100" in diagnostics[0].message
        assert "Ticks: total 5000" in diagnostics[0].message
