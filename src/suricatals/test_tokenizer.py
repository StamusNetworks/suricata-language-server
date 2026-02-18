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

# pylint: disable=W0212 # testing internal methods and properties is ok in this context

import pytest
from suricatals.signature_tokenizer import SuricataSemanticTokenParser


class TestSuricataSemanticTokenParser:
    """Tests for SuricataSemanticTokenParser class"""

    @pytest.fixture
    def sample_definitions(self):
        """Provide sample definitions for testing"""
        return {
            "actions": ["alert", "drop", "reject", "pass"],
            "protocols": ["tcp", "udp", "http", "icmp", "ip"],
            "sticky_buffers": ["http.uri", "http.host", "tls.sni", "dns.query"],
            "options": [
                "msg",
                "content",
                "sid",
                "rev",
                "reference",
                "classtype",
                "offset",
                "depth",
            ],
            "deprecated_keywords": ["offset", "depth"],
        }

    @pytest.fixture
    def parser(self, sample_definitions):
        """Create a parser instance with sample definitions"""
        return SuricataSemanticTokenParser(sample_definitions)

    def test_init(self, sample_definitions):
        """Test parser initialization"""
        parser = SuricataSemanticTokenParser(sample_definitions)
        assert parser.definitions == sample_definitions
        assert parser.deprecated_keywords == {"offset", "depth"}
        assert parser.master_regex is not None

    def test_token_types_constants(self):
        """Test TOKEN_TYPES constants"""
        expected_types = [
            "keyword",
            "type",
            "variable",
            "number",
            "property",
            "function",
            "string",
            "operator",
            "comment",
        ]
        assert SuricataSemanticTokenParser.TOKEN_TYPES == expected_types

    def test_token_modifiers_constants(self):
        """Test TOKEN_MODIFIERS constants"""
        expected_modifiers = ["declaration", "readonly", "deprecated"]
        assert SuricataSemanticTokenParser.TOKEN_MODIFIERS == expected_modifiers

    def test_get_legend(self, parser):
        """Test get_legend() returns correct structure"""
        legend = parser.get_legend()
        assert "tokenTypes" in legend
        assert "tokenModifiers" in legend
        assert legend["tokenTypes"] == parser.TOKEN_TYPES
        assert legend["tokenModifiers"] == parser.TOKEN_MODIFIERS

    def test_utf16_len_ascii(self, parser):
        """Test UTF-16 length calculation for ASCII text"""
        assert parser._utf16_len("hello") == 5
        assert parser._utf16_len("test") == 4
        assert parser._utf16_len("") == 0
        assert parser._utf16_len("a") == 1

    def test_utf16_len_emojis(self, parser):
        """Test UTF-16 length calculation with emojis (surrogate pairs)"""
        # Emojis take 2 UTF-16 code units
        assert parser._utf16_len("😀") == 2
        assert parser._utf16_len("test😀") == 6  # 4 + 2
        assert parser._utf16_len("😀😀") == 4  # 2 + 2
        assert parser._utf16_len("hello 😀 world") == 14  # 6 + 2 + 6

    def test_utf16_len_unicode(self, parser):
        """Test UTF-16 length calculation with various Unicode characters"""
        # Most Unicode characters are 1 UTF-16 code unit
        assert parser._utf16_len("café") == 4
        assert parser._utf16_len("日本語") == 3
        assert parser._utf16_len("Привет") == 6

    def test_parse_empty_input(self, parser):
        """Test parsing empty input"""
        result = parser.parse("")
        assert result == []

    def test_parse_comment(self, parser):
        """Test parsing comments"""
        text = "# This is a comment"
        result = parser.parse(text)

        # Should have one token (comment)
        assert len(result) == 5
        # Format: [deltaLine, deltaStart, length, typeIdx, modifierBits]
        assert result[0] == 0  # deltaLine
        assert result[1] == 0  # deltaStart
        assert result[2] == len(text)  # length
        assert result[3] == parser.TOKEN_TYPES.index("comment")  # typeIdx
        assert result[4] == 0  # modifierBits

    def test_parse_inline_comment(self, parser):
        """Test parsing inline comments"""
        text = "alert tcp any any # comment"
        result = parser.parse(text)

        # Should have multiple tokens including comment
        assert len(result) > 0
        # Last token should be comment
        comment_idx = -5
        assert result[comment_idx + 3] == parser.TOKEN_TYPES.index("comment")

    def test_parse_string(self, parser):
        """Test parsing quoted strings"""
        text = '"test string"'
        result = parser.parse(text)

        assert len(result) == 5
        assert result[0] == 0  # deltaLine
        assert result[1] == 0  # deltaStart
        assert result[2] == 13  # length of entire string with quotes
        assert result[3] == parser.TOKEN_TYPES.index("string")

    def test_parse_string_with_escape(self, parser):
        """Test parsing strings with escape sequences"""
        text = r'"test \"quoted\" string"'
        result = parser.parse(text)

        assert len(result) == 5
        assert result[3] == parser.TOKEN_TYPES.index("string")

    def test_parse_action_alert(self, parser):
        """Test parsing alert action"""
        text = "alert tcp"
        result = parser.parse(text)

        # Should have at least 2 tokens (alert and tcp)
        assert len(result) >= 10
        # First token should be 'alert' as keyword
        assert result[0] == 0  # deltaLine
        assert result[2] == 5  # length of 'alert'
        assert result[3] == parser.TOKEN_TYPES.index("keyword")

    def test_parse_multiple_actions(self, parser):
        """Test parsing different actions"""
        actions = ["alert", "drop", "reject", "pass"]
        for action in actions:
            text = f"{action} tcp"
            result = parser.parse(text)
            assert len(result) >= 5
            assert result[3] == parser.TOKEN_TYPES.index("keyword")

    def test_parse_protocol(self, parser):
        """Test parsing protocols"""
        text = "alert tcp"
        result = parser.parse(text)

        # Second token should be 'tcp' as type
        assert len(result) >= 10
        # Result format: [deltaLine, deltaStart, length, typeIdx, modifierBits] * N
        # Second token starts at index 5
        assert result[5] == 0  # deltaLine (same line)
        assert result[7] == 3  # length of 'tcp'
        assert result[8] == parser.TOKEN_TYPES.index("type")

    def test_parse_variable(self, parser):
        """Test parsing variables with $ prefix"""
        text = "$HOME_NET"
        result = parser.parse(text)

        assert len(result) == 5
        assert result[2] == 9  # length of '$HOME_NET'
        assert result[3] == parser.TOKEN_TYPES.index("variable")

    def test_parse_bracketed_list(self, parser):
        """Test parsing bracketed lists as variables"""
        text = "[1.1.1.1,2.2.2.2]"
        result = parser.parse(text)

        assert len(result) == 5
        assert result[2] == 17  # length of entire bracketed list
        assert result[3] == parser.TOKEN_TYPES.index("variable")

    def test_parse_keyword_any(self, parser):
        """Test parsing 'any' keyword"""
        text = "any any"
        result = parser.parse(text)

        # Should have 2 tokens, both 'any' as keyword
        assert len(result) == 10
        assert result[3] == parser.TOKEN_TYPES.index("keyword")
        assert result[8] == parser.TOKEN_TYPES.index("keyword")

    def test_parse_direction_arrow(self, parser):
        """Test parsing direction arrows"""
        directions = ["->", "<>", "=>"]
        for direction in directions:
            text = f"any {direction} any"
            result = parser.parse(text)
            # Should find the direction arrow as a keyword
            found_direction = False
            for i in range(0, len(result), 5):
                if result[i + 3] == parser.TOKEN_TYPES.index("keyword"):
                    if result[i + 2] == len(direction):
                        found_direction = True
                        break
            assert found_direction, f"Direction {direction} not found as keyword"

    def test_parse_port_number(self, parser):
        """Test parsing port numbers"""
        text = "any 80"
        result = parser.parse(text)

        # Should find 80 as a number
        found_number = False
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("number"):
                if result[i + 2] == 2:  # length of '80'
                    found_number = True
                    break
        assert found_number

    def test_parse_port_range(self, parser):
        """Test parsing port ranges"""
        text = "any 80:8080"
        result = parser.parse(text)

        # Should find port range as number
        found_range = False
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("number"):
                if result[i + 2] == 7:  # length of '80:8080'
                    found_range = True
                    break
        assert found_range

    def test_parse_sticky_buffer(self, parser):
        """Test parsing sticky buffers as functions"""
        text = "http.uri; content:"
        result = parser.parse(text)

        # Should find http.uri as function
        found_function = False
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("function"):
                if result[i + 2] == 8:  # length of 'http.uri'
                    found_function = True
                    break
        assert found_function

    def test_parse_option_property(self, parser):
        """Test parsing option keys as properties"""
        text = "(msg: content: sid:)"
        result = parser.parse(text)

        # Should find msg, content, sid as properties
        property_count = 0
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("property"):
                property_count += 1
        assert property_count == 3

    def test_parse_operators(self, parser):
        """Test parsing operators (semicolon, colon, parentheses)"""
        text = "(msg:test;)"
        result = parser.parse(text)

        # Should find operators
        operator_count = 0
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("operator"):
                operator_count += 1
        # Should have: ( : ; )
        assert operator_count == 4

    def test_parse_deprecated_keyword(self, parser):
        """Test deprecated keyword detection"""
        text = "(offset:10;)"
        result = parser.parse(text)

        # Find the offset property token
        found_deprecated = False
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("property"):
                token_text_len = result[i + 2]
                if token_text_len == 6:  # length of 'offset'
                    modifier_bits = result[i + 4]
                    # Deprecated modifier is at index 2, so bit 2 should be set
                    if modifier_bits & (1 << 2):
                        found_deprecated = True
                        break
        assert found_deprecated

    def test_parse_non_deprecated_keyword(self, parser):
        """Test non-deprecated keyword has no modifier bits"""
        text = "(msg:test;)"
        result = parser.parse(text)

        # Find the msg property token
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("property"):
                modifier_bits = result[i + 4]
                # Should not have deprecated bit set
                assert not (modifier_bits & (1 << 2))
                break

    def test_parse_complete_rule(self, parser):
        """Test parsing a complete Suricata rule"""
        text = (
            'alert tcp $HOME_NET any -> any 80 (msg:"Test"; content:"test"; sid:1000;)'
        )
        result = parser.parse(text)

        # Should have multiple tokens
        assert len(result) > 0
        # Should be divisible by 5 (each token has 5 values)
        assert len(result) % 5 == 0

        # Extract token types
        token_types = [result[i + 3] for i in range(0, len(result), 5)]

        # Should contain various token types
        assert parser.TOKEN_TYPES.index("keyword") in token_types  # alert
        assert parser.TOKEN_TYPES.index("type") in token_types  # tcp
        assert parser.TOKEN_TYPES.index("variable") in token_types  # $HOME_NET
        assert parser.TOKEN_TYPES.index("number") in token_types  # 80, 1000
        assert parser.TOKEN_TYPES.index("property") in token_types  # msg, content, sid
        assert parser.TOKEN_TYPES.index("string") in token_types  # "Test", "test"
        assert parser.TOKEN_TYPES.index("operator") in token_types  # ( ; )

    def test_parse_multiline_rule(self, parser):
        """Test parsing multiline rules"""
        text = """alert tcp any any -> any 80 ( \
    msg:"Multiline rule"; \
    content:"test"; \
    sid:1000;)
)"""
        result = parser.parse(text)

        # Should parse all lines
        assert len(result) > 0
        assert len(result) % 5 == 0

        # Check delta line values are non-negative
        for i in range(0, len(result), 5):
            delta_line = result[i]
            # Delta line should be 0 for same line, > 0 for new line
            assert delta_line >= 0

    def test_delta_encoding_same_line(self, parser):
        """Test delta encoding for tokens on the same line"""
        text = "alert tcp"
        result = parser.parse(text)

        # First token: alert
        assert result[0] == 0  # deltaLine (first token, line 0)
        assert result[1] == 0  # deltaStart (starts at 0)

        # Second token: tcp
        assert result[5] == 0  # deltaLine (same line)
        # deltaStart should be relative to previous token
        # 'alert' is 5 chars + 1 space = 6
        assert result[6] == 6  # deltaStart relative to previous

    def test_delta_encoding_multiline(self, parser):
        """Test delta encoding across multiple lines"""
        text = "alert tcp\n(msg:test;)"
        result = parser.parse(text)

        # Should have tokens on both lines
        assert len(result) > 0

        # Find tokens on different lines by checking deltaLine > 0
        found_multiline = False
        for i in range(5, len(result), 5):
            if result[i] > 0:  # deltaLine > 0 means new line
                found_multiline = True
                # When moving to new line, deltaStart is absolute from start of line
                assert result[i + 1] >= 0
                break
        assert found_multiline, "Should have tokens on multiple lines"

    def test_parse_with_emoji(self, parser):
        """Test parsing text with emoji (tests UTF-16 handling)"""
        text = '(msg:"Test 😀";)'
        result = parser.parse(text)

        # Should successfully parse despite emoji
        assert len(result) > 0
        assert len(result) % 5 == 0

    def test_parse_empty_definitions(self):
        """Test parser with empty definitions"""
        parser = SuricataSemanticTokenParser({})
        text = "alert tcp any any -> any any (msg:test; sid:1;)"
        result = parser.parse(text)

        # Should still parse basic structure
        assert len(result) > 0

    def test_parse_rule_with_http_sticky(self, parser):
        """Test parsing rule with HTTP sticky buffers"""
        text = 'alert http any any -> any any (msg:"Test"; http.uri; content:"/test"; sid:1;)'
        result = parser.parse(text)

        # Should find http.uri as function
        token_types = [result[i + 3] for i in range(0, len(result), 5)]
        assert parser.TOKEN_TYPES.index("function") in token_types

    def test_parse_rule_with_datasets(self, parser):
        """Test parsing rule with dataset references"""
        text = 'alert tcp any any -> any any (msg:"Test"; dataset:test_set; sid:1;)'
        result = parser.parse(text)

        # Should parse successfully
        assert len(result) > 0
        assert len(result) % 5 == 0

    def test_parse_multiple_content_keywords(self, parser):
        """Test parsing rule with multiple content keywords"""
        text = '(content:"test1"; content:"test2"; content:"test3";)'
        result = parser.parse(text)

        # Count content properties
        content_count = 0
        for i in range(0, len(result), 5):
            if result[i + 3] == parser.TOKEN_TYPES.index("property"):
                # Approximate check for 'content' length
                if result[i + 2] == 7:  # length of 'content'
                    content_count += 1
        assert content_count == 3

    def test_parse_pcre_pattern(self, parser):
        """Test parsing PCRE patterns (as strings)"""
        text = r'(pcre:"/test\d+/i";)'
        result = parser.parse(text)

        # Should find the PCRE string
        token_types = [result[i + 3] for i in range(0, len(result), 5)]
        assert parser.TOKEN_TYPES.index("string") in token_types

    def test_parse_hex_content(self, parser):
        """Test parsing hex content patterns"""
        text = '(content:"|48 65 6c 6c 6f|";)'
        result = parser.parse(text)

        # Should find the hex string
        token_types = [result[i + 3] for i in range(0, len(result), 5)]
        assert parser.TOKEN_TYPES.index("string") in token_types

    def test_parse_negation(self, parser):
        """Test parsing rules with negation"""
        text = "alert tcp !$HOME_NET any -> any any (msg:test; sid:1;)"
        result = parser.parse(text)

        # Should parse successfully
        assert len(result) > 0
        # Variable should still be detected
        token_types = [result[i + 3] for i in range(0, len(result), 5)]
        assert parser.TOKEN_TYPES.index("variable") in token_types

    def test_token_boundaries(self, parser):
        """Test that tokens don't overlap and maintain proper boundaries"""
        text = 'alert tcp any any -> any any (msg:"test"; sid:1;)'
        result = parser.parse(text)

        # Verify result structure
        assert len(result) % 5 == 0

        # Check that all delta values are non-negative
        for i in range(0, len(result), 5):
            delta_line = result[i]
            delta_start = result[i + 1]
            length = result[i + 2]
            type_idx = result[i + 3]
            modifier_bits = result[i + 4]

            assert delta_line >= 0, "Delta line should be non-negative"
            assert delta_start >= 0, "Delta start should be non-negative"
            assert length > 0, "Token length should be positive"
            assert 0 <= type_idx < len(parser.TOKEN_TYPES), "Type index out of range"
            assert modifier_bits >= 0, "Modifier bits should be non-negative"

    def test_parse_whitespace_handling(self, parser):
        """Test parsing with various whitespace"""
        text = "alert   tcp  any    any -> any any"
        result = parser.parse(text)

        # Should parse correctly despite extra whitespace
        assert len(result) > 0
        token_types = [result[i + 3] for i in range(0, len(result), 5)]
        assert parser.TOKEN_TYPES.index("keyword") in token_types  # alert, any
        assert parser.TOKEN_TYPES.index("type") in token_types  # tcp

    def test_parse_tabs(self, parser):
        """Test parsing with tabs"""
        text = "alert\ttcp\tany\tany"
        result = parser.parse(text)

        # Should parse correctly with tabs
        assert len(result) > 0

    def test_empty_sticky_buffer_definition(self):
        """Test parser with no sticky buffers defined"""
        definitions = {
            "actions": ["alert"],
            "protocols": ["tcp"],
            "sticky_buffers": [],
            "options": ["msg", "sid"],
        }
        parser = SuricataSemanticTokenParser(definitions)
        text = "alert tcp any any -> any any (msg:test; sid:1;)"
        result = parser.parse(text)

        # Should still parse
        assert len(result) > 0
