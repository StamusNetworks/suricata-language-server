"""
Unit tests for SignatureCompletion class.

Copyright(C) 2026 Stamus Networks SAS
Written by Eric Leblond <el@stamus-networks.com>

Tests auto-completion for Suricata signature files including:
- Action completion (alert, drop, etc.)
- App layer protocol completion
- Keyword completion
- SID completion

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

# pylint: disable=W0201  # Pytest setup_method pattern
# pylint: disable=W0212  # Access to protected members for testing

from lsprotocol import types

from suricatals.signature_completion import SignatureCompletion

# Sample data for testing
SAMPLE_ACTIONS = [
    {"label": "alert", "kind": 14, "detail": "Alert", "documentation": "Trigger alert"},
    {"label": "drop", "kind": 14, "detail": "Drop", "documentation": "Drop and alert"},
    {"label": "pass", "kind": 14, "detail": "Pass", "documentation": "Pass traffic"},
    {
        "label": "reject",
        "kind": 14,
        "detail": "Reject",
        "documentation": "Reject traffic",
    },
]

SAMPLE_APP_LAYERS = [
    {"label": "http", "kind": 10, "detail": "HTTP", "documentation": "HTTP protocol"},
    {"label": "dns", "kind": 10, "detail": "DNS", "documentation": "DNS protocol"},
    {"label": "tls", "kind": 10, "detail": "TLS", "documentation": "TLS protocol"},
    {"label": "ssh", "kind": 10, "detail": "SSH", "documentation": "SSH protocol"},
]

SAMPLE_KEYWORDS = [
    {
        "label": "content",
        "kind": 3,
        "detail": "Content",
        "documentation": "Match content",
    },
    {
        "label": "flow",
        "kind": 3,
        "detail": "Flow",
        "documentation": "Flow direction",
    },
    {"label": "msg", "kind": 3, "detail": "Message", "documentation": "Rule message"},
    {"label": "sid", "kind": 3, "detail": "Signature ID", "documentation": "Rule ID"},
    {
        "label": "metadata",
        "kind": 3,
        "detail": "Metadata",
        "documentation": "Rule metadata",
    },
    {
        "label": "http.uri",
        "kind": 3,
        "detail": "HTTP URI",
        "documentation": "HTTP URI buffer",
    },
]


class TestSignatureCompletion:
    """Tests for SignatureCompletion class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.completion_handler = SignatureCompletion(
            keywords_list=SAMPLE_KEYWORDS,
            app_layer_list=SAMPLE_APP_LAYERS,
            actions_items=SAMPLE_ACTIONS,
        )

    def test_action_completion_at_start(self):
        """Test action completion when cursor is at start of line"""
        sig_content = "a"
        sig_index = 1

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is not None
        assert len(result.items) == len(SAMPLE_ACTIONS)
        assert result.items[0].label == "alert"
        assert result.items[0].kind == types.CompletionItemKind.Keyword
        assert not result.is_incomplete

    def test_action_completion_empty_line(self):
        """Test action completion on empty line"""
        sig_content = ""
        sig_index = 0

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is not None
        assert len(result.items) == len(SAMPLE_ACTIONS)

    def test_app_layer_completion(self):
        """Test app layer protocol completion after action"""
        sig_content = "alert "
        sig_index = 6

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is not None
        assert len(result.items) == len(SAMPLE_APP_LAYERS)
        assert result.items[0].label == "http"
        assert result.items[0].kind == types.CompletionItemKind.Property

    def test_app_layer_completion_partial(self):
        """Test app layer completion with partial text"""
        sig_content = "alert h"
        sig_index = 7

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is not None
        assert len(result.items) == len(SAMPLE_APP_LAYERS)

    def test_no_completion_after_protocol(self):
        """Test no completion after protocol is entered"""
        sig_content = "alert http any any -> any any "
        sig_index = 31

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is None

    def test_sid_completion(self):
        """Test SID completion suggestion"""
        next_sid = 1000001

        result = self.completion_handler.get_sid_completion(next_sid)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "1000001"
        assert result.items[0].kind == types.CompletionItemKind.Value
        assert result.items[0].detail == "Next available SID"
        assert result.items[0].insert_text == "1000001"

    def test_is_sid_completion_context_true(self):
        """Test SID completion context detection - positive case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; sid:'
        sig_index = len(sig_content)

        result = self.completion_handler.is_sid_completion_context(
            sig_content, sig_index
        )

        assert result is True

    def test_is_sid_completion_context_with_space(self):
        """Test SID completion context with space after colon"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; sid: '
        sig_index = len(sig_content)

        result = self.completion_handler.is_sid_completion_context(
            sig_content, sig_index
        )

        assert result is True

    def test_is_sid_completion_context_false(self):
        """Test SID completion context detection - negative case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; '
        sig_index = len(sig_content)

        result = self.completion_handler.is_sid_completion_context(
            sig_content, sig_index
        )

        assert result is False

    def test_is_before_content_section_true(self):
        """Test detection of position before content section"""
        sig_content = "alert http any any -> any any "
        sig_index = len(sig_content)

        result = self.completion_handler.is_before_content_section(
            sig_content, sig_index
        )

        assert result is True

    def test_is_before_content_section_false(self):
        """Test detection of position after content section starts"""
        sig_content = "alert http any any -> any any (msg:"
        sig_index = len(sig_content)

        result = self.completion_handler.is_before_content_section(
            sig_content, sig_index
        )

        assert result is False

    def test_keyword_completion_partial_match(self):
        """Test keyword completion with partial keyword"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; con'
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "content"

    def test_keyword_completion_no_match(self):
        """Test keyword completion with no matching keywords"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; xyz'
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is None

    def test_keyword_completion_at_space(self):
        """Test keyword completion at space (should return None)"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; '
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is None

    def test_keyword_completion_after_colon(self):
        """Test no keyword completion after colon (editing option value)"""
        sig_content = "alert tcp any any -> any any (msg:"
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is None

    def test_keyword_completion_after_comma(self):
        """Test no keyword completion after comma (editing option value)"""
        sig_content = "alert tcp any any -> any any (flow:to_server,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is None

    def test_keyword_completion_with_dot(self):
        """Test keyword completion with dot in keyword name"""
        sig_content = "alert tcp any any -> any any (http."
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "http.uri"

    def test_keyword_completion_multiple_matches(self):
        """Test keyword completion with multiple matching keywords"""
        sig_content = "alert tcp any any -> any any (m"
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 2  # msg and metadata
        labels = [item.label for item in result.items]
        assert "msg" in labels
        assert "metadata" in labels

    def test_action_completion_with_drop(self):
        """Test action completion includes drop action"""
        sig_content = "d"
        sig_index = 1

        result = self.completion_handler.get_initial_params_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "drop" in labels

    def test_keyword_completion_empty_partial(self):
        """Test keyword completion with empty partial (right after space)"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; f'
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "flow"

    def test_sid_completion_different_values(self):
        """Test SID completion with various SID values"""
        test_sids = [1, 100, 1000, 10000, 1000000, 9999999]

        for next_sid in test_sids:
            result = self.completion_handler.get_sid_completion(next_sid)

            assert result is not None
            assert len(result.items) == 1
            assert result.items[0].label == str(next_sid)
            assert result.items[0].insert_text == str(next_sid)

    def test_deprecated_completion_item(self):
        """Test completion with deprecated item"""
        deprecated_keywords = [
            {
                "label": "old_keyword",
                "kind": 3,
                "detail": "Deprecated",
                "documentation": "Old keyword",
                "deprecated": True,
            }
        ]

        completion_handler = SignatureCompletion(
            keywords_list=deprecated_keywords,
            app_layer_list=SAMPLE_APP_LAYERS,
            actions_items=SAMPLE_ACTIONS,
        )

        sig_content = "alert tcp any any -> any any (old"
        sig_index = len(sig_content)

        result = completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].deprecated is True

    def test_completion_with_minimal_item_data(self):
        """Test completion with minimal item data (no optional fields)"""
        minimal_keywords = [
            {
                "label": "minimal",
            }
        ]

        completion_handler = SignatureCompletion(
            keywords_list=minimal_keywords,
            app_layer_list=SAMPLE_APP_LAYERS,
            actions_items=SAMPLE_ACTIONS,
        )

        sig_content = "alert tcp any any -> any any (min"
        sig_index = len(sig_content)

        result = completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "minimal"
        assert result.items[0].detail == ""
        assert result.items[0].documentation == ""
        assert result.items[0].deprecated is False

    def test_case_sensitive_keyword_matching(self):
        """Test that keyword matching is case-sensitive"""
        sig_content = "alert tcp any any -> any any (CON"
        sig_index = len(sig_content)

        result = self.completion_handler.get_keyword_completion(sig_content, sig_index)

        # Should not match "content" since Suricata keywords are lowercase
        assert result is None

    def test_keyword_completion_with_underscore(self):
        """Test keyword completion with underscore in name"""
        keywords_with_underscore = [
            {
                "label": "http_method",
                "kind": 3,
                "detail": "HTTP Method",
                "documentation": "HTTP method buffer",
                "deprecated": True,
            }
        ]

        completion_handler = SignatureCompletion(
            keywords_list=keywords_with_underscore,
            app_layer_list=SAMPLE_APP_LAYERS,
            actions_items=SAMPLE_ACTIONS,
        )

        sig_content = "alert tcp any any -> any any (http_"
        sig_index = len(sig_content)

        result = completion_handler.get_keyword_completion(sig_content, sig_index)

        assert result is not None
        assert len(result.items) == 1
        assert result.items[0].label == "http_method"
        assert result.items[0].deprecated is True

    def test_is_flow_value_completion_context_true(self):
        """Test flow value completion context detection - positive case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; flow:'
        sig_index = len(sig_content)

        result = self.completion_handler.is_flow_value_completion_context(
            sig_content, sig_index
        )

        assert result is True

    def test_is_flow_value_completion_context_with_space(self):
        """Test flow value completion context with space after colon"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; flow: '
        sig_index = len(sig_content)

        result = self.completion_handler.is_flow_value_completion_context(
            sig_content, sig_index
        )

        assert result is True

    def test_is_flow_value_completion_context_false(self):
        """Test flow value completion context detection - negative case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; '
        sig_index = len(sig_content)

        result = self.completion_handler.is_flow_value_completion_context(
            sig_content, sig_index
        )

        assert result is False

    def test_parse_existing_flow_values_empty(self):
        """Test parsing flow values when none exist"""
        sig_content = "alert tcp any any -> any any (flow:"
        sig_index = len(sig_content)

        result = self.completion_handler._parse_existing_flow_values(
            sig_content, sig_index
        )

        assert result == []

    def test_parse_existing_flow_values_single(self):
        """Test parsing single flow value"""
        sig_content = "alert tcp any any -> any any (flow:established"
        sig_index = len(sig_content)

        result = self.completion_handler._parse_existing_flow_values(
            sig_content, sig_index
        )

        assert result == ["established"]

    def test_parse_existing_flow_values_multiple(self):
        """Test parsing multiple flow values"""
        sig_content = "alert tcp any any -> any any (flow:established,to_server"
        sig_index = len(sig_content)

        result = self.completion_handler._parse_existing_flow_values(
            sig_content, sig_index
        )

        assert result == ["established", "to_server"]

    def test_parse_existing_flow_values_with_comma(self):
        """Test parsing flow values with trailing comma"""
        sig_content = "alert tcp any any -> any any (flow:established,"
        sig_index = len(sig_content)

        result = self.completion_handler._parse_existing_flow_values(
            sig_content, sig_index
        )

        assert result == ["established"]

    def test_flow_value_completion_no_existing_values(self):
        """Test flow value completion with no existing values"""
        sig_content = "alert tcp any any -> any any (flow:"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        assert len(result.items) == 11  # All flow values available
        labels = [item.label for item in result.items]
        assert "established" in labels
        assert "stateless" in labels
        assert "to_server" in labels
        assert "to_client" in labels

    def test_flow_value_completion_excludes_to_server_when_to_client_exists(self):
        """Test flow value completion excludes to_server when to_client exists"""
        sig_content = "alert tcp any any -> any any (flow:to_client,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "to_server" not in labels
        assert "from_client" not in labels
        assert "to_client" not in labels  # Don't suggest duplicates
        assert "from_server" not in labels  # Alias for to_client
        assert "established" in labels  # Still available

    def test_flow_value_completion_excludes_to_client_when_to_server_exists(self):
        """Test flow value completion excludes to_client when to_server exists"""
        sig_content = "alert tcp any any -> any any (flow:to_server,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "to_client" not in labels
        assert "from_server" not in labels
        assert "to_server" not in labels  # Don't suggest duplicates
        assert "from_client" not in labels  # Alias for to_server
        assert "established" in labels  # Still available

    def test_flow_value_completion_excludes_not_established_when_established_exists(
        self,
    ):
        """Test flow value completion excludes not_established when established exists"""
        sig_content = "alert tcp any any -> any any (flow:established,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "not_established" not in labels
        assert "established" not in labels  # Don't suggest duplicates
        assert "to_server" in labels  # Still available
        assert "to_client" in labels  # Still available

    def test_flow_value_completion_with_multiple_existing_values(self):
        """Test flow value completion with multiple existing values"""
        sig_content = "alert tcp any any -> any any (flow:established,to_server,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "established" not in labels  # Already present
        assert "not_established" not in labels  # Excluded by established
        assert "to_server" not in labels  # Already present
        assert "to_client" not in labels  # Excluded by to_server
        assert "from_client" not in labels  # Excluded by to_server
        assert "from_server" not in labels  # Excluded by to_server
        assert "only_stream" in labels  # Still available
        assert "only_frag" in labels  # Still available

    def test_flow_value_completion_from_client_excludes_to_client(self):
        """Test flow value completion with from_client excludes to_client"""
        sig_content = "alert tcp any any -> any any (flow:from_client,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "to_client" not in labels
        assert "from_server" not in labels
        assert "from_client" not in labels  # Don't suggest duplicates
        assert "to_server" not in labels  # Alias for from_client
        assert "established" in labels  # Still available

    def test_flow_value_completion_stateless_excludes_established(self):
        """Test flow value completion with stateless excludes established and not_established"""
        sig_content = "alert tcp any any -> any any (flow:stateless,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "established" not in labels
        assert "not_established" not in labels
        assert "stateless" not in labels  # Don't suggest duplicates
        assert "to_server" in labels  # Still available
        assert "to_client" in labels  # Still available

    def test_flow_value_completion_established_excludes_stateless(self):
        """Test flow value completion with established excludes stateless"""
        sig_content = "alert tcp any any -> any any (flow:established,"
        sig_index = len(sig_content)

        result = self.completion_handler.get_flow_value_completion(
            sig_content, sig_index
        )

        assert result is not None
        labels = [item.label for item in result.items]
        assert "not_established" not in labels
        assert "stateless" not in labels
        assert "established" not in labels  # Don't suggest duplicates
        assert "to_server" in labels  # Still available
        assert "to_client" in labels  # Still available


class TestDatasetCompletion:
    """Tests for dataset keyword completion"""

    def setup_method(self):
        """Set up test fixtures"""
        self.completion_handler = SignatureCompletion(
            keywords_list=SAMPLE_KEYWORDS,
            app_layer_list=SAMPLE_APP_LAYERS,
            actions_items=SAMPLE_ACTIONS,
        )

    def test_is_dataset_completion_context_true(self):
        """Test dataset completion context detection - positive case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:'
        sig_index = len(sig_content)

        result = self.completion_handler.is_dataset_completion_context(
            sig_content, sig_index
        )

        assert result is True

    def test_is_dataset_completion_context_false(self):
        """Test dataset completion context detection - negative case"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; '
        sig_index = len(sig_content)

        result = self.completion_handler.is_dataset_completion_context(
            sig_content, sig_index
        )

        assert result is False

    def test_dataset_command_completion(self):
        """Test dataset completion suggests commands after dataset:"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "isset" in labels
        assert "isnotset" in labels
        assert "set" in labels
        assert "unset" in labels

    def test_dataset_command_completion_partial(self):
        """Test dataset completion with partial command"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:is'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "isset" in labels
        assert "isnotset" in labels

    def test_dataset_no_completion_for_name(self):
        """Test no dataset completion for dataset name"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        # Name is user-defined, no completion
        assert result is None

    def test_dataset_type_keyword_completion(self):
        """Test dataset completion suggests 'type' keyword after name"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "type" in labels

    def test_dataset_type_value_completion(self):
        """Test dataset completion suggests type values after 'type '"""
        sig_content = (
            'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type '
        )
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "string" in labels
        assert "md5" in labels
        assert "sha256" in labels
        assert "ipv4" in labels
        assert "ip" in labels

    def test_dataset_param_completion_after_type(self):
        """Test dataset completion suggests params after type is set"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "load" in labels
        assert "state" in labels
        assert "save" in labels
        assert "memcap" in labels
        assert "hashsize" in labels
        assert "format" in labels

    def test_dataset_param_exclusion_load_excludes_state(self):
        """Test that 'load' excludes 'state' from completion"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,load file.lst,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "state" not in labels
        assert "load" not in labels  # Already used
        assert "save" in labels  # Still available
        assert "memcap" in labels  # Still available

    def test_dataset_param_exclusion_state_excludes_load_save(self):
        """Test that 'state' excludes 'load' and 'save' from completion"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,state file.lst,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "load" not in labels
        assert "save" not in labels
        assert "state" not in labels  # Already used
        assert "memcap" in labels  # Still available

    def test_dataset_format_value_completion(self):
        """Test dataset completion suggests format values after 'format '"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,format '
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "csv" in labels
        assert "json" in labels
        assert "ndjson" in labels

    def test_dataset_json_params_available(self):
        """Test that JSON-related params are available after type"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "context_key" in labels
        assert "value_key" in labels
        assert "array_key" in labels
        assert "remove_key" in labels

    def test_dataset_no_duplicate_params(self):
        """Test that already-used params are not suggested again"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,memcap 10mb,'
        sig_index = len(sig_content)

        result = self.completion_handler.get_dataset_completion(sig_content, sig_index)

        assert result is not None
        labels = [item.label for item in result.items]
        assert "memcap" not in labels
        assert "load" in labels  # Still available

    def test_dataset_context_after_complete_command(self):
        """Test context parsing after complete command without comma"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset'
        sig_index = len(sig_content)

        context = self.completion_handler._parse_dataset_context(sig_content, sig_index)

        assert context["state"] == "after_command"

    def test_dataset_context_typing_command(self):
        """Test context parsing while typing command"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:iss'
        sig_index = len(sig_content)

        context = self.completion_handler._parse_dataset_context(sig_content, sig_index)

        assert context["state"] == "command"

    def test_dataset_context_type_keyword(self):
        """Test context parsing when type keyword is needed"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,'
        sig_index = len(sig_content)

        context = self.completion_handler._parse_dataset_context(sig_content, sig_index)

        assert context["state"] == "type_keyword"
        assert context["has_type"] is False

    def test_dataset_context_type_value(self):
        """Test context parsing when typing type value"""
        sig_content = (
            'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type '
        )
        sig_index = len(sig_content)

        context = self.completion_handler._parse_dataset_context(sig_content, sig_index)

        assert context["state"] == "type_value"

    def test_dataset_context_param_key(self):
        """Test context parsing when expecting param key"""
        sig_content = 'alert tcp any any -> any any (msg:"test"; dataset:isset,mydata,type string,'
        sig_index = len(sig_content)

        context = self.completion_handler._parse_dataset_context(sig_content, sig_index)

        assert context["state"] == "param_key"
        assert context["has_type"] is True
