"""
Copyright(C) 2021-2026 Stamus Networks SAS
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

import logging
import re
from typing import Optional, List, Dict, Any

from lsprotocol import types

log = logging.getLogger(__name__)

SID_COMPLETION_PATTERN = re.compile(r"sid:\s*$")
# Use greedy match (not lazy) since we're anchored with $ - no backtracking issues
FLOW_KEYWORD_PATTERN = re.compile(r"flow:\s{0,10}([^;)]*)$")
# Dataset keyword pattern - matches dataset: followed by content up to ; or )
DATASET_KEYWORD_PATTERN = re.compile(r"dataset:\s{0,10}([^;)]*)$")


class SignatureCompletion:
    """Handles completion logic for Suricata signature files."""

    # Flow keyword values with their descriptions
    FLOW_VALUES = [
        {
            "label": "established",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow state",
            "documentation": "Match established connections only",
        },
        {
            "label": "not_established",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow state",
            "documentation": "Match connections that are not established",
        },
        {
            "label": "stateless",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow state",
            "documentation": "Match packets without connection state tracking",
        },
        {
            "label": "to_client",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow direction",
            "documentation": "Match packets from server to client",
        },
        {
            "label": "to_server",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow direction",
            "documentation": "Match packets from client to server",
        },
        {
            "label": "from_client",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow direction",
            "documentation": "Match packets from client to server (alias for to_server)",
        },
        {
            "label": "from_server",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Flow direction",
            "documentation": "Match packets from server to client (alias for to_client)",
        },
        {
            "label": "only_stream",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Stream requirement",
            "documentation": "Match only if flow is part of an established TCP stream",
        },
        {
            "label": "no_stream",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Stream requirement",
            "documentation": "Match only if flow is not part of an established TCP stream",
        },
        {
            "label": "only_frag",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Fragmentation",
            "documentation": "Match only fragmented packets",
        },
        {
            "label": "no_frag",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Fragmentation",
            "documentation": "Match only non-fragmented packets",
        },
    ]

    # Mutual exclusivity rules for flow values
    # Each key cannot coexist with any of its values
    # Note: to_server and from_client are aliases (client→server)
    #       to_client and from_server are aliases (server→client)
    #       stateless is mutually exclusive with stateful options
    FLOW_EXCLUSIONS = {
        "to_client": ["to_server", "from_client", "from_server"],
        "to_server": ["to_client", "from_server", "from_client"],
        "from_client": ["to_client", "from_server", "to_server"],
        "from_server": ["to_server", "from_client", "to_client"],
        "established": ["not_established", "stateless"],
        "not_established": ["established", "stateless"],
        "stateless": ["established", "not_established"],
        "only_stream": ["no_stream"],
        "no_stream": ["only_stream"],
        "only_frag": ["no_frag"],
        "no_frag": ["only_frag"],
    }

    # Dataset command options (first positional argument after dataset:)
    DATASET_COMMANDS = [
        {
            "label": "isset",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset operation",
            "documentation": "Check if data exists in the dataset",
        },
        {
            "label": "isnotset",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset operation",
            "documentation": "Check if data does not exist in the dataset",
        },
        {
            "label": "set",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset operation",
            "documentation": "Add data to the dataset",
        },
        {
            "label": "unset",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset operation",
            "documentation": "Remove data from the dataset",
        },
    ]

    # Dataset type options (after 'type' keyword)
    DATASET_TYPES = [
        {
            "label": "string",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset type",
            "documentation": "String type dataset",
        },
        {
            "label": "md5",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset type",
            "documentation": "MD5 hash type dataset",
        },
        {
            "label": "sha256",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset type",
            "documentation": "SHA256 hash type dataset",
        },
        {
            "label": "ipv4",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset type",
            "documentation": "IPv4 address type dataset",
        },
        {
            "label": "ip",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset type",
            "documentation": "IP address type dataset",
        },
    ]

    # Dataset parameter keywords (after type is specified)
    DATASET_PARAMS = [
        {
            "label": "load",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "Load dataset from file at startup",
        },
        {
            "label": "state",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "Load on startup and save on exit",
        },
        {
            "label": "save",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "Save data when Suricata exits",
        },
        {
            "label": "memcap",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "Memory limit for dataset (e.g., 10mb)",
        },
        {
            "label": "hashsize",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "Hash table size for entries",
        },
    ]

    # JSON format related dataset parameters
    DATASET_JSON_PARAMS = [
        {
            "label": "format",
            "kind": types.CompletionItemKind.Property,
            "detail": "Dataset parameter",
            "documentation": "File format (csv, json, ndjson)",
        },
        {
            "label": "context_key",
            "kind": types.CompletionItemKind.Property,
            "detail": "JSON parameter",
            "documentation": "JSON enrichment alert key",
        },
        {
            "label": "value_key",
            "kind": types.CompletionItemKind.Property,
            "detail": "JSON parameter",
            "documentation": "JSON field containing matching value",
        },
        {
            "label": "array_key",
            "kind": types.CompletionItemKind.Property,
            "detail": "JSON parameter",
            "documentation": "Location of JSON array to search",
        },
        {
            "label": "remove_key",
            "kind": types.CompletionItemKind.Property,
            "detail": "JSON parameter",
            "documentation": "Remove value_key from alert output",
        },
    ]

    # Dataset format options (for 'format' parameter)
    DATASET_FORMATS = [
        {
            "label": "csv",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset format",
            "documentation": "CSV format (default)",
        },
        {
            "label": "json",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset format",
            "documentation": "JSON format",
        },
        {
            "label": "ndjson",
            "kind": types.CompletionItemKind.EnumMember,
            "detail": "Dataset format",
            "documentation": "Newline-delimited JSON format",
        },
    ]

    # Mutual exclusivity rules for dataset parameters
    # load/state/save are mutually exclusive storage options
    DATASET_EXCLUSIONS = {
        "load": ["state"],
        "state": ["load", "save"],
        "save": ["state"],
    }

    def __init__(
        self,
        keywords_list: List[Dict[str, Any]],
        app_layer_list: List[Dict[str, Any]],
        actions_items: List[Dict[str, Any]],
    ):
        """
        Initialize the completion handler.

        Args:
            keywords_list: List of Suricata keyword completion items
            app_layer_list: List of app layer protocol completion items
            actions_items: List of action (alert, drop, etc.) completion items
        """
        self.keywords_list = keywords_list
        self.app_layer_list = app_layer_list
        self.actions_items = actions_items

    def get_initial_params_completion(
        self, sig_content: str, sig_index: int
    ) -> Optional[types.CompletionList]:
        """
        Handle completion for initial signature parameters (action and protocol).

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            CompletionList for actions or app layers, or None if not applicable
        """
        word_split = re.split(" +", sig_content[0:sig_index])

        # First word - offer actions (alert, drop, etc.)
        if len(word_split) == 1:
            lsp_completion_items = []
            for item in self.actions_items:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 3)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)

        # Second word - offer app layer protocols
        if len(word_split) == 2:
            lsp_completion_items = []
            for item in self.app_layer_list:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 10)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)

        return None

    def get_sid_completion(self, next_sid: int) -> types.CompletionList:
        """
        Generate completion for SID (Signature ID) value.

        Args:
            next_sid: The next available SID to suggest

        Returns:
            CompletionList with the suggested SID
        """
        lsp_completion_items = [
            types.CompletionItem(
                label=str(next_sid),
                kind=types.CompletionItemKind.Value,
                detail="Next available SID",
                documentation="Next available signature ID based on file and workspace",
                insert_text=str(next_sid),
            )
        ]
        return types.CompletionList(is_incomplete=False, items=lsp_completion_items)

    def get_keyword_completion(
        self, sig_content: str, sig_index: int
    ) -> Optional[types.CompletionList]:
        """
        Handle completion for Suricata keywords within signature content.

        Args:
            sig_content: Content of the current line
            sig_index: Character index within the line

        Returns:
            CompletionList with matching keywords, or None if not applicable
        """
        # Find the start of the current keyword being typed
        cursor = sig_index - 1
        while cursor > 0:
            log.debug(
                "At index: %d of %d (%s)",
                cursor,
                len(sig_content),
                sig_content[cursor:sig_index],
            )
            if not sig_content[cursor].isalnum() and sig_content[cursor] not in [
                ".",
                "_",
            ]:
                break
            cursor -= 1

        log.debug("Final is: %d : %d", cursor, sig_index)

        # No partial keyword found
        if cursor == sig_index - 1:
            return None

        # This is an option edit (after : or ,), don't list keywords
        if sig_content[cursor] in [":", ","]:
            return None

        cursor += 1
        partial_keyword = sig_content[cursor:sig_index]
        log.debug("Got keyword start: '%s'", partial_keyword)

        # Find matching keywords
        items_list = []
        for item in self.keywords_list:
            if item["label"].startswith(partial_keyword):
                items_list.append(item)

        # Return completion items if matches found
        if len(items_list):
            lsp_completion_items = []
            for item in items_list:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 3)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)

        return None

    def is_sid_completion_context(self, sig_content: str, sig_index: int) -> bool:
        """
        Check if cursor is positioned for SID completion (after "sid:" or "sid: ").

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            True if in SID completion context, False otherwise
        """
        prefix = sig_content[0:sig_index]
        return SID_COMPLETION_PATTERN.search(prefix) is not None

    def is_before_content_section(self, sig_content: str, sig_index: int) -> bool:
        """
        Check if cursor is before the content matching section (before opening parenthesis).

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            True if before content section, False otherwise
        """
        prefix = sig_content[0:sig_index]
        return "(" not in prefix

    def is_flow_value_completion_context(
        self, sig_content: str, sig_index: int
    ) -> bool:
        """
        Check if cursor is positioned for flow value completion (after "flow:" or "flow:value,").

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            True if in flow value completion context, False otherwise
        """
        prefix = sig_content[0:sig_index]
        match = FLOW_KEYWORD_PATTERN.search(prefix)
        return match is not None

    def _parse_existing_flow_values(
        self, sig_content: str, sig_index: int
    ) -> List[str]:
        """
        Parse existing flow values from the current flow keyword.

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            List of existing flow values
        """
        prefix = sig_content[0:sig_index]
        match = FLOW_KEYWORD_PATTERN.search(prefix)
        if not match:
            return []

        values_str = match.group(1).strip()
        if not values_str:
            return []

        # Split by comma and clean up values
        values = [v.strip() for v in values_str.split(",")]
        return [v for v in values if v]

    def get_flow_value_completion(
        self, sig_content: str, sig_index: int
    ) -> Optional[types.CompletionList]:
        """
        Handle completion for flow keyword values with mutual exclusivity.

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            CompletionList with available flow values, or None if not applicable
        """
        # Get existing flow values
        existing_values = self._parse_existing_flow_values(sig_content, sig_index)

        # Find excluded values based on existing values
        excluded = set()
        for value in existing_values:
            if value in self.FLOW_EXCLUSIONS:
                excluded.update(self.FLOW_EXCLUSIONS[value])
            # Also exclude the value itself (don't suggest duplicates)
            excluded.add(value)

        # Filter available values
        available_values = [v for v in self.FLOW_VALUES if v["label"] not in excluded]

        # If no values available, return None
        if not available_values:
            return None

        # Build completion items
        lsp_completion_items = []
        for item in available_values:
            lsp_completion_items.append(
                types.CompletionItem(
                    label=item["label"],
                    kind=item["kind"],
                    detail=item.get("detail", ""),
                    documentation=item.get("documentation", ""),
                )
            )

        return types.CompletionList(is_incomplete=False, items=lsp_completion_items)

    def is_dataset_completion_context(self, sig_content: str, sig_index: int) -> bool:
        """
        Check if cursor is positioned for dataset value completion.

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            True if in dataset completion context, False otherwise
        """
        prefix = sig_content[0:sig_index]
        match = DATASET_KEYWORD_PATTERN.search(prefix)
        return match is not None

    def _parse_dataset_context(
        self, sig_content: str, sig_index: int
    ) -> Dict[str, Any]:
        """
        Parse the current dataset keyword state to determine what to suggest.

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            dict with:
            - 'state': 'command' | 'name' | 'type_keyword' | 'type_value' |
                       'format_value' | 'param_key' | 'param_value'
            - 'existing_params': list of already specified parameter names
            - 'current_param': the parameter currently being edited (if applicable)
            - 'has_type': whether type has been specified
        """
        prefix = sig_content[0:sig_index]
        match = DATASET_KEYWORD_PATTERN.search(prefix)
        if not match:
            return {"state": "unknown", "existing_params": [], "has_type": False}

        content = match.group(1)

        # Empty content - suggest commands
        if not content or not content.strip():
            return {"state": "command", "existing_params": [], "has_type": False}

        # Parse the comma-separated parts - don't strip the last part
        # as trailing spaces are significant
        raw_parts = content.split(",")
        parts = [p.strip() for p in raw_parts[:-1]]  # Strip all but last
        last_part_raw = raw_parts[-1] if raw_parts else ""
        parts.append(last_part_raw.lstrip())  # Only strip leading space from last

        # First part is the command
        # Second part is the dataset name
        # Remaining parts are key-value parameters

        if len(parts) == 1:
            # Still typing command or just finished command
            part = parts[0].strip()
            if part in ["isset", "isnotset", "set", "unset"]:
                # Command complete, but no comma yet - waiting for comma
                return {
                    "state": "after_command",
                    "existing_params": [],
                    "has_type": False,
                }
            # Still typing command
            return {"state": "command", "existing_params": [], "has_type": False}

        if len(parts) == 2:
            # Second part is the dataset name
            # Could be typing name or finished name
            return {"state": "name", "existing_params": [], "has_type": False}

        # Three or more parts - parsing parameters
        existing_params = []
        has_type = False

        # Parse parameters starting from part 3 (index 2)
        # Don't process the last part in this loop - handle it separately
        for part in parts[2:-1]:
            part = part.strip()
            if not part:
                continue

            # Check if this part starts with 'type '
            if part.startswith("type "):
                has_type = True
                existing_params.append("type")
            elif " " in part:
                # key value pair
                key = part.split()[0]
                existing_params.append(key)

        # Now analyze the last part (which has preserved trailing spaces)
        last_part = parts[-1]

        # Check if cursor is right after a comma (empty last part)
        if not last_part.strip():
            if not has_type:
                return {
                    "state": "type_keyword",
                    "existing_params": existing_params,
                    "has_type": False,
                }
            return {
                "state": "param_key",
                "existing_params": existing_params,
                "has_type": True,
            }

        # Check if we're typing after "type " (with trailing space)
        if last_part.startswith("type "):
            type_value = last_part[5:].strip()
            if type_value in ["string", "md5", "sha256", "ipv4", "ip"]:
                # Type is complete - this becomes an existing param
                has_type = True
                existing_params.append("type")
            else:
                # Still typing type value or just "type "
                return {
                    "state": "type_value",
                    "existing_params": existing_params,
                    "has_type": False,
                }

        # Check if we're typing after "format " (with trailing space)
        if last_part.startswith("format "):
            format_value = last_part[7:].strip()
            if format_value not in ["csv", "json", "ndjson"]:
                return {
                    "state": "format_value",
                    "existing_params": existing_params,
                    "has_type": has_type,
                }

        # Check other parameter patterns with trailing space
        if " " in last_part:
            key = last_part.split()[0]
            # Check if there's a value after the space
            value_part = last_part[len(key) :].strip()
            if not value_part:
                # Just "key " - typing parameter value
                if key == "format":
                    return {
                        "state": "format_value",
                        "existing_params": existing_params,
                        "has_type": has_type,
                    }
                return {
                    "state": "param_value",
                    "existing_params": existing_params,
                    "has_type": has_type,
                    "current_param": key,
                }

        # Typing a parameter key (no space yet)
        last_part_stripped = last_part.strip()

        # Check if 'type' is complete (as a standalone word about to get a space)
        if last_part_stripped == "type":
            return {
                "state": "type_keyword_partial",
                "existing_params": existing_params,
                "has_type": False,
            }

        if has_type:
            return {
                "state": "param_key",
                "existing_params": existing_params,
                "has_type": True,
                "partial": last_part_stripped,
            }

        # Need to type 'type' first
        return {
            "state": "type_keyword",
            "existing_params": existing_params,
            "has_type": False,
            "partial": last_part_stripped,
        }

    def get_dataset_completion(
        self, sig_content: str, sig_index: int
    ) -> Optional[types.CompletionList]:
        """
        Handle completion for dataset keyword values.

        Args:
            sig_content: Full reconstructed signature content (multiline rules already joined)
            sig_index: Character index within the reconstructed content

        Returns:
            CompletionList with available dataset values, or None if not applicable
        """
        context = self._parse_dataset_context(sig_content, sig_index)
        state = context.get("state", "unknown")
        existing_params = context.get("existing_params", [])

        log.debug("Dataset completion context: %s", context)

        if state == "command":
            return self._build_completion_list(self.DATASET_COMMANDS)

        if state == "after_command":
            # After command, waiting for comma - no completion
            return None

        if state == "name":
            # Dataset name is user-defined - no completion
            return None

        if state in ["type_keyword", "type_keyword_partial"]:
            # Suggest "type" keyword
            items = [
                types.CompletionItem(
                    label="type",
                    kind=types.CompletionItemKind.Keyword,
                    detail="Required parameter",
                    documentation="Dataset type (string, md5, sha256, ipv4, ip)",
                    insert_text="type ",
                )
            ]
            return types.CompletionList(is_incomplete=False, items=items)

        if state == "type_value":
            return self._build_completion_list(self.DATASET_TYPES)

        if state == "format_value":
            return self._build_completion_list(self.DATASET_FORMATS)

        if state == "param_key":
            # Filter out already used params and apply exclusions
            excluded = set(existing_params)

            # Apply mutual exclusivity rules
            for param in existing_params:
                if param in self.DATASET_EXCLUSIONS:
                    excluded.update(self.DATASET_EXCLUSIONS[param])

            # Combine base params and JSON params
            all_params = self.DATASET_PARAMS + self.DATASET_JSON_PARAMS

            # Filter available params
            available = [p for p in all_params if p["label"] not in excluded]

            if not available:
                return None

            return self._build_completion_list(available)

        if state == "param_value":
            # Only format has predefined values
            current_param = context.get("current_param", "")
            if current_param == "format":
                return self._build_completion_list(self.DATASET_FORMATS)
            # Other params take user-defined values (file paths, numbers)
            return None

        return None

    def _build_completion_list(
        self, items: List[Dict[str, Any]]
    ) -> types.CompletionList:
        """
        Build a CompletionList from a list of item dictionaries.

        Args:
            items: List of completion item dictionaries

        Returns:
            CompletionList with the items
        """
        lsp_items = []
        for item in items:
            lsp_items.append(
                types.CompletionItem(
                    label=item["label"],
                    kind=item.get("kind", types.CompletionItemKind.Text),
                    detail=item.get("detail", ""),
                    documentation=item.get("documentation", ""),
                    insert_text=item.get("insert_text"),
                )
            )
        return types.CompletionList(is_incomplete=False, items=lsp_items)
