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
FLOW_KEYWORD_PATTERN = re.compile(r"flow:\s*([^;)]*?)$")


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
        self, sig_content: str, sig_index: int, line_index: int, file_lines: List[str]
    ) -> Optional[types.CompletionList]:
        """
        Handle completion for initial signature parameters (action and protocol).

        Args:
            sig_content: Content of the current line
            sig_index: Character index within the line
            line_index: Line number in the file
            file_lines: All lines in the file

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

        # Check if this is a continuation of a previous line
        if line_index == 0:
            return None
        elif not re.search(r"\\ *$", file_lines[line_index - 1]):
            return None

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
            sig_content: Content of the current line
            sig_index: Character index within the line

        Returns:
            True if in SID completion context, False otherwise
        """
        prefix = sig_content[0:sig_index]
        return SID_COMPLETION_PATTERN.search(prefix) is not None

    def is_before_content_section(self, sig_content: str, sig_index: int) -> bool:
        """
        Check if cursor is before the content matching section (before opening parenthesis).

        Args:
            sig_content: Content of the current line
            sig_index: Character index within the line

        Returns:
            True if before content section, False otherwise
        """
        return "(" not in sig_content[0:sig_index]

    def is_flow_value_completion_context(
        self, sig_content: str, sig_index: int
    ) -> bool:
        """
        Check if cursor is positioned for flow value completion (after "flow:" or "flow:value,").

        Args:
            sig_content: Content of the current line
            sig_index: Character index within the line

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
            sig_content: Content of the current line
            sig_index: Character index within the line

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
            sig_content: Content of the current line
            sig_index: Character index within the line

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
