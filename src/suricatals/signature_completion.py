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


class SignatureCompletion:
    """Handles completion logic for Suricata signature files."""

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
