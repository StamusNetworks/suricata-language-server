"""
Copyright(C) 2025 Stamus Networks
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

import re
from typing import List, Dict, Any


class SuricataSemanticTokenParser:
    TOKEN_TYPES = [
        "keyword",  # 0: Actions (alert), 'any', Direction (->)
        "type",  # 1: Protocols (tcp, http)
        "variable",  # 2: $HOME_NET, [10,20]
        "number",  # 3: Ports (80), Integers
        "property",  # 4: Option Keys (msg, content)
        "function",  # 5: Sticky Buffers (http.uri)
        "string",  # 6: Option Values
        "operator",  # 7: Punctuation
        "comment",  # 8: Comments
    ]

    TOKEN_MODIFIERS = ["declaration", "readonly", "deprecated"]

    def __init__(self, definitions: Dict[str, List[str]]):
        self.definitions = definitions
        self.deprecated_keywords = set(definitions.get("deprecated_keywords", []))
        self.master_regex = self._compile_master_regex()

    def _compile_master_regex(self) -> re.Pattern:
        def make_group(items: List[str]) -> str:
            if not items:
                return r"(?!x)x"
            sorted_items = sorted(items, key=len, reverse=True)
            return r"\b(" + "|".join(re.escape(i) for i in sorted_items) + r")\b"

        actions_pat = make_group(self.definitions.get("actions", []))
        base_proto_pat = make_group(self.definitions.get("protocols", []))
        protocols_pat = r"(?<=\s)" + base_proto_pat
        sticky_pat = (
            r"(?P<function>"
            + make_group(self.definitions.get("sticky_buffers", []))
            + r")"
        )

        options_list = self.definitions.get("options", [])
        if options_list:
            options_pat = (
                r"(?P<property>" + make_group(options_list) + r")(?=[\s]*[:;])"
            )
        else:
            options_pat = r"(?P<property>\b[a-z_0-9.]+(?=[\s]*[:;]))"

        patterns = [
            (r"(?P<comment>(^|[\s;])#.*)", "comment"),
            # Strings must be before keywords to avoid matching internals
            (r'(?P<string>"(\\.|[^"\\])*")', "string"),
            # Keywords / Actions
            (f"(?P<action>{actions_pat})", "keyword"),
            # Sticky Buffers (Functions)
            (sticky_pat, "function"),
            # Option Keys (Properties)
            (options_pat, "property"),
            # Protocols (Types)
            (f"(?P<protocol>{protocols_pat})", "type"),
            # --- UPDATED SECTIONS ---
            # 1. 'any' is a Constant -> Mapped to Keyword
            (r"(?P<constant>\bany\b)", "keyword"),
            # 2. Variables: Strict '$' prefix or bracketed lists
            # Removed 'any' from here.
            (r"(?P<variable>\$[A-Za-z0-9_]+|\[.*?\])", "variable"),
            # 3. Numbers: Ports, Ranges, Integers
            (r"(?P<number>\b\d+\b(:(\d+)?)?|(?<=[\s,\[]):\d+)", "number"),
            # 4. Structure
            (r"(?P<direction>(->|<>|=>))", "keyword"),
            (r"(?P<operator>[;:()])", "operator"),
        ]

        return re.compile("|".join(p[0] for p in patterns))

    def _utf16_len(self, s: str) -> int:
        """
        Returns the length of the string in UTF-16 code units.
        This is required because LSP uses UTF-16 offsets (emojis = 2 chars).
        """
        # We use utf-16-le to avoid the Byte Order Mark (BOM) counting as 2 bytes
        return len(s.encode("utf-16-le")) // 2

    def parse(self, text: str) -> List[int]:
        """Parse Suricata rule text and generate semantic tokens.

        Returns LSP semantic tokens format (relative delta encoding).

        Args:
            text: Suricata rule text to tokenize

        Returns:
            List[int]: Flattened array of [deltaLine, deltaStart, length, typeIdx, modifierBits]
        """
        data = []
        prev_line = 0
        prev_start = 0
        lines = text.splitlines(keepends=True)

        for line_idx, line in enumerate(lines):
            for match in self.master_regex.finditer(line):
                group = match.lastgroup

                # Default mapping
                token_type_str = group
                if group in ["action", "constant", "direction"]:
                    token_type_str = "keyword"
                if group == "protocol":
                    token_type_str = "type"

                try:
                    type_idx = self.TOKEN_TYPES.index(token_type_str)
                except ValueError:
                    continue

                # This accounts for any emojis occurring BEFORE this token.
                start_char_idx = match.start()
                start_col_utf16 = self._utf16_len(line[:start_char_idx])

                # We measure the UTF-16 length of the token text itself.
                # If the string contains an emoji, this returns N+1 compared to Python len.
                token_text = match.group()
                length_utf16 = self._utf16_len(token_text)

                delta_line = line_idx - prev_line

                if delta_line > 0:
                    delta_start = start_col_utf16  # New line: absolute from 0
                else:
                    delta_start = (
                        start_col_utf16 - prev_start
                    )  # Same line: relative to prev start

                # Check if this token is deprecated
                modifier_bits = 0
                if group == "property" and token_text in self.deprecated_keywords:
                    modifier_bits = (
                        1 << 2
                    )  # "deprecated" is at index 2 in TOKEN_MODIFIERS

                data.extend(
                    [delta_line, delta_start, length_utf16, type_idx, modifier_bits]
                )

                prev_line = line_idx
                prev_start = start_col_utf16

        return data

    def get_legend(self) -> Dict[str, Any]:
        """Get semantic tokens legend for LSP initialization.

        Returns:
            Dict: Legend with tokenTypes and tokenModifiers arrays
        """
        return {"tokenTypes": self.TOKEN_TYPES, "tokenModifiers": self.TOKEN_MODIFIERS}
