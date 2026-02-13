"""
Copyright(C) 2026 Stamus Networks
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

import json
import importlib.resources
from typing import Dict, Any


class SuricataDiscovery:
    """Discover Suricata capabilities (keywords, protocols, actions)."""

    # Constants for common strings
    ALERT_ACTION_DETAIL = "Alert action"
    STICKY_BUFFER_DETAIL = "Sticky Buffer"

    ACTIONS_ITEMS = [
        {
            "label": "alert",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert",
        },
        {
            "label": "config",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Configuration signature. Used mostly for conditional logging.",
        },
        {
            "label": "drop",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert and drop flow",
        },
        {
            "label": "pass",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Stop inspecting the data",
        },
        {
            "label": "reject",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert and reset session",
        },
        {
            "label": "rejectsrc",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert and reset session for source IP",
        },
        {
            "label": "rejectdst",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert and reset session for destination IP",
        },
        {
            "label": "rejectboth",
            "kind": 14,
            "detail": ALERT_ACTION_DETAIL,
            "documentation": "Trigger alert and reset session for both IPs",
        },
    ]

    def __init__(self, suricmd):
        """Initialize discovery with SuriCmd instance.

        Args:
            suricmd: SuriCmd instance for executing Suricata commands
        """
        self.suricmd = suricmd

    def _get_keywords_from_json(self):
        """Load cached keyword metadata from data file."""
        keywords = {}
        try:
            ressource_path = (
                importlib.resources.files("suricatals")
                / "data"
                / "suricata-keywords.json"
            )
            file_content = ressource_path.read_text(encoding="utf-8")
            known_keywords = json.loads(file_content)
            for keyword in known_keywords:
                keywords[keyword["name"]] = keyword
        except FileNotFoundError:
            pass
        return keywords

    def build_keywords_list(self):
        """Query Suricata for keyword list with metadata.

        Returns:
            List of keyword dicts with label, kind, detail, documentation
        """
        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()
        self.suricmd.generate_config(tmpdir)
        outdata = self.suricmd.run(["--list-keywords=csv"])
        self.suricmd.cleanup()
        if outdata is None:
            return []
        official_keywords = self._get_keywords_from_json()
        keywords = outdata.splitlines()
        keywords.pop(0)
        keywords_list = []
        for keyword in keywords:
            keyword_array = keyword.split(";")
            try:
                detail = "No option"
                if "sticky" in keyword_array[3]:
                    detail = self.STICKY_BUFFER_DETAIL
                elif keyword_array[3] == "none":
                    detail = "No option"
                else:
                    detail = keyword_array[3]
                if keyword_array[0] in official_keywords:
                    detail = f'{detail} (min_version: {official_keywords[keyword_array[0]]["initial_version"]}, max_version: {official_keywords[keyword_array[0]]["last_version"]})'
                else:
                    detail = f"{detail} (custom keyword)"
                documentation = keyword_array[1]
                if len(keyword_array) > 5:
                    if "https" in keyword_array[4]:
                        documentation += "\n\n"
                        documentation += "[Documentation](" + keyword_array[4] + ")"
                        documentation = {"kind": "markdown", "value": documentation}
                keyword_item = {
                    "label": keyword_array[0],
                    "kind": 14,
                    "detail": detail,
                    "documentation": documentation,
                }
                if "content modifier" in keyword_array[3]:
                    keyword_item["kind"] = 10  # Property instead of Keyword
                    keyword_item["tags"] = [1]
                    keyword_item["deprecated"] = True
                    keyword_item["detail"] = "Content Modifier (deprecated)"
                keywords_list.append(keyword_item)
            except IndexError:
                pass
        return keywords_list

    def build_app_layer_list(self):
        """Query Suricata for app-layer protocols.

        Returns:
            List of protocol dicts with label, detail, kind
        """
        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()
        self.suricmd.generate_config(tmpdir)
        suri_cmd = [
            "--list-app-layer-proto",
        ]

        outdata = self.suricmd.run(suri_cmd)
        # start suricata in test mode
        self.suricmd.cleanup()
        if outdata is None:
            return []
        applayers = outdata.splitlines()
        while not applayers[0].startswith("===="):
            applayers.pop(0)
        applayers.pop(0)
        applayers_list = [
            {"label": "tcp", "detail": "tcp", "kind": 14},
            {"label": "udp", "detail": "udp", "kind": 14},
        ]
        for app_layer in applayers:
            app_layer_item = {"label": app_layer, "detail": app_layer, "kind": 14}
            applayers_list.append(app_layer_item)
        return applayers_list

    def get_semantic_token_definitions(self) -> Dict[str, Any]:
        """Aggregate keywords, protocols, and actions for semantic highlighting.

        Returns:
            Dict with actions, protocols, sticky_buffers, options, deprecated_keywords
        """
        # we need to get the list of keywords from suricata
        keywords = self.build_keywords_list()
        sticky_buffers = [
            k["label"]
            for k in keywords
            if self.STICKY_BUFFER_DETAIL in k.get("detail", "")
        ]
        options = [
            k["label"]
            for k in keywords
            if self.STICKY_BUFFER_DETAIL not in k.get("detail", "")
        ]
        deprecated_keywords = [
            k["label"] for k in keywords if k.get("deprecated", False)
        ]
        app_layers = [k["label"] for k in self.build_app_layer_list()]
        actions = [k["label"] for k in self.ACTIONS_ITEMS]
        return {
            "actions": actions,
            "protocols": app_layers,
            "sticky_buffers": sticky_buffers,
            "options": options,
            "deprecated_keywords": deprecated_keywords,
        }
