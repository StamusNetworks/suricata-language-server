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

from json.decoder import JSONDecodeError
import os
import json


class SuricataEngineAnalyzer:
    """Analyzer for Suricata engine analysis output."""

    SURICATA_ENGINE_ANALYSIS = "Suricata Engine Analysis"

    def __init__(self, suricata_version):
        """Initialize engine analyzer with Suricata version.

        Args:
            suricata_version: Version string (e.g., "7.0.0")
        """
        self.suricata_version = suricata_version

    def json_compat_version(self):
        """Check if Suricata version supports JSON format for engine analysis."""
        major, minor, fix = self.suricata_version.split(".")
        if int(major) < 6:
            return True
        elif int(major) == 6 and int(minor) == 0 and int(fix) < 4:
            return False
        return True

    def parse_engine_analysis(self, log_dir):
        """Parse engine analysis output based on version and format.

        Args:
            log_dir: Directory containing Suricata analysis output

        Returns:
            List of signature analysis data
        """
        if self.json_compat_version():
            json_path = os.path.join(log_dir, "rules.json")
            if os.path.isfile(json_path):
                return self._parse_engine_analysis_v2(json_path)
            else:
                # we end up in this case when no rules is valid in buffer
                return []
        return self._parse_engine_analysis_v1(log_dir)

    def _parse_engine_analysis_v1(self, log_dir):
        """Parse text-based engine analysis format (older Suricata versions)."""
        analysis = []
        analysis_path = os.path.join(log_dir, "rules_analysis.txt")
        if not os.path.isfile(analysis_path):
            return analysis
        with open(analysis_path, "r", encoding="utf-8") as analysis_file:
            in_sid_data = False
            signature: dict[str, (str | list[str])] = {}
            for line in analysis_file:
                if line.startswith("== "):
                    in_sid_data = True
                    signature = {"sid": line.split(" ")[2]}
                    continue
                elif in_sid_data and len(line) == 1:
                    in_sid_data = False
                    analysis.append(signature)
                    signature = {}
                elif in_sid_data and "content" not in signature:
                    signature["content"] = line.strip()
                    continue
                elif in_sid_data and "Warning: " in line:
                    warning = line.split("Warning: ")[1]
                    if "warnings" not in signature:
                        signature["warnings"] = []
                    if isinstance(signature["warnings"], str):
                        raise ValueError("Signature warnings is not a list")
                    signature["warnings"].append(warning.strip())
                elif in_sid_data and "Fast Pattern" in line:
                    if "info" not in signature:
                        signature["info"] = []
                    if isinstance(signature["info"], str):
                        raise ValueError("Signature info is not a list")
                    signature["info"].append(line.strip())
        return analysis

    def _parse_engine_analysis_v2(self, json_path):
        """Parse JSON-based engine analysis format (modern Suricata versions)."""
        analysis = []
        with open(json_path, "r", encoding="utf-8") as analysis_file:
            for line in analysis_file:
                try:
                    signature_info = json.loads(line)
                except JSONDecodeError:
                    continue

                signature_msg = self._build_signature_message(signature_info)
                analysis.append(signature_msg)
        return analysis

    def _build_signature_message(self, signature_info):
        """Build signature message dict from parsed JSON.

        Args:
            signature_info: Parsed JSON signature data

        Returns:
            Dict with signature analysis data
        """
        signature_msg = {"content": signature_info["raw"]}

        self._add_type_info(signature_msg, signature_info)
        self._add_sid(signature_msg, signature_info)
        self._check_bidirectional_flow(signature_msg, signature_info)
        self._add_warnings_and_notes(signature_msg, signature_info)
        self._analyze_engines(signature_msg, signature_info)

        return signature_msg

    def _add_type_info(self, signature_msg, signature_info):
        """Add rule type to info list."""
        if "type" in signature_info:
            self._ensure_list(signature_msg, "info")
            type_msg = f'Rule type is "{signature_info["type"]}"'
            signature_msg["info"].append(type_msg)

    def _add_sid(self, signature_msg, signature_info):
        """Add signature ID to message."""
        if "id" in signature_info:
            signature_msg["sid"] = signature_info["id"]

    def _check_bidirectional_flow(self, signature_msg, signature_info):
        """Check for bidirectional flow without flow keyword."""
        flags = signature_info.get("flags", [])
        if "toserver" in flags and "toclient" in flags:
            self._add_warning(
                signature_msg,
                "Rule inspect server and client side, consider adding a flow keyword",
            )

    def _add_warnings_and_notes(self, signature_msg, signature_info):
        """Add warnings and notes from signature info."""
        if "warnings" in signature_info:
            self._ensure_list(signature_msg, "warnings")
            signature_msg["warnings"].extend(signature_info["warnings"])

        if "notes" in signature_info:
            self._ensure_list(signature_msg, "info")
            signature_msg["info"].extend(signature_info["notes"])

    def _analyze_engines(self, signature_msg, signature_info):
        """Analyze engines and generate warnings for performance issues."""
        if "engines" not in signature_info:
            return

        engine_analysis = self._collect_engine_data(signature_info["engines"])
        self._generate_engine_warnings(signature_msg, engine_analysis)

    def _collect_engine_data(self, engines):
        """Collect data from all engines for analysis.

        Returns:
            Dict with app_proto, multiple_app_proto, got_raw_match, got_content, got_pcre
        """
        app_proto = None
        multiple_app_proto = False
        got_raw_match = False
        got_content = False
        got_pcre = False

        for engine in engines:
            if "app_proto" in engine:
                new_proto = engine["app_proto"]
                if app_proto is None:
                    app_proto = new_proto
                elif app_proto != new_proto:
                    if not self._are_compatible_protocols(app_proto, new_proto):
                        multiple_app_proto = True
            else:
                got_raw_match = True

            # Check matches
            for match in engine.get("matches", []):
                match_name = match["name"]
                if match_name == "content":
                    got_content = True
                elif match_name == "pcre":
                    got_pcre = True

        return {
            "app_proto": app_proto,
            "multiple_app_proto": multiple_app_proto,
            "got_raw_match": got_raw_match,
            "got_content": got_content,
            "got_pcre": got_pcre,
        }

    def _are_compatible_protocols(self, proto1, proto2):
        """Check if two protocols are compatible (e.g., http/http2, dns/doh2)."""
        compatible_groups = [
            {"http", "http2"},
            {"dns", "doh2"},
        ]
        for group in compatible_groups:
            if proto1 in group and proto2 in group:
                return True
        return False

    def _generate_engine_warnings(self, signature_msg, engine_analysis):
        """Generate warnings based on engine analysis data."""
        if engine_analysis["got_pcre"] and not engine_analysis["got_content"]:
            self._add_warning(
                signature_msg,
                "Rule with pcre without content match (possible performance issue)",
            )

        if engine_analysis["app_proto"] and engine_analysis["got_raw_match"]:
            self._add_warning(
                signature_msg,
                f'Application layer "{engine_analysis["app_proto"]}" combined with raw match, '
                "consider using a match on application buffer",
            )

        if engine_analysis["multiple_app_proto"]:
            self._add_warning(
                signature_msg, "Multiple application layers in same signature"
            )

    def _ensure_list(self, signature_msg, key):
        """Ensure a key exists as a list in signature_msg."""
        if key not in signature_msg:
            signature_msg[key] = []

    def _add_warning(self, signature_msg, warning):
        """Add a warning to signature message."""
        self._ensure_list(signature_msg, "warnings")
        signature_msg["warnings"].append(warning)

    def parse_mpm_data(self, log_dir):
        """Parse Multi-Pattern Matching data from rules.json.

        Args:
            log_dir: Directory containing rules.json

        Returns:
            Dict with 'buffer' and 'sids' keys containing MPM analysis
        """
        mpm_data = []
        mpm_analysis = {"buffer": {}, "sids": {}}
        try:
            with open(
                os.path.join(log_dir, "rules.json"), "r", encoding="utf-8"
            ) as rules_json:
                for line in rules_json:
                    # some suricata version have an invalid JSON formatted message
                    try:
                        rule_analysis = json.loads(line)
                    except json.JSONDecodeError:
                        return None
                    if "mpm" in rule_analysis:
                        rule_analysis["mpm"]["id"] = rule_analysis["id"]
                        rule_analysis["mpm"]["gid"] = rule_analysis["gid"]
                        mpm_data.append(rule_analysis["mpm"])
                    else:
                        if "engines" in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for engine in rule_analysis.get("engines", []):
                                if engine["is_mpm"]:
                                    fp_buffer = engine["name"]
                                    for match in engine.get("matches", []):
                                        if match.get("name") == "content":
                                            if match.get("content", {}).get(
                                                "is_mpm", False
                                            ):
                                                fp_pattern = match["content"]["pattern"]
                                                break
                                    if fp_pattern:
                                        break
                            if fp_buffer and fp_pattern:
                                mpm_data.append(
                                    {
                                        "id": rule_analysis["id"],
                                        "gid": rule_analysis["gid"],
                                        "buffer": fp_buffer,
                                        "pattern": fp_pattern,
                                    }
                                )
                            continue
                        if "lists" in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for key in rule_analysis["lists"]:
                                fp_buffer = key
                                for match in rule_analysis["lists"][key].get(
                                    "matches", []
                                ):
                                    if match.get("name") == "content":
                                        if match.get("content", {}).get(
                                            "is_mpm", False
                                        ):
                                            fp_pattern = match["content"]["pattern"]
                                            break
                                if fp_pattern:
                                    break
                            if fp_buffer and fp_pattern:
                                mpm_data.append(
                                    {
                                        "id": rule_analysis["id"],
                                        "gid": rule_analysis["gid"],
                                        "buffer": fp_buffer,
                                        "pattern": fp_pattern,
                                    }
                                )
                            continue
        except FileNotFoundError:
            return mpm_analysis
        # target to have
        # { 'http.host': { 'grosminet': { 'count': 34, sigs: [{'id': 2, 'gid':1}]} } }
        for sig in mpm_data:
            if "content" in sig:
                sig_pattern = sig["content"]["pattern"]
            else:
                sig_pattern = sig["pattern"]
            if sig["buffer"] in mpm_analysis["buffer"]:
                if sig_pattern in mpm_analysis["buffer"][sig["buffer"]]:
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern]["count"] += 1
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern]["sigs"].append(
                        {"id": sig["id"], "gid": sig["gid"]}
                    )
                else:
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern] = {
                        "count": 1,
                        "sigs": [{"id": sig["id"], "gid": sig["gid"]}],
                    }
            else:
                mpm_analysis["buffer"][sig["buffer"]] = {
                    sig_pattern: {
                        "count": 1,
                        "sigs": [{"id": sig["id"], "gid": sig["gid"]}],
                    }
                }
            mpm_analysis["sids"][sig["id"]] = {
                "buffer": sig["buffer"],
                "pattern": sig_pattern,
            }
        return mpm_analysis
