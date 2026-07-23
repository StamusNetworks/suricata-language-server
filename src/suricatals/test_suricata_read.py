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

import os
import json
import subprocess
import pytest
from suricatals.suricata_command import SuriCmd


class TestSuricataRead:
    """Tests for the suricata-read command-line tool."""

    def test_read_pcap_cli_help(self):
        """Test that suricata-read --help works."""
        result = subprocess.run(
            ["suricata-read", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "Suricata PCAP Reader" in result.stdout
        assert "pcap_file" in result.stdout

    def test_read_pcap_cli_version(self):
        """Test that suricata-read --version works."""
        result = subprocess.run(
            ["suricata-read", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout.strip() != ""

    def test_read_pcap_cli_missing_pcap(self):
        """Test that suricata-read fails gracefully with missing PCAP file."""
        result = subprocess.run(
            ["suricata-read", "nonexistent.pcap"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0

    def test_read_pcap_basic(self):
        """Test reading a PCAP file with SuriCmd.read_pcap."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        suricmd = SuriCmd()
        eve_output = suricmd.read_pcap(pcap_path)

        # Verify we got output
        assert eve_output is not None
        assert len(eve_output) > 0

        # Verify it's valid JSON lines
        lines = eve_output.strip().split("\n")
        for line in lines:
            if line:  # Skip empty lines
                data = json.loads(line)
                assert "event_type" in data

    def test_read_pcap_with_rules(self):
        """Test reading a PCAP file with custom rules."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "short-http.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        rules_content = 'alert http any any -> any any (msg:"Test HTTP"; http.host; content:"www"; sid:1; rev:1;)'

        suricmd = SuriCmd()
        eve_output = suricmd.read_pcap(pcap_path, rules_content)

        # Verify we got output
        assert eve_output is not None
        assert len(eve_output) > 0

        # Check for alerts in the output
        lines = eve_output.strip().split("\n")
        has_alert = False
        for line in lines:
            if line:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    has_alert = True
                    break

        # We should have alerts from the HTTP traffic
        assert has_alert

    def test_read_pcap_cli_with_pcap_file(self):
        """Test suricata-read command-line with actual PCAP file."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        result = subprocess.run(
            ["suricata-read", pcap_path],
            capture_output=True,
            text=True,
            check=False,
        )

        # Should succeed
        assert result.returncode == 0

        # Should produce EVE JSON output
        assert len(result.stdout) > 0

        # Verify it's valid JSON lines
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if line:
                data = json.loads(line)
                assert "event_type" in data

    def test_read_pcap_cli_with_rules_file(self):
        """Test suricata-read command-line with custom rules file."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        rules_path = os.path.join(os.getcwd(), "tests", "clean.rules")

        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")
        if not os.path.exists(rules_path):
            pytest.skip(f"Rules file not found: {rules_path}")

        result = subprocess.run(
            ["suricata-read", "--rules-file", rules_path, pcap_path],
            capture_output=True,
            text=True,
            check=False,
        )

        # Should succeed
        assert result.returncode == 0

        # Should produce EVE JSON output
        assert len(result.stdout) > 0

        # Verify it's valid JSON lines
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if line:
                data = json.loads(line)
                assert "event_type" in data

    def test_read_pcap_empty_rules(self):
        """Test reading PCAP with empty rules content."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        suricmd = SuriCmd()
        eve_output = suricmd.read_pcap(pcap_path, "")

        # Should still work with empty rules
        assert eve_output is not None
        assert len(eve_output) > 0

    def test_read_pcap_set_option_smb_transactions(self):
        """Test that --set stream.checksum-validation=no enables SMB transaction events."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        suricmd = SuriCmd()
        eve_output = suricmd.read_pcap(
            pcap_path, set_options=["stream.checksum-validation=no"]
        )

        assert eve_output is not None
        events = [json.loads(l) for l in eve_output.strip().split("\n") if l]
        event_types = [e["event_type"] for e in events]
        assert "smb" in event_types

    def test_read_pcap_cli_set_option_smb_transactions(self):
        """Test that --set stream.checksum-validation=no enables SMB transaction events via CLI."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        # Without --set: only a flow event, no SMB transactions
        result_plain = subprocess.run(
            ["suricata-read", pcap_path],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result_plain.returncode == 0
        events_plain = [
            json.loads(l) for l in result_plain.stdout.strip().split("\n") if l
        ]
        assert not any(e["event_type"] == "smb" for e in events_plain)

        # With --set: SMB transactions are decoded
        result_set = subprocess.run(
            ["suricata-read", "--set", "stream.checksum-validation=no", pcap_path],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result_set.returncode == 0
        events_set = [json.loads(l) for l in result_set.stdout.strip().split("\n") if l]
        assert any(e["event_type"] == "smb" for e in events_set)

    def test_read_pcap_k_none_smb_transactions(self):
        """Test that -k none enables SMB transaction events via the API."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        suricmd = SuriCmd()
        eve_output = suricmd.read_pcap(pcap_path, checksum_checks="none")

        assert eve_output is not None
        events = [json.loads(l) for l in eve_output.strip().split("\n") if l]
        assert any(e["event_type"] == "smb" for e in events)

    def test_read_pcap_cli_k_none_smb_transactions(self):
        """Test that -k none enables SMB transaction events via the CLI."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "smb.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip(f"PCAP file not found: {pcap_path}")

        result = subprocess.run(
            ["suricata-read", "-k", "none", pcap_path],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        events = [json.loads(l) for l in result.stdout.strip().split("\n") if l]
        assert any(e["event_type"] == "smb" for e in events)

    def test_read_pcap_profile_lua_rule(self):
        """Test profiling a Lua-based rule against an HTTP PCAP."""
        pcap_path = os.path.join(os.getcwd(), "tests", "pcap", "short-http.pcap")
        rules_path = os.path.join(os.getcwd(), "tests", "lua.rules")
        for path in (pcap_path, rules_path):
            if not os.path.exists(path):
                pytest.skip(f"Required file not found: {path}")

        suricmd = SuriCmd()
        perf_json, stats = suricmd.read_pcap_profile(
            pcap_path,
            rules_file=rules_path,
        )

        assert perf_json is not None
        perf = json.loads(perf_json)
        rules = perf.get("rules", perf if isinstance(perf, list) else [])
        assert len(rules) > 0
        assert isinstance(stats, dict)
