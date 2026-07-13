"""
Copyright(C) 2026 Stamus Networks SAS
Written by Eric Leblond <eld@stamus-networks.com>

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

import sys
import argparse
import json
import re
from suricatals.suricata_command import SuriCmd
from importlib.metadata import version

__version__ = version("suricata-language-server")

MSG_RE = re.compile(r'msg\s*:\s*"([^"]*)"')
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")


def error_exit(error_str):
    print("ERROR: {0}".format(error_str))
    sys.exit(-1)


def build_sid_msg_index(rules_content):
    """Return {sid: msg} extracted from a raw rules-file string."""
    if not rules_content:
        return {}
    index = {}
    for line in rules_content.splitlines():
        sid_m = SID_RE.search(line)
        if not sid_m:
            continue
        msg_m = MSG_RE.search(line)
        if not msg_m:
            continue
        index[int(sid_m.group(1))] = msg_m.group(1)
    return index


def reshape_profile(raw_perf_json, sid_msg, top_n):
    """Turn Suricata's rule_perf.json into a compact top-N list with msg lookups."""
    doc = json.loads(raw_perf_json)
    rules = doc.get("rules", doc if isinstance(doc, list) else [])
    reshaped = []
    for entry in rules:
        sid = entry.get("signature_id") or entry.get("sid")
        reshaped.append(
            {
                "sid": sid,
                "msg": sid_msg.get(sid),
                "gid": entry.get("gid"),
                "rev": entry.get("rev"),
                "checks": entry.get("checks"),
                "matches": entry.get("matches"),
                "ticks_total": entry.get("ticks_total") or entry.get("ticks"),
                "ticks_max": entry.get("ticks_max"),
                "ticks_avg": entry.get("ticks_avg"),
                "ticks_avg_match": entry.get("ticks_avg_match"),
                "ticks_avg_nomatch": entry.get("ticks_avg_nomatch"),
            }
        )
    reshaped.sort(
        key=lambda r: (r.get("ticks_total") or 0),
        reverse=True,
    )
    return reshaped[:top_n]


def main():
    parser = argparse.ArgumentParser()
    parser.description = "Suricata PCAP Reader ({0})".format(__version__)
    parser.add_argument(
        "--version", action="store_true", help="Print version number and exit"
    )
    parser.add_argument(
        "--container",
        action="store_true",
        default=False,
        help="Use a container to run Suricata",
    )
    parser.add_argument(
        "--image",
        default=SuriCmd.SLS_DEFAULT_DOCKER_IMAGE,
        help="Suricata image to use in container mode",
    )
    parser.add_argument(
        "--suricata-binary", default="suricata", help="Path to Suricata binary"
    )
    parser.add_argument(
        "--suricata-config", default=None, help="Path to Suricata config"
    )
    parser.add_argument(
        "--rules-file",
        default=None,
        help="Optional rules file to use with PCAP analysis",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        default=False,
        help="Enable rules profiling: output top-N most expensive signatures "
        "(by ticks) instead of eve.json alerts. Requires a Suricata build "
        "with --enable-profiling.",
    )
    parser.add_argument(
        "--profile-top",
        type=int,
        default=100,
        help="Number of signatures to include in --profile output (default: 100)",
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="PCAP file to process with Suricata",
    )
    args = parser.parse_args()

    if args.version:
        print("{0}".format(__version__))
        sys.exit(0)

    if not args.pcap_file:
        parser.error("the following arguments are required: pcap_file")

    if args.profile_top <= 0:
        parser.error("--profile-top must be a positive integer")

    suricmd = SuriCmd(
        suricata_binary=args.suricata_binary, suricata_config=args.suricata_config
    )
    if args.container:
        suricmd.set_docker_mode(docker_image=args.image)

    rules_content = None
    if args.rules_file:
        with open(args.rules_file, "r", encoding="utf-8") as rf:
            rules_content = rf.read()

    try:
        if args.profile:
            raw, pcap_stats = suricmd.read_pcap_profile(
                args.pcap_file, rules_content, top_n=args.profile_top
            )
            reshaped = reshape_profile(
                raw, build_sid_msg_index(rules_content), args.profile_top
            )
            output = {
                "processing": pcap_stats,
                "rules": reshaped,
            }
            print(json.dumps(output, indent=2, ensure_ascii=False))
        else:
            eve_output = suricmd.read_pcap(args.pcap_file, rules_content)
            print(eve_output)
        sys.exit(0)
    except RuntimeError as e:
        error_exit(str(e))
