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
from suricatals.suricata_command import SuriCmd
from importlib.metadata import version


__version__ = version("suricata-language-server")


def error_exit(error_str):
    print("ERROR: {0}".format(error_str))
    sys.exit(-1)


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

    suricmd = SuriCmd(
        suricata_binary=args.suricata_binary, suricata_config=args.suricata_config
    )
    if args.container:
        suricmd.set_docker_mode(docker_image=args.image)

    # Read rules file if provided
    rules_content = None
    if args.rules_file:
        with open(args.rules_file, "r", encoding="utf-8") as rf:
            rules_content = rf.read()

    # Process PCAP and output eve.json
    try:
        eve_output = suricmd.read_pcap(args.pcap_file, rules_content)
        print(eve_output)
        sys.exit(0)
    except RuntimeError as e:
        error_exit(str(e))
