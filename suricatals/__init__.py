"""
Copyright(C) 2018-2021 Chris Hansen <hansec@uw.edu>
Copyright(C) 2021-2023 Stamus Networks
Written by Chris Hansen <hansec@uw.edu>
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
from .langserver import LangServer
from .jsonrpc import JSONRPC2Connection, ReadWriter
import json
__version__ = '0.9.0'


def error_exit(error_str):
    print("ERROR: {0}".format(error_str))
    sys.exit(-1)


def main():
    #
    parser = argparse.ArgumentParser()
    parser.description = "Suricata Language Server ({0})".format(__version__)
    parser.add_argument(
        '--version', action="store_true",
        help="Print server version number and exit"
    )
    parser.add_argument(
        '--suricata-binary', default="suricata",
        help="Path to Suricata binary"
    )
    parser.add_argument(
        '--suricata-config', default=None,
        help="Path to Suricata config"
    )
    parser.add_argument(
        '--debug-log', action="store_true",
        help="Generate debug log in project root folder"
    )
    parser.add_argument(
        '--max-lines', default=1000, type=int,
        help="Don't start suricata analysis over this file size"
    )
    parser.add_argument(
        '--batch-file', default=None,
        help="Batch mode to parse only the file in argument"
    )
    args = parser.parse_args()
    if args.version:
        print("{0}".format(__version__))
        sys.exit(0)
    #
    settings = {
        "suricata_binary": args.suricata_binary,
        "suricata_config": args.suricata_config,
        "max_lines": args.max_lines,
    }
    #

    if args.batch_file is None:
        stdin, stdout = _binary_stdio()
        s = LangServer(conn=JSONRPC2Connection(ReadWriter(stdin, stdout)),
                       debug_log=args.debug_log, settings=settings)
        s.run()
    else:
        s = LangServer(conn=None, settings=settings)
        diags = s.analyse_file(args.batch_file)
        for diag in diags:
            print(json.dumps(diag.to_message()))


def _binary_stdio():
    """Construct binary stdio streams (not text mode).
    This seems to be different for Window/Unix Python2/3, so going by:
        https://stackoverflow.com/questions/2850893/reading-binary-data-from-stdin
    """

    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer

    return stdin, stdout
