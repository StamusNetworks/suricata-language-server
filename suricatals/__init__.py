from __future__ import print_function
import sys
import os
import argparse
from .langserver import LangServer
from .jsonrpc import JSONRPC2Connection, ReadWriter
__version__ = '0.2.0'


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
        '--debug_log', action="store_true",
        help="Generate debug log in project root folder"
    )
    parser.add_argument(
        '--max-lines', default=1000, type=int,
        help="Don't start suricata analysis over this file size"
    )
    args = parser.parse_args()
    if args.version:
        print("{0}".format(__version__))
        sys.exit(0)
    #
    settings = {
        "suricata_binary": args.suricata_binary,
        "max_lines": args.max_lines,
    }
    #
    stdin, stdout = _binary_stdio()
    s = LangServer(conn=JSONRPC2Connection(ReadWriter(stdin, stdout)),
                   debug_log=args.debug_log, settings=settings)
    s.run()


def _binary_stdio():
    """Construct binary stdio streams (not text mode).
    This seems to be different for Window/Unix Python2/3, so going by:
        https://stackoverflow.com/questions/2850893/reading-binary-data-from-stdin
    """

    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer

    return stdin, stdout
