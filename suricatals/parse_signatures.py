import os
import hashlib
import re

from suricatals.tests_rules import TestRules

class suricata_file:
    def __init__(self, path=None, pp_suffixes=None):
        self.path = path
        self.contents_split = []
        self.contents_pp = []
        self.nLines = 0
        self.ast = None
        self.hash = None
        if path is not None:
            _, file_ext = os.path.splitext(os.path.basename(path))
            if pp_suffixes is not None:
                self.preproc = (file_ext in pp_suffixes)
            else:
                self.preproc = (file_ext == file_ext.upper())
        else:
            self.preproc = False

    def copy(self):
        """Copy content to new file object (does not copy objects)"""
        copy_obj = suricata_file(self.path)
        return copy_obj

    def load_from_disk(self):
        """Read file from disk"""
        try:
            with open(self.path, 'r', encoding='utf-8', errors='replace') as fhandle:
                contents = re.sub(r'\t', r' ', fhandle.read())
                self.hash = hashlib.md5(contents.encode('utf-8')).hexdigest()
                self.contents_split = contents.splitlines()
            self.contents_pp = self.contents_split
            self.nLines = len(self.contents_split)
        except:
            return 'Could not read/decode file'
        else:
            return None

    def check_file(self, obj_tree):
        diagnostics = []
        result = {}
        with open(self.path, 'r', encoding='utf-8', errors='replace') as fhandle:
            test_rules = TestRules()
            result = test_rules.check_rule_buffer(fhandle.read())
        for error in result.get('errors', []):
            if 'line' in error:
                diagnostics.append({ "range": { "start": {"line": error['line'], "character": 0}, "end": {"line": error['line'], "character": 10} }, "message": error['message'], "severity": 1 })
        for warning in result.get('warnings', []):
            if 'line' in warning:
                diagnostics.append({ "range": { "start": {"line": warning['line'], "character": 0}, "end": {"line": warning['line'], "character": 10} }, "message": warning['message'], "severity": 2 })
        for info in result.get('info', []):
            if 'line' in info:
                diagnostics.append({ "range": { "start": {"line": info['line'], "character": 0}, "end": {"line": info['line'], "character": 10} }, "message": info['message'], "severity": 4 })
        return diagnostics



def parse_file(file_obj, close_open_scopes, debug=False, pp_defs={}, include_dirs=[]):
    """Build file AST by parsing file"""

