import os
import hashlib

from suricatals.tests_rules import TestRules

class suricata_file:
    def __init__(self, path=None, pp_suffixes=None):
        self.path = path
        self.contents_split = []
        self.contents_pp = []
        self.content_line_map= {}
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
                contents = fhandle.read()
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
                diagnostics.append({ "range": { "start": {"line": error['line'], "character": 0}, "end": {"line": error['line'], "character": 0} }, "message": error['message'], "severity": 1 })
        for warning in result.get('warnings', []):
            line = None
            if 'line' in warning:
                line = warning['line']
            elif 'content' in warning:
                line = self.content_line_map.get(warning['content'])
            if line is None:
                continue
            diagnostics.append({ "range": { "start": {"line": line, "character": 0}, "end": {"line": line, "character": 0} }, "message": warning['message'], "severity": 2 })
        for info in result.get('info', []):
            line = None
            if 'line' in info:
                line = info['line']
            elif 'content' in info:
                line = self.content_line_map.get(info['content'])
            if line is None:
                continue
            start_char = info.get('start_char', 0)
            end_char = info.get('end_char', 0)
            diagnostics.append({ "range": { "start": {"line": line, "character": start_char}, "end": {"line": line, "character": end_char} }, "message": info['message'], "severity": 4 })
        return diagnostics

    def parse_file(self, debug=False):
        """Build file Info by parsing file"""
        i = 0
        self.content_line_map= {}
        for line in self.contents_split:
            if line.startswith("#"):
                i += 1
                continue
            self.content_line_map[line] = i
            i += 1
