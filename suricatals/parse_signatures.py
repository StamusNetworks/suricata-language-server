import os
import hashlib

from suricatals.tests_rules import TestRules

class SuricataFile:
    def __init__(self, path=None, pp_suffixes=None, suricata_binary='suricata'):
        self.path = path
        self.suricata_binary = suricata_binary
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
        copy_obj = SuricataFile(self.path, suricata_binary=self.suricata_binary)
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
        lines_list = []
        with open(self.path, 'r', encoding='utf-8', errors='replace') as fhandle:
            test_rules = TestRules(suricata_binary=self.suricata_binary)
            result = test_rules.check_rule_buffer(fhandle.read())
        for error in result.get('errors', []):
            if 'line' in error:
                if error['line'] in lines_list:
                    continue
                range_end = 1000
                line_content = self.line_content_map.get(error['line'])
                if line_content:
                    range_end = len(line_content.rstrip())
                diagnostics.append({ "range": { "start": {"line": error['line'], "character": 0}, "end": {"line": error['line'], "character": range_end} }, "message": error['message'], "severity": 1 })
                lines_list.append(error['line'])
        for warning in result.get('warnings', []):
            line = None
            range_start = 0
            range_end = 1000
            if 'line' in warning:
                line = warning['line']
            elif 'content' in warning:
                line = self.content_line_map.get(warning['content'])
                range_start = warning['content'].index('sid:')
                range_end = range_start + len('sid:')
            if line is None or line in lines_list:
                continue
            diagnostics.append({ "range": { "start": {"line": line, "character": range_start}, "end": {"line": line, "character": range_end} }, "message": warning['message'], "severity": 2 })
            lines_list.append(line)
        for info in result.get('info', []):
            line = None
            if 'line' in info:
                line = info['line']
            elif 'content' in info:
                line = self.content_line_map.get(info['content'])
            if line is None or line in lines_list:
                continue
            start_char = info.get('start_char', 0)
            end_char = info.get('end_char', 0)
            diagnostics.append({ "range": { "start": {"line": line, "character": start_char}, "end": {"line": line, "character": end_char} }, "message": info['message'], "severity": 4 })
            lines_list.append(line)
        return diagnostics

    def parse_file(self, debug=False):
        """Build file Info by parsing file"""
        i = 0
        self.content_line_map= {}
        self.line_content_map= {}
        for line in self.contents_split:
            if line.startswith("#"):
                i += 1
                continue
            self.content_line_map[line] = i
            self.line_content_map[i] = line
            i += 1
