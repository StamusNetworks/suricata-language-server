import hashlib

import re

class FileRange:
    def __init__(self, line_start, col_start, line_end, col_end):
        self.line_start = line_start
        self.col_start = col_start
        self.line_end = line_end
        self.col_end = col_end

    def __repr__(self):
        return "FileRange()"

    def to_range(self):
        return {"start": {"line": self.line_start, "character": self.col_start}, "end": {"line": self.line_end, "character": self.col_end}}

class Signature:
    GETSID = re.compile(r"sid *:(\d+)")
    def __init__(self, line, content, multiline = False):
        self.line = line
        self.line_end = line
        self.multiline = multiline
        if self.multiline:
            self.content = content.strip('\\')
        else:
            self.content = content
        self.raw_content = [content]
        self.multiline = multiline
        self.sid = 0
        self._search_sid(content)
        self.mpm = None
        self.has_error = False

    def append_content(self, content, line):
        self.content += content.rstrip('\\')
        self.raw_content.append(content)
        self.line_end = line
        if self.sid == 0:
            self._search_sid(content)

    def _get_diag_range_by_sid(self):
        fr = None
        i = 0
        for line in self.raw_content:
            if "sid:" in line:
                line_start = self.line + i
                line_end = line_start
                range_start = line.index('sid:')
                range_end = range_start + len('sid:')
                fr = FileRange(line_start, range_start, line_end, range_end)
                break
            i += 1
        return fr

    def get_diag_range(self, mode="all", pattern=""):
        fr = None
        if mode == "all":
            last_char = len(self.raw_content[-1].rstrip())
            fr = FileRange(self.line, 0, self.line_end, last_char)
        elif mode == "sid":
            i = 0
            fr = self._get_diag_range_by_sid()
        elif mode == "pattern":
            # TODO 'normalize' string like "rer|20|b"
            pattern_match = re.compile(f'content: *("{pattern}")')
            i = 0
            found = False
            for line in self.raw_content:
                match = pattern_match.search(line)
                if match:
                    line_start = self.line + i
                    line_end = line_start
                    range_start = match.start()
                    range_end = match.end()
                    fr = FileRange(line_start, range_start, line_end, range_end)
                    found = True
                    break
                i += 1
            if found == False:
                fr = self._get_diag_range_by_sid()
        return fr

    def _search_sid(self, content):
        match = self.GETSID.search(content)
        if match:
            self.sid = int(match.groups()[0])

    def __repr__(self):
        return "Signature()"

    def __str__(self):
        return "%d:%s" % (self.sid, self.content)

class SignatureSet:
    def __init__(self):
        self.content_map= {}
        self.line_map= {}
        self.sid_map= {}
        self.signatures = []

    def add_signature(self, line, content, multiline = False):
        signature = Signature(line, content, multiline = multiline)
        self.signatures.append(signature)
        self.content_map[content] = signature
        self.line_map[line] = signature
        if signature.sid:
            self.sid_map[signature.sid] = signature
        return signature

    def add_content_to_signature(self, sig_line, line, content):
        signature = self.get_sig_by_line(sig_line)
        if signature is None:
            return
        signature.append_content(content, line)
        self.content_map[signature.content] = signature
        if signature.sid != 0:
            self.sid_map[signature.sid] = signature

    def get_sig_by_line(self, line):
        return self.line_map.get(line)

    def get_sig_by_content(self, content):
        return self.content_map.get(content)

    def get_sig_by_sid(self, sid):
        return self.sid_map.get(sid)


class SuricataFile:
    IS_COMMENT = re.compile(r"[ \t]*#")
    GET_MULTILINES = re.compile(r"\\ *$" )

    def __init__(self, path, rules_tester):
        self.path = path
        self.rules_tester = rules_tester
        self.contents_split = []
        self.sigset = SignatureSet()
        self.nLines = 0
        self.hash = None
        self.mpm = None
        self.diagnosis = None

    def copy(self):
        """Copy content to new file object (does not copy objects)"""
        copy_obj = SuricataFile(self.path, self.rules_tester)
        return copy_obj

    def load_from_disk(self):
        """Read file from disk"""
        try:
            contents = ''
            with open(self.path, 'r', encoding='utf-8', errors='replace') as fhandle:
                contents = fhandle.read()
            self.hash = hashlib.md5(contents.encode('utf-8')).hexdigest()
            self.contents_split = contents.splitlines()
            self.nLines = len(self.contents_split)
            self.parse_file()
        # pylint: disable=W0703
        except Exception:
            return 'Could not read/decode file'
        else:
            return None

    def sort_diagnosis(self, key):
        return -key['severity']

    def check_file(self):
        diagnostics = []
        result = {}
        with open(self.path, 'r', encoding='utf-8', errors='replace') as fhandle:
            result = self.rules_tester.check_rule_buffer(fhandle.read())
            self.mpm = result.get('mpm', {}).get('buffer')
            for sid in result.get('mpm', {}).get('sids'):
                signature = self.sigset.get_sig_by_sid(sid)
                if signature is not None:
                    signature.mpm = result.get('mpm', {}).get('sids', {}).get(sid)
        for error in result.get('errors', []):
            if 'line' in error:
                range_end = 1000
                signature = self.sigset.get_sig_by_line(error['line'])
                if signature:
                    signature.has_error = True
                    sig_range = signature.get_diag_range(mode="all")
                    diagnostics.append({ "range": sig_range.to_range(), "message": error['message'], "source": error['source'], "severity": 1 })
                else: 
                    diagnostics.append({ "range": { "start": {"line": error['line'], "character": 0}, "end": {"line": error['line'], "character": range_end} }, "message": error['message'], "source": error['source'], "severity": 1 })
        for warning in result.get('warnings', []):
            line = None
            signature = None
            range_start = 0
            range_end = 1000
            if 'line' in warning:
                line = warning['line']
            elif 'content' in warning:
                signature = self.sigset.get_sig_by_content(warning['content'])
                if signature is not None:
                    line = signature.line
            elif 'sid' in warning:
                signature = self.sigset.get_sig_by_sid(warning['sid'])
                if signature is not None:
                    line = signature.line
            if line is None:
                continue
            if signature is not None:
                diagnostics.append({ "range": signature.get_diag_range(mode="sid").to_range(), "message": warning['message'], "source": warning['source'], "severity": 2 })
            else:
                diagnostics.append({ "range": { "start": {"line": line, "character": range_start}, "end": {"line": line, "character": range_end} }, "message": warning['message'], "source": warning['source'], "severity": 2 })
        for info in result.get('info', []):
            line = None
            signature = None
            if 'line' in info:
                line = info['line']
            elif 'content' in info:
                signature = self.sigset.get_sig_by_content(info['content'])
                if signature:
                    line = signature.line
            if line is None:
                continue
            sig_range = FileRange(line, 0, line, 1)
            if signature is not None:
                if "Fast Pattern \"" in info['message']:
                    sig_range = signature.get_diag_range(mode='pattern', pattern=signature.mpm['pattern'])
                else:
                    sig_range = signature.get_diag_range(mode='sid')
            diagnostics.append({ "range": sig_range.to_range(), "message": info['message'], "source": info['source'], "severity": 4 })
        for sig in self.sigset.signatures:
            if sig.mpm is None:
                if sig.sid and sig.has_error == False:
                    message = "No Fast pattern used, consider adding one to improve performance if possible."
                    diagnostics.append({ "range": sig.get_diag_range(mode="sid").to_range(), "message": message, "source": "Suricata MPM Analysis", "severity": 4 })
                continue
            # mpm is content:"$pattern"
            pattern = self.mpm.get(sig.mpm['buffer'], {}).get(sig.mpm['pattern'])
            if pattern is None:
                continue
            if pattern['count'] > 1:
                message = "Fast pattern '%s' on '%s' buffer is used in %d different signatures, consider using a unique fast pattern to improve performance." % (sig.mpm['pattern'], sig.mpm['buffer'], pattern['count'])
                sig_range = sig.get_diag_range(mode="pattern", pattern=sig.mpm['pattern'])
                diagnostics.append({ "range": sig_range.to_range(), "message": message, "source": "Suricata MPM Analysis", "severity": 4 })
        self.diagnosis = diagnostics
        return sorted(diagnostics, key=self.sort_diagnosis)

    def parse_file(self):
        """Build file Info by parsing file"""
        i = 0
        self.sigset = SignatureSet()
        multi_lines_index = -1
        for content_line in self.contents_split:
            if self.IS_COMMENT.match(content_line):
                i += 1
                continue
            if multi_lines_index >= 0:
                self.sigset.add_content_to_signature(multi_lines_index, i, content_line)
                if self.GET_MULTILINES.search(content_line):
                    i += 1
                    continue
                else:
                    multi_lines_index = -1
                    i += 1
                    continue
            elif self.GET_MULTILINES.search(content_line):
                multi_lines_index = i
                self.sigset.add_signature(i, content_line, multiline=True)
                i += 1
                continue
            else:
                self.sigset.add_signature(i, content_line, multiline=False)
            i += 1

    def apply_change(self, content_update):
        self.contents_split = content_update['text'].splitlines()
        self.nLines = len(self.contents_split)
        self.parse_file()
