import hashlib

import re


class Signature:
    GETSID = re.compile(r"sid *:(\d+)")
    def __init__(self, line, content, multiline = False):
        self.line = line
        self.content = content
        self.multiline = multiline
        self.sid = 0
        self._search_sid(content)
        self.mpm = None

    def append_content(self, content):
        self.content += content
        if self.sid == 0:
            self._search_sid(content)

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
        if multiline:
            content = content.rstrip('\\')
        signature = Signature(line, content, multiline = multiline)
        self.signatures.append(signature)
        self.content_map[content] = signature
        self.line_map[line] = signature
        if signature.sid:
            self.sid_map[signature.sid] = signature
        return signature

    def add_content_to_signature(self, line, content):
        signature = self.get_sig_by_line(line)
        if signature is None:
            return
        signature.append_content(content.rstrip('\\'))
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
                    line_content = signature.content
                    if line_content:
                        range_end = len(line_content.rstrip())
                diagnostics.append({ "range": { "start": {"line": error['line'], "character": 0}, "end": {"line": error['line'], "character": range_end} }, "message": error['message'], "source": error['source'], "severity": 1 })
        for warning in result.get('warnings', []):
            line = None
            range_start = 0
            range_end = 1000
            if 'line' in warning:
                line = warning['line']
            elif 'content' in warning:
                signature = self.sigset.get_sig_by_content(warning['content'])
                if signature is not None:
                    line = signature.line
                    range_start = warning['content'].index('sid:')
                    range_end = range_start + len('sid:')
            elif 'sid' in warning:
                signature = self.sigset.get_sig_by_sid(warning['sid'])
                if signature is not None:
                    line = signature.line
            if line is None:
                continue
            diagnostics.append({ "range": { "start": {"line": line, "character": range_start}, "end": {"line": line, "character": range_end} }, "message": warning['message'], "source": warning['source'], "severity": 2 })
        for info in result.get('info', []):
            line = None
            if 'line' in info:
                line = info['line']
            elif 'content' in info:
                signature = self.sigset.get_sig_by_content(info['content'])
                if signature:
                    line = signature.line
            if line is None:
                continue
            start_char = info.get('start_char', 0)
            end_char = info.get('end_char', 0)
            diagnostics.append({ "range": { "start": {"line": line, "character": start_char}, "end": {"line": line, "character": end_char} }, "message": info['message'], "source": info['source'], "severity": 4 })
        for sig in self.sigset.signatures:
            if sig.mpm is None:
                range_start = 0 
                range_end = 1000
                message = "No Fast pattern used, consider adding one to improve performance if possible."
                diagnostics.append({ "range": { "start": {"line": sig.line, "character": range_start}, "end": {"line": sig.line, "character": range_end} }, "message": message, "source": "Suricata MPM Analysis", "severity": 4 })
                continue
            # mpm is content:"$pattern"
            pattern = self.mpm.get(sig.mpm['buffer'], {}).get(sig.mpm['pattern'])
            if pattern is None:
                continue
            if pattern['count'] > 1:
                range_start = 0 
                range_end = 1000
                message = "Fast pattern '%s' on '%s' buffer is used in %d different signatures, consider using a unique fast pattern to improve performance." % (sig.mpm['pattern'], sig.mpm['buffer'], pattern['count'])
                diagnostics.append({ "range": { "start": {"line": sig.line, "character": range_start}, "end": {"line": sig.line, "character": range_end} }, "message": message, "source": "Suricata MPM Analysis", "severity": 4 })
        self.diagnosis = diagnostics
        return diagnostics

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
                self.sigset.add_content_to_signature(multi_lines_index, content_line)
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
