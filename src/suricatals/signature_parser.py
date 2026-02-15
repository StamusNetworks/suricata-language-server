"""
Copyright(C) 2021-2026 Stamus Networks SAS
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

import re

from lsprotocol import types
from .signature_tokenizer import SuricataSemanticTokenParser


class DiagnosticBuilder:
    """Helper class to build LSP diagnostics with a convenient interface."""

    # Use Hint (4) for INFO_LEVEL to maintain backward compatibility
    INFO_LEVEL = types.DiagnosticSeverity.Hint
    WARNING_LEVEL = types.DiagnosticSeverity.Warning
    ERROR_LEVEL = types.DiagnosticSeverity.Error

    def __init__(self):
        self.range = None
        self.message = None
        self.severity = types.DiagnosticSeverity.Error
        self.source = "Suricata Language Server"
        self.sid = 0
        self.content = ""

    def to_message(self):
        """Convert to dict for batch mode."""
        if self.range is None or self.message is None:
            return None
        return {
            "range": {
                "start": {
                    "line": self.range.start.line,
                    "character": self.range.start.character,
                },
                "end": {
                    "line": self.range.end.line,
                    "character": self.range.end.character,
                },
            },
            "message": self.message,
            "source": self.source,
            "severity": self.severity.value,
            "content": self.content,
            "sid": self.sid,
        }

    def to_diagnostic(self):
        """Convert to LSP Diagnostic."""
        if self.range is None or self.message is None:
            return None
        return types.Diagnostic(
            range=self.range,
            message=self.message,
            source=self.source,
            severity=self.severity,
        )


class Signature:
    GETSID = re.compile(r"sid *:(\d+)")
    GETREV = re.compile(r"rev *:(\d+)")
    SIG_END = re.compile(r"\) *$")
    SIG_CONTENT = re.compile(r"content *:")

    def __init__(self, line, content, multiline=False):
        self.line = line
        self.line_end = line
        self.multiline = multiline
        if self.multiline:
            self.content = content.strip("\\")
        else:
            self.content = content
        self.raw_content = [content]
        self.multiline = multiline
        self.sid = 0
        self._search_sid(content)
        self.rev = 0
        self._search_rev(content)
        self.mpm = None
        self.has_error = False

    def append_content(self, content, line):
        """Append a continuation line to a multiline signature.

        Args:
            content: Line content to append
            line: Line number in file
        """
        self.content += content.rstrip("\\")
        self.raw_content.append(content)
        self.line_end = line
        if self.sid == 0:
            self._search_sid(content)
        if self.rev == 0:
            self._search_rev(content)

    def _get_diag_range_by_keyword(self, keyword="msg:"):
        fr = None
        i = 0
        for line in self.raw_content:
            if keyword in line:
                line_start = self.line + i
                line_end = line_start
                range_start = line.index(keyword)
                range_end = range_start + len(keyword)
                fr = types.Range(
                    start=types.Position(line=line_start, character=range_start),
                    end=types.Position(line=line_end, character=range_end),
                )
                break
            i += 1
        return fr

    def get_diag_range(self, mode="all", pattern=""):
        """Get LSP Range for diagnostic highlighting.

        Args:
            mode: Range mode - "all" (entire signature), "sid", "msg", or "pattern"
            pattern: Content pattern to highlight when mode="pattern"

        Returns:
            types.Range: LSP Range object for highlighting, or None if not found
        """
        fr = None
        if mode == "all":
            last_char = len(self.raw_content[-1].rstrip())
            fr = types.Range(
                start=types.Position(line=self.line, character=0),
                end=types.Position(line=self.line_end, character=last_char),
            )
        elif mode == "sid":
            fr = self._get_diag_range_by_keyword(keyword="sid:")
        elif mode == "msg":
            fr = self._get_diag_range_by_keyword(keyword="msg:")
            if fr is None:
                fr = self._get_diag_range_by_keyword(keyword="sid:")
        elif mode == "pattern":
            pattern_match = re.compile(f'content: *("{re.escape(pattern)}")')
            i = 0
            found = False
            for line in self.raw_content:
                match = pattern_match.search(line)
                if match:
                    line_start = self.line + i
                    line_end = line_start
                    range_start = match.start()
                    range_end = match.end()
                    fr = types.Range(
                        start=types.Position(line=line_start, character=range_start),
                        end=types.Position(line=line_end, character=range_end),
                    )
                    found = True
                    break
                i += 1
            if found is False:
                fr = self._get_diag_range_by_keyword(keyword="msg:")
        return fr

    def get_content_keyword_count(self):
        """Count the number of content keywords in signature.

        Returns:
            int: Number of content: keywords found
        """
        count = 0
        for line in self.raw_content:
            count += len(self.SIG_CONTENT.findall(line))
        return count

    def sls_syntax_check(self):
        """Perform basic syntax checks on signature.

        Returns:
            list: List of DiagnosticBuilder objects for any issues found
        """
        diagnosis = []
        # check for incomplete signature
        if self.SIG_END.search(self.raw_content[-1]) is None:
            sig_range = self.get_diag_range(mode="all")
            if sig_range:
                end_diag = DiagnosticBuilder()
                end_diag.range = sig_range
                end_diag.message = "Missing closing parenthesis: incomplete signature"
                end_diag.severity = DiagnosticBuilder.WARNING_LEVEL
                end_diag.source = "SLS syntax check"
                end_diag.sid = (self.sid,)
                end_diag.content = self.content
                diagnosis.append(end_diag)
        return diagnosis

    def _search_sid(self, content):
        match = self.GETSID.search(content)
        if match:
            self.sid = int(match.groups()[0])

    def _search_rev(self, content):
        match = self.GETREV.search(content)
        if match:
            self.rev = int(match.groups()[0])

    def __repr__(self):
        return "Signature()"

    def __str__(self):
        return "%d:%s" % (self.sid, self.content)


class SignatureSet:
    def __init__(self):
        self.content_map = {}
        self.line_map = {}
        self.sid_map = {}
        self.signatures = []

    def add_signature(self, line, content, multiline=False):
        """Add a new signature to the set.

        Tracks signature by line, content, and sid. Detects revision conflicts.

        Args:
            line: Line number where signature starts
            content: Signature content (first line if multiline)
            multiline: Whether this is a multiline signature

        Returns:
            Signature: The created signature object
        """
        signature = Signature(line, content, multiline=multiline)
        self.signatures.append(signature)
        self.content_map[content] = signature
        self.line_map[line] = signature
        if signature.sid:
            if signature.sid in self.sid_map:
                if self.sid_map[signature.sid].rev > signature.rev:
                    signature.has_error = True
                elif self.sid_map[signature.sid].rev < signature.rev:
                    self.sid_map[signature.sid].has_error = True
                self.sid_map[signature.sid] = signature
            else:
                self.sid_map[signature.sid] = signature
        return signature

    def add_content_to_signature(self, sig_line, line, content):
        """Append continuation line to existing multiline signature.

        Args:
            sig_line: Line number where signature started
            line: Current line number
            content: Line content to append
        """
        signature = self.get_sig_by_line(sig_line)
        if signature is None:
            return
        signature.append_content(content, line)
        self.content_map[signature.content] = signature
        if signature.sid != 0:
            self.sid_map[signature.sid] = signature

    def get_sig_by_line(self, line):
        """Get signature that starts at given line number.

        Args:
            line: Line number

        Returns:
            Signature: Signature object or None if not found
        """
        return self.line_map.get(line)

    def get_sig_by_content(self, content):
        """Get signature by content string.

        Args:
            content: Signature content to search for

        Returns:
            Signature: Signature object or None if not found
        """
        return self.content_map.get(content)

    def get_sig_by_sid(self, sid):
        """Get signature by signature ID.

        Args:
            sid: Signature ID number

        Returns:
            Signature: Signature object or None if not found
        """
        return self.sid_map.get(sid)


class SuricataFile:
    IS_COMMENT = re.compile(r"[ \t]*#")
    GET_MULTILINES = re.compile(r"\\ *$")

    def __init__(self, path, rules_tester):
        self.path = path
        self.rules_tester = rules_tester
        self.semantic_tokens_parser = SuricataSemanticTokenParser(
            self.rules_tester.get_semantic_token_definitions()
        )
        self.contents_split = []
        self.sigset = SignatureSet()
        self.mpm = {}
        self.diagnosis = None

    def copy(self):
        """Copy content to new file object (does not copy objects)"""
        copy_obj = SuricataFile(self.path, self.rules_tester)
        return copy_obj

    def _load_file(self, contents):
        self.contents_split = contents.splitlines()
        self.parse_file()

    def load_from_disk(self):
        """Read file from disk"""
        try:
            contents = ""
            with open(self.path, "r", encoding="utf-8", errors="replace") as fhandle:
                contents = fhandle.read()
            self._load_file(contents)

        # pylint: disable=W0703
        except Exception:
            return "Could not read/decode file"
        else:
            return None

    def load_from_lsp(self, lsp_file):
        """Load file content from lsp file object"""
        try:
            contents = lsp_file.source
            self._load_file(contents)
        # pylint: disable=W0703
        except Exception:
            return "Could not read/decode file"
        else:
            return None

    def load_from_buffer(self, buffer):
        """Load file content from a string buffer"""
        try:
            self._load_file(buffer)
        # pylint: disable=W0703
        except Exception:
            return "Could not read/decode buffer"
        else:
            return None

    def sort_diagnosis(self, key):
        """Sort key function for diagnostics (by severity, descending).

        Args:
            key: DiagnosticBuilder object

        Returns:
            int: Negative severity for descending sort
        """
        return -key.severity

    def build_errors_diagnostics(self, errors):
        """Convert Suricata errors to LSP diagnostics.

        Args:
            errors: List of error dicts from Suricata

        Returns:
            list: List of DiagnosticBuilder objects
        """
        diagnostics = []
        for error in errors:
            if "line" in error:
                l_diag = DiagnosticBuilder()
                l_diag.message = error["message"]
                l_diag.source = error["source"]
                l_diag.severity = DiagnosticBuilder.ERROR_LEVEL
                signature = self.sigset.get_sig_by_line(error["line"])
                if signature:
                    signature.has_error = True
                    sig_range = signature.get_diag_range(mode="all")
                    l_diag.range = sig_range
                    l_diag.content = signature.content
                    l_diag.sid = signature.sid
                else:
                    e_range = types.Range(
                        start=types.Position(line=error["line"], character=0),
                        end=types.Position(line=error["line"], character=1000),
                    )
                    l_diag.range = e_range
                    l_diag.content = error.get("content", "")
                    l_diag.sid = error.get("sid", "UNKNOWN")

                diagnostics.append(l_diag)
        return diagnostics

    def build_warnings_diagnostics(self, warnings):
        """Convert Suricata warnings to LSP diagnostics.

        Args:
            warnings: List of warning dicts from Suricata

        Returns:
            list: List of DiagnosticBuilder objects
        """
        diagnostics = []
        for warning in warnings:
            line = None
            signature = None
            l_diag = DiagnosticBuilder()
            l_diag.message = warning["message"]
            l_diag.source = warning["source"]
            l_diag.severity = DiagnosticBuilder.WARNING_LEVEL
            if "line" in warning:
                line = warning["line"]
                signature = self.sigset.get_sig_by_line(line)
            elif "content" in warning:
                signature = self.sigset.get_sig_by_content(warning["content"])
                if signature is not None:
                    line = signature.line
            elif "sid" in warning:
                signature = self.sigset.get_sig_by_sid(warning["sid"])
                if signature is not None:
                    line = signature.line
            if line is None:
                continue
            if signature is not None:
                l_diag.range = signature.get_diag_range(mode="msg")
                if warning.get("suricata_error", False):
                    signature.has_error = True

                l_diag.content = signature.content
                l_diag.sid = signature.sid
            else:
                w_range = types.Range(
                    start=types.Position(line=line, character=0),
                    end=types.Position(line=line, character=1000),
                )
                l_diag.range = w_range
                l_diag.content = warning.get("content", "")
                l_diag.sid = warning.get("sid", "UNKNOWN")

            diagnostics.append(l_diag)
        return diagnostics

    def build_engine_diagnostics(self, engine_results, workspace):
        diagnostics = []
        for info in engine_results:
            line = None
            signature = None
            l_diag = DiagnosticBuilder()
            l_diag.message = info["message"]
            l_diag.source = info["source"]
            l_diag.severity = DiagnosticBuilder.INFO_LEVEL
            if "line" in info:
                line = info["line"]
            elif "content" in info:
                signature = self.sigset.get_sig_by_content(info["content"])
                if signature:
                    line = signature.line
            if line is None:
                continue
            sig_range = types.Range(
                start=types.Position(line=line, character=0),
                end=types.Position(line=line, character=1),
            )
            if signature is not None:
                if 'Fast Pattern "' in info["message"]:
                    if signature.mpm is not None:
                        sig_range = signature.get_diag_range(
                            mode="pattern", pattern=signature.mpm["pattern"]
                        )
                    else:
                        sig_range = signature.get_diag_range(mode="msg")
                else:
                    sig_range = signature.get_diag_range(mode="msg")

                l_diag.content = signature.content
                l_diag.sid = signature.sid
            else:
                l_diag.content = info.get("content", "")
                l_diag.sid = info.get("sid", "UNKNOWN")

            l_diag.range = sig_range
            diagnostics.append(l_diag)
        for sig in self.sigset.signatures:
            if sig.mpm is None:
                if sig.sid and sig.has_error is False:
                    message = "No Fast Pattern used, if possible add one content match to improve performance."
                    l_diag = DiagnosticBuilder()
                    l_diag.message = message
                    l_diag.source = "Suricata MPM Analysis"
                    l_diag.severity = DiagnosticBuilder.INFO_LEVEL
                    l_diag.range = sig.get_diag_range(mode="msg")
                    l_diag.sid = sig.sid
                    l_diag.content = sig.content
                    diagnostics.append(l_diag)
                continue
            # mpm is content:"$pattern"
            pattern = self.mpm.get(sig.mpm["buffer"], {}).get(sig.mpm["pattern"])
            if pattern is None:
                continue
            pattern_count = pattern["count"]
            # Check workspace_mpm for pattern usage across files
            if workspace:
                for sig_file in workspace:
                    if sig_file != self.path:
                        file_mpm_data = workspace.get(sig_file)
                        if file_mpm_data is None:
                            continue
                        # Access the buffer data from workspace_mpm structure
                        # workspace_mpm[filepath] = {"buffer": {...}, "sids": {...}}
                        if isinstance(file_mpm_data, dict):
                            file_mpm = file_mpm_data.get("buffer")
                        else:
                            # Support old format where file_obj.mpm was passed
                            file_mpm = getattr(file_mpm_data, "mpm", None)

                        if file_mpm is None:
                            continue
                        f_pattern = file_mpm.get(sig.mpm["buffer"], {}).get(
                            sig.mpm["pattern"]
                        )
                        if f_pattern is None:
                            continue
                        pattern_count += f_pattern["count"]
            l_diag = DiagnosticBuilder()
            if pattern_count > 1:
                l_diag.message = (
                    "Fast Pattern '%s' on '%s' buffer is used in %d different signatures, "
                    "consider using a unique fast pattern to improve performance."
                    % (sig.mpm["pattern"], sig.mpm["buffer"], pattern_count)
                )
                l_diag.source = "SLS MPM Analysis"
            else:
                if sig.get_content_keyword_count() == 1:
                    continue
                l_diag.message = "Fast Pattern '%s' on '%s' buffer" % (
                    sig.mpm["pattern"],
                    sig.mpm["buffer"],
                )
                l_diag.source = "Suricata MPM Analysis"
            sig_range = sig.get_diag_range(mode="pattern", pattern=sig.mpm["pattern"])
            l_diag.severity = DiagnosticBuilder.INFO_LEVEL
            l_diag.range = sig.get_diag_range(
                mode="pattern", pattern=sig.mpm["pattern"]
            )
            l_diag.sid = sig.sid
            l_diag.content = sig.content
            diagnostics.append(l_diag)
        return diagnostics

    def build_pcap_diagnostics(self, pcap_results):
        diagnostics = []
        for sid, count in pcap_results.items():
            l_diag = DiagnosticBuilder()
            l_diag.message = f"Alerts: {count}"
            l_diag.source = "Suricata Pcap Analysis"
            l_diag.severity = DiagnosticBuilder.INFO_LEVEL
            signature = self.sigset.get_sig_by_sid(sid)
            if signature:
                sig_range = signature.get_diag_range(mode="msg")
                l_diag.range = sig_range
                l_diag.content = signature.content
                l_diag.sid = signature.sid
                diagnostics.append(l_diag)

        return diagnostics

    def build_profiling_diagnostics(self, profiling_results):
        diagnostics = []
        for res in profiling_results:
            l_diag = DiagnosticBuilder()
            l_diag.message = f"Checks: {res['checks']}. Ticks: total {res['ticks_total']}, max {res['ticks_max']}, avg {res['ticks_avg']}"
            l_diag.source = "Suricata Pcap Profiling"
            l_diag.severity = DiagnosticBuilder.INFO_LEVEL
            signature = self.sigset.get_sig_by_sid(res["signature_id"])
            if signature:
                sig_range = signature.get_diag_range(mode="msg")
                l_diag.range = sig_range
                l_diag.content = signature.content
                l_diag.sid = signature.sid
                diagnostics.append(l_diag)
        return diagnostics

    def build_sid_conflict_diagnostics(self, sid_conflicts):
        """Build diagnostics for SID conflicts across workspace files.

        Args:
            sid_conflicts: Dict mapping SID -> list of filepaths where it appears

        Returns:
            List of DiagnosticBuilder objects for conflicting SIDs
        """
        diagnostics = []
        for sid, filepaths in sid_conflicts.items():
            signature = self.sigset.get_sig_by_sid(sid)
            if signature:
                l_diag = DiagnosticBuilder()
                # Format file list for display
                file_list = ", ".join([fp.split("/")[-1] for fp in filepaths[:3]])
                if len(filepaths) > 3:
                    file_list += f" and {len(filepaths) - 3} more"

                l_diag.message = (
                    f"SID {sid} conflicts with signature(s) in: {file_list}"
                )
                l_diag.source = "Suricata Language Server"
                l_diag.severity = DiagnosticBuilder.WARNING_LEVEL
                sig_range = signature.get_diag_range(mode="sid")
                l_diag.range = sig_range
                l_diag.content = signature.content
                l_diag.sid = signature.sid
                diagnostics.append(l_diag)

        return diagnostics

    def _compute_sid_conflicts(self, workspace):
        """Compute SID conflicts between current file and workspace files.

        Args:
            workspace: Dict from MpmCache.get_workspace_view() with structure:
                       {filepath: {"buffer": {...}, "sids": {sid: mpm_info, ...}}, ...}

        Returns:
            Dict mapping conflicting SID -> list of filepaths where it appears
        """
        conflicts = {}

        # Build a map of current file's SIDs
        current_sids = {sig.sid for sig in self.sigset.signatures if sig.sid != 0}

        # Check each workspace file for SID conflicts
        for filepath, file_data in workspace.items():
            workspace_sids = file_data.get("sids", {})
            for sid in workspace_sids.keys():
                if sid in current_sids:
                    if sid not in conflicts:
                        conflicts[sid] = []
                    conflicts[sid].append(filepath)

        return conflicts

    def build_all_diags(self, result, workspace=None, engine_analysis=True):
        diagnostics = []
        self.mpm = result.get("mpm", {}).get("buffer")
        for sid in result.get("mpm", {}).get("sids", []):
            signature = self.sigset.get_sig_by_sid(sid)
            if signature is not None:
                signature.mpm = result.get("mpm", {}).get("sids", {}).get(sid)
        errors = self.build_errors_diagnostics(result.get("errors", []))
        diagnostics.extend(errors)
        warnings = self.build_warnings_diagnostics(result.get("warnings", []))
        diagnostics.extend(warnings)

        if engine_analysis:
            analysis_diags = self.build_engine_diagnostics(
                result.get("info", {}), workspace
            )
            diagnostics.extend(analysis_diags)
        for sig in self.sigset.signatures:
            sls_diag = sig.sls_syntax_check()
            if len(sls_diag):
                diagnostics.extend(sls_diag)
        # let's check for match in the pcap if exists
        if "matches" in result:
            matches = self.build_pcap_diagnostics(result["matches"])
            diagnostics.extend(matches)
        # let's check for profiling in the pcap if exists
        if "profiling" in result:
            profiling = self.build_profiling_diagnostics(result.get("profiling", {}))
            diagnostics.extend(profiling)

        # Check for SID conflicts across workspace files
        if workspace:
            sid_conflicts = self._compute_sid_conflicts(workspace)
            if sid_conflicts:
                conflict_diags = self.build_sid_conflict_diagnostics(sid_conflicts)
                diagnostics.extend(conflict_diags)

        self.diagnosis = diagnostics
        return result["status"], sorted(diagnostics, key=self.sort_diagnosis)

    def check_lsp_file(self, lsp_file, workspace=None, engine_analysis=True, **kwargs):
        """Check LSP file object using Suricata and return diagnostics.

        Args:
            lsp_file: LSP file object with source attribute
            workspace: Optional workspace context for MPM analysis
            engine_analysis: Whether to run engine analysis (default: True)
            **kwargs: Additional options passed to rules_tester

        Returns:
            tuple: (status, diagnostics) where status is bool and diagnostics is list
        """
        result = {}
        if not workspace:
            workspace = {}
        kwargs["file_path"] = self.path
        buffer = lsp_file.source
        result = self.rules_tester.check_rule_buffer(buffer, engine_analysis, **kwargs)
        return self.build_all_diags(
            result, workspace=workspace, engine_analysis=engine_analysis
        )

    def check_file(self, workspace=None, engine_analysis=True, **kwargs):
        """Check file from disk using Suricata and return diagnostics.

        Args:
            workspace: Optional workspace context for MPM analysis
            engine_analysis: Whether to run engine analysis (default: True)
            **kwargs: Additional options passed to rules_tester

        Returns:
            tuple: (status, diagnostics) where status is bool and diagnostics is list
        """
        result = {}
        if not workspace:
            workspace = {}
        with open(self.path, "r", encoding="utf-8", errors="replace") as fhandle:
            kwargs["file_path"] = self.path
            result = self.rules_tester.check_rule_buffer(
                fhandle.read(), engine_analysis, **kwargs
            )
        return self.build_all_diags(
            result, workspace=workspace, engine_analysis=engine_analysis
        )

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
                if len(content_line) > 0 and not content_line.isspace():
                    self.sigset.add_signature(i, content_line, multiline=False)
            i += 1

    def extract_range(self, file_range):
        """Extract text content from file within given LSP range.

        Args:
            file_range: LSP Range object with start and end positions

        Returns:
            str: Extracted text content
        """
        lines = self.contents_split

        start = file_range.start
        end = file_range.end

        s_line, s_char = start.line, start.character
        e_line, e_char = end.line, end.character
        # handle range with an empty line at the end
        if e_char == 0:
            e_line -= 1
            e_char = len(lines[e_line])
        # Case 1: Range is on a single line
        if s_line == e_line:
            return lines[s_line][s_char:e_char]
        # Case 2: Range spans multiple lines
        # Part A: Suffix of the first line
        result = [lines[s_line][s_char:]]
        # Part B: All full lines in between
        result.extend(lines[s_line + 1 : e_line])
        # Part C: Prefix of the last line
        result.append(lines[e_line][:e_char])
        # Join with newline
        return "\n".join(result)

    def get_semantic_tokens(self, file_range=None):
        """Generate semantic tokens for the file"""
        if file_range is None:
            content = "\n".join(self.contents_split)
        else:
            content = self.extract_range(file_range)
        data = self.semantic_tokens_parser.parse(content)
        return data
