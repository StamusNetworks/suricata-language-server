"""
Copyright(C) 2026 Stamus Networks SAS
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

from json.decoder import JSONDecodeError
import io
import json
import re
from lsprotocol import types


class SuricataFileException(Exception):
    """Exception raised for Suricata file processing errors."""

    def __init__(self, message, line_number=None):
        """Initialize exception with message and optional line number.

        Args:
            message: Error message describing the problem
            line_number: Optional line number where error occurred
        """
        super().__init__(message)
        self.line_number = line_number

    def get_diagnosis(self):
        """Convert exception to LSP Diagnostic object.

        Returns:
            types.Diagnostic: LSP diagnostic with error severity
        """
        return types.Diagnostic(
            range=types.Range(
                start=types.Position(line=self.line_number, character=0),
                end=types.Position(line=self.line_number, character=1000),
            ),
            message=str(self),
            severity=types.DiagnosticSeverity.Error,
            source="Suricata Language Server",
        )


class SuricataErrorParser:
    """Parser for Suricata error and warning output."""

    VARIABLE_ERROR = 101
    OPENING_RULE_FILE = 41  # Error when opening a file referenced in the source
    OPENING_DATASET_FILE = 322  # Error when opening a dataset referenced in the source
    USELESS_ERRNO = [40, 43, 44]
    SURICATA_SYNTAX_CHECK = "Suricata Syntax Check"

    def __init__(self, suricata_version, suricata_config=None):
        """Initialize error parser with Suricata version.

        Args:
            suricata_version: Version string (e.g., "7.0.0")
            suricata_config: Optional config path (used for variable error handling)
        """
        self.suricata_version = suricata_version
        self.suricata_config = suricata_config

    def parse_error(self, error):
        """Parse Suricata error output based on version.

        Args:
            error: Error output string from Suricata

        Returns:
            Dict with 'errors' and 'warnings' lists
        """
        major, _, _ = self.suricata_version.split(".")
        if int(major) < 7:
            return self._parse_error_before_7(error)
        else:
            return self._parse_error_after_7(error)

    def _parse_error_after_7(self, error):
        """Parse Suricata 7.x+ JSON error format."""
        ret = {
            "errors": [],
            "warnings": [],
        }
        error_stream = io.StringIO(error)
        wait_line = False
        prev_err = {}
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except JSONDecodeError:
                continue
            if s_err["event_type"] != "engine":
                continue
            s_err["engine"]["source"] = self.SURICATA_SYNTAX_CHECK

            if not s_err["engine"]["module"].startswith("detect") and s_err["engine"][
                "module"
            ] not in ["rule-vars"]:
                continue

            if re.search(
                'Variable "(.+)" is not defined in configuration file',
                s_err["engine"].get("message", ""),
            ):
                s_err["engine"]["variable_error"] = True

            if s_err["engine"]["module"] == "detect-parse":
                if s_err["log_level"] == "Error":
                    ret["errors"].append(s_err["engine"])
                    wait_line = True
                else:
                    ret["warnings"].append(s_err["engine"])
                    getsid = re.compile(r"sid *:(\d+)")
                    match = getsid.search(line)
                    if match:
                        s_err["engine"]["sid"] = int(match.groups()[0])
            elif s_err["engine"]["module"] == "detect-dataset":
                if not wait_line:
                    if s_err["engine"]["message"].startswith("bad type"):
                        s_err["engine"]["message"] = (
                            "dataset: " + s_err["engine"]["message"]
                        )
                    ret["errors"].append(s_err["engine"])
                    wait_line = True
            elif s_err["engine"]["module"] == "rules-vars":
                ret["errors"].append(s_err["engine"])
            elif s_err["engine"]["module"] == "detect-http-host":
                if s_err["log_level"] == "Error":
                    ret["errors"].append(s_err["engine"])
                else:
                    # Warning is escalated as error if match
                    getsid = re.compile(r"rule (\d+)\:")
                    match = getsid.search(line)
                    if match:
                        s_err["engine"]["sid"] = int(match.groups()[0])
                        wait_line = True
                    else:
                        ret["warnings"].append(s_err["engine"])
            elif s_err["engine"]["module"] == "detect":
                if "error parsing signature" in s_err["engine"]["message"]:
                    message = s_err["engine"]["message"]
                    s_err["engine"]["message"] = s_err["engine"]["message"].split(
                        " from file"
                    )[0]
                    getsid = re.compile(r"sid *:(\d+)")
                    match = getsid.search(line)
                    if match:
                        s_err["engine"]["sid"] = int(match.groups()[0])
                    getline = re.compile(r"at line (\d+)$")
                    match = getline.search(message)
                    if match:
                        line_nb = int(match.groups()[0])
                        if wait_line:
                            if prev_err != {}:
                                prev_err["engine"]["line"] = line_nb - 1
                                if prev_err["engine"] not in ret["errors"]:
                                    ret["errors"].append(prev_err["engine"])
                        else:
                            if prev_err != {} and prev_err["log_level"] == "Warning":
                                prev_err["engine"]["line"] = line_nb - 1
                                ret["errors"].append(prev_err["engine"])
                            else:
                                s_err["engine"]["line"] = line_nb - 1
                                ret["errors"].append(s_err["engine"])
                    wait_line = False
                else:
                    ret["errors"].append(s_err["engine"])
                    wait_line = True
            else:
                if not wait_line:
                    if s_err["log_level"] == "Error":
                        ret["errors"].append(s_err["engine"])
                        wait_line = True
            prev_err = s_err
        return ret

    def _parse_error_before_7(self, error):  # pragma: no cover
        """Parse Suricata 6.x JSON error format."""
        ret = {
            "errors": [],
            "warnings": [],
        }
        files_list = []
        ignore_next = False
        error_stream = io.StringIO(error)
        error_type = "errors"
        prev_err = None
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except JSONDecodeError:
                continue
            s_err["engine"]["source"] = self.SURICATA_SYNTAX_CHECK
            errno = s_err["engine"]["error_code"]
            if s_err.get("log_level", "") != "Error":
                if errno not in [176, 242, 308]:
                    prev_err = s_err["engine"]
                    continue
            if errno == self.VARIABLE_ERROR:
                s_err["engine"]["suricata_error"] = True
                s_err["engine"]["variable_error"] = True

                # suricata config is set when we should have all variables defined
                if self.suricata_config is None:
                    error_type = "warnings"
                    s_err["engine"]["warning"] = s_err["engine"].pop("error", "")
                ret[error_type].append(s_err["engine"])
                continue
            elif errno == self.OPENING_DATASET_FILE:
                m = re.match(
                    "fopen '([^:]*)' failed: No such file or directory",
                    s_err["engine"]["message"],
                )
                if m is not None:
                    datasource = m.group(1)
                    s_err["engine"]["message"] = (
                        'Dataset source "%s" is a dependency " \
                        "and needs to be added to rulesets'
                        % datasource
                    )
                    s_err["engine"]["suricata_error"] = True
                    error_type = "warnings"
                    ret[error_type].append(s_err["engine"])
                    ignore_next = True
                    continue
            elif errno == self.OPENING_RULE_FILE:
                m = re.match(
                    "opening hash file ([^:]*): No such file or directory",
                    s_err["engine"]["message"],
                )
                if m is not None:
                    filename = m.group(1)
                    filename = filename.rsplit("/", 1)[1]
                    files_list.append(filename)
                    s_err["engine"]["message"] = (
                        'External file "%s" is a dependency '
                        "and needs to be added to rulesets" % filename
                    )
                    s_err["engine"]["suricata_error"] = True
                    error_type = "warnings"
                    ret[error_type].append(s_err["engine"])
                    continue
            elif errno == 176:
                warning, sig_content = s_err["engine"]["message"].split('"', 1)
                ret["warnings"].append(
                    {
                        "message": warning.rstrip(),
                        "source": self.SURICATA_SYNTAX_CHECK,
                        "content": sig_content.rstrip('"'),
                    }
                )
            # Message for invalid signature
            elif errno == 276:
                rule, warning = s_err["engine"]["message"].split(": ", 1)
                rule = int(rule.split(" ")[1])
                ret["warnings"].append(
                    {
                        "message": warning.rstrip(),
                        "source": self.SURICATA_SYNTAX_CHECK,
                        "sid": rule,
                    }
                )
            elif errno not in self.USELESS_ERRNO:
                # clean error message
                if errno == 39:
                    if "failed to set up dataset" in s_err["engine"]["message"]:
                        if ignore_next:
                            continue
                    if ignore_next:
                        ignore_next = False
                        continue
                    if "error parsing signature" in s_err["engine"]["message"]:
                        message = s_err["engine"]["message"]
                        s_err["engine"]["message"] = s_err["engine"]["message"].split(
                            " from file"
                        )[0]
                        getsid = re.compile(r"sid *:(\d+)")
                        match = getsid.search(line)
                        if match:
                            s_err["engine"]["sid"] = int(match.groups()[0])
                        getline = re.compile(r"at line (\d+)$")
                        match = getline.search(message)
                        if match:
                            line_nb = int(match.groups()[0])
                            if prev_err is not None:
                                prev_err["line"] = line_nb - 1
                                ret["errors"].append(prev_err)
                                prev_err = None
                            else:
                                if len(ret[error_type]):
                                    ret[error_type][-1]["line"] = line_nb - 1
                                error_type = "errors"
                            continue
                if errno == 42:
                    s_err["engine"]["message"] = s_err["engine"]["message"].split(
                        " from"
                    )[0]
                ret["errors"].append(s_err["engine"])
        return ret
