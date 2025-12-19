"""
Copyright(C) 2018-2025 Stamus Networks
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
import shutil
import os
import json
import io
import re
import logging
import importlib.resources
import shlex
from suricatals.suri_cmd import SuriCmd
from suricatals.lsp_helpers import Diagnosis, FileRange
from typing import Dict, Any

log = logging.getLogger(__name__)


class SuricataFileException(Exception):
    def __init__(self, message, line_number=None):
        super().__init__(message)
        self.line_number = line_number

    def get_diagnosis(self):
        diagnosis = Diagnosis()
        diagnosis.message = str(self)
        diagnosis.severity = Diagnosis.ERROR_LEVEL
        diagnosis.source = "Suricata Language Server"
        diagnosis.range = FileRange(self.line_number, 0, self.line_number, 1000)
        return diagnosis


class TestRules:
    VARIABLE_ERROR = 101
    OPENING_RULE_FILE = 41  # Error when opening a file referenced in the source
    OPENING_DATASET_FILE = 322  # Error when opening a dataset referenced in the source
    USELESS_ERRNO = [40, 43, 44]
    SURICATA_SYNTAX_CHECK = "Suricata Syntax Check"
    SURICATA_ENGINE_ANALYSIS = "Suricata Engine Analysis"
    ACTIONS_ITEMS = [
        {
            "label": "alert",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert",
        },
        {
            "label": "config",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Configuration signature. Used mostly for conditional logging.",
        },
        {
            "label": "drop",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert and drop flow",
        },
        {
            "label": "pass",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Stop inspecting the data",
        },
        {
            "label": "reject",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert and reset session",
        },
        {
            "label": "rejectsrc",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert and reset session for source IP",
        },
        {
            "label": "rejectdst",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert and reset session for destination IP",
        },
        {
            "label": "rejectboth",
            "kind": 14,
            "detail": "Alert action",
            "documentation": "Trigger alert and reset session for both IPs",
        },
    ]

    def __init__(
        self,
        suricata_binary="suricata",
        suricata_config=None,
        docker=False,
        docker_image=SuriCmd.SLS_DEFAULT_DOCKER_IMAGE,
    ) -> None:
        self.suricata_binary = suricata_binary
        self.suricata_config = suricata_config
        self.docker = docker
        self.docker_image = docker_image
        self.create_suricmd()
        self.suricata_version = self.get_suricata_version()

    def create_suricmd(self):
        self.suricmd = SuriCmd(self.suricata_binary, self.suricata_config)
        if self.docker:
            self.suricmd.set_docker_mode(docker_image=self.docker_image)

    def __getstate__(self):
        # Create a copy of the instance's dictionary
        state = self.__dict__.copy()
        # Remove the unpicklable field before pickling
        del state["suricmd"]
        return state

    def __setstate__(self, state):
        # Restore the attributes from the pickled state
        self.__dict__.update(state)
        self.create_suricmd()

    def get_suricata_version(self):
        outdata = self.suricmd.get_version()
        if outdata is None:
            return "6.0.0"
        for line in outdata.splitlines():
            if line.startswith("This is Suricata version"):
                outdata = line
                break
        mm = re.match(r"This is Suricata version (\d+\.\d+\.\d+)", outdata)
        if mm is not None:
            return mm.group(1)
        return "6.0.0"

    def json_compat_version(self):
        (major, minor, fix) = self.suricata_version.split(".")
        if int(major) < 6:
            return True
        elif int(major) == 6 and int(minor) == 0 and int(fix) < 4:
            return False
        return True

    def parse_suricata_error_after_7(self, error):
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

    # pylint: disable=W0613
    def parse_suricata_error_before_7(self, error):
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

    def parse_suricata_error(self, error):
        (major, _, _) = self.suricata_version.split(".")
        if int(major) < 7:
            return self.parse_suricata_error_before_7(error)
        else:
            return self.parse_suricata_error_after_7(error)

    def _prepare_conf(self, rule_buffer, tmpdir, **kwargs):
        # write the rule file in temp dir
        rule_file = os.path.join(tmpdir, "file.rules")
        with open(rule_file, "w", encoding="utf-8") as rf:
            rf.write(rule_buffer)

        if kwargs.get("extra_buffers"):
            for filename, content in kwargs["extra_buffers"].items():
                full_path = os.path.join(tmpdir, filename)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(content)

        return self.suricmd.generate_config(
            tmpdir,
            config_buffer=kwargs.get("config_buffer"),
            related_files=kwargs.get("related_files"),
            reference_config=kwargs.get("reference_config"),
            classification_config=kwargs.get("classification_config"),
            extra_conf=kwargs.get("extra_conf"),
        )

    def _sanitize_file(self, filepath):
        # check if the file path is absolute or use .. construct and return
        # an error if it is the case
        if os.path.isabs(filepath):
            raise ValueError("Absolute file paths are not allowed")
        if ".." in filepath.split(os.path.sep):
            raise ValueError("Parent directory references are not allowed")

    def _rules_buffer_get_suricata_options(self, rule_buffer) -> Dict[str, Any]:
        regexp = {
            "options": re.compile(r"^##\s*SLS\s+suricata-options:\s*(\S.*)$"),
            "replace": re.compile(r"^##\s*SLS\s+replace:\s*(\S.*)$"),
            "dataset-dir": re.compile(r"^##\s*SLS\s+dataset-dir:\s*(\S.*)$"),
            "version": re.compile(r"^##\s*SLS\s+suricata-version:\s*(\S.*)$"),
            "pcap": re.compile(r"^##\s*SLS\s+pcap-file:\s*(\S.*)$"),
        }
        result = {"options": [], "replace": [], "dataset-dir": None, "version": None}
        for line_number, line in enumerate(rule_buffer.splitlines(), start=0):
            match = regexp["options"].match(line)
            if match:
                result["options"] = shlex.split(match.group(1))
            match = regexp["replace"].match(line)
            if match:
                result["replace"] = shlex.split(match.group(1))
            match = regexp["dataset-dir"].match(line)
            if match:
                result["dataset-dir"] = match.group(1)
            match = regexp["version"].match(line)
            if match:
                result["version"] = match.group(1)
            match = regexp["pcap"].match(line)
            if match:
                pcap_file = match.group(1)
                try:
                    self._sanitize_file(pcap_file)
                    result["pcap"] = pcap_file
                    result["pcap_line"] = line_number
                except ValueError as exc:
                    log.warning("Invalid pcap file path in rule buffer: %s", pcap_file)
                    raise SuricataFileException(
                        "Only relative pcap file path are allowed in rule buffer",
                        line_number=line_number,
                    ) from exc
        return result

    def _rules_buffer_prepare_dataset(self, rule_buffer, tmpdir):
        # check that we have a dataset keyword and create the load/save file in tmpdir after transformation
        # if we have a file with same basename as the dataset then we copy it to tmp dir with correct name
        # if no file, we create a dummy file with the same name
        dataset_match = r"dataset:.*, *(load|save|state) +(\S+);"
        dm_re = re.compile(dataset_match)
        for line in rule_buffer.splitlines():
            match = dm_re.search(line)
            if match:
                operation = match.group(1)
                dataset = match.group(2)
                # if we save to file, we don't need to create a dummy file
                if operation == "save":
                    continue
                else:
                    base_file = dataset.split("_")[-1]
                    if os.path.exists(base_file):
                        shutil.copyfile(base_file, os.path.join(tmpdir, dataset))
                    else:
                        with open(
                            os.path.join(tmpdir, dataset), "w", encoding="utf-8"
                        ) as f:
                            f.write("")

    def rules_infos(self, rule_buffer, **kwargs):
        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()
        if tmpdir is None:
            raise IOError("Unable to get temporary directory for Suricata execution")

        try:
            options = self._rules_buffer_get_suricata_options(rule_buffer)
        except SuricataFileException as e:
            self.suricmd.cleanup()
            raise e

        if options.get("dataset-dir"):
            undir = re.sub(r"/", "_", options["dataset-dir"])
            rule_buffer = rule_buffer.replace(options["dataset-dir"], undir)

        if self.docker and options.get("version"):
            self.suricmd.set_docker_version_for_run(image_version=options["version"])

        self._rules_buffer_prepare_dataset(rule_buffer, tmpdir)

        replace = options.get("replace")
        if replace and len(replace) == 2:
            rule_buffer = re.sub(replace[0], replace[1], rule_buffer)

        suri_cmd = [
            "--engine-analysis",
        ]

        suri_options = options.get("options")
        if suri_options:
            suri_cmd += suri_options

        self.suricmd.run(suri_cmd)

        res = {}
        json_path = os.path.join(tmpdir, "rules.json")
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                for line in f.readlines():
                    content = json.loads(line)
                    res[content["id"]] = content

        self.suricmd.cleanup()
        return res

    def rule_buffer(
        self,
        rule_buffer,
        engine_analysis=True,
        config_buffer=None,
        related_files=None,
        reference_config=None,
        classification_config=None,
        extra_buffers=None,
        **kwargs,
    ):

        try:
            options = self._rules_buffer_get_suricata_options(rule_buffer)
        except SuricataFileException as e:
            self.suricmd.cleanup()
            raise e

        suri_options = options.get("options")
        if options.get("dataset-dir"):
            undir = re.sub(r"/", "_", options["dataset-dir"])
            rule_buffer = re.sub(options["dataset-dir"], undir, rule_buffer)
        replace = options.get("replace")
        if replace and len(replace) == 2:
            rule_buffer = re.sub(replace[0], replace[1], rule_buffer)
        if self.docker and options.get("version"):
            self.suricmd.set_docker_version_for_run(image_version=options["version"])

        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()

        self._rules_buffer_prepare_dataset(rule_buffer, tmpdir)

        self._prepare_conf(
            rule_buffer,
            tmpdir,
            config_buffer=config_buffer,
            related_files=related_files,
            reference_config=reference_config,
            classification_config=classification_config,
            extra_buffers=extra_buffers,
            **kwargs,
        )

        suri_cmd = [
            "-T",
        ]

        if suri_options:
            suri_cmd += suri_options

        outdata = self.suricmd.run(suri_cmd)
        result = {"status": True, "errors": "", "warnings": [], "info": []}
        # if not a success
        if self.suricmd.returncode == False:
            result["status"] = False
        result["errors"] = outdata

        if engine_analysis:
            # runs rules analysis to have warnings
            suri_cmd = [
                "--engine-analysis",
            ]

            if suri_options:
                suri_cmd += suri_options

            run_error = self.suricmd.run(suri_cmd)
            if self.suricmd.returncode == False:
                self.suricmd.cleanup()
                raise SuricataFileException(
                    f"Error during Suricata engine analysis run: {run_error}", 0
                )

            engine_analysis = self.parse_engine_analysis(tmpdir)
            for signature in engine_analysis:
                for warning in signature.get("warnings", []):
                    result["warnings"].append(
                        {
                            "message": warning,
                            "source": self.SURICATA_ENGINE_ANALYSIS,
                            "sid": signature.get("sid", "UNKNOWN"),
                            "content": signature["content"],
                        }
                    )

                for info in signature.get("info", []):
                    result["info"].append(
                        {
                            "message": info,
                            "source": self.SURICATA_ENGINE_ANALYSIS,
                            "content": signature["content"],
                            "sid": signature.get("sid", "UNKNOWN"),
                        }
                    )

            mpm_analysis = self.mpm_parse_rules_json(tmpdir)
            result["mpm"] = mpm_analysis

        if options.get("pcap"):
            pcap_file = options["pcap"]
            if "file_path" in kwargs:
                base_dir = os.path.dirname(kwargs["file_path"])
                pcap_file = os.path.join(base_dir, pcap_file)
            pcap_path = os.path.join(tmpdir, "test.pcap")

            if not os.path.exists(pcap_file):
                if "warnings" not in result:
                    result["warnings"] = []
                pcap_file_line = options.get("pcap_line", 0)
                result["warnings"].append(
                    {
                        "message": f'PCAP file "{pcap_file}" not found for rules testing',
                        "source": self.SURICATA_SYNTAX_CHECK,
                        "line": pcap_file_line,
                    }
                )
                self.suricmd.cleanup()
                return result

            try:
                shutil.copyfile(pcap_file, pcap_path)
            except PermissionError as e:
                if "warnings" not in result:
                    result["warnings"] = []
                pcap_file_line = options.get("pcap_line", 0)
                result["warnings"].append(
                    {
                        "message": f'Permission error during PCAP file "{pcap_file}" copy: {str(e)}',
                        "source": self.SURICATA_SYNTAX_CHECK,
                        "line": pcap_file_line,
                    }
                )
                self.suricmd.cleanup()
                return result
            except OSError as e:
                if "warnings" not in result:
                    result["warnings"] = []
                pcap_file_line = options.get("pcap_line", 0)
                result["warnings"].append(
                    {
                        "message": f'Error during PCAP file "{pcap_file}" copy: {str(e)}',
                        "source": self.SURICATA_SYNTAX_CHECK,
                        "line": pcap_file_line,
                    }
                )
                self.suricmd.cleanup()
                return result

            suri_cmd = [
                "-r",
                os.path.join(self.suricmd.get_internal_tmpdir(), "test.pcap"),
            ]

            if suri_options:
                suri_cmd += suri_options

            run_error = self.suricmd.run(suri_cmd)
            if self.suricmd.returncode == True:
                result["matches"] = self.parse_eve(tmpdir)
                result["profiling"] = self.parse_profiling(tmpdir)
            else:
                self.suricmd.cleanup()
                raise SuricataFileException(
                    f"Error during Suricata run: {run_error}", 0
                )

        self.suricmd.cleanup()
        return result

    def parse_eve(self, tmpdir):
        eve_json_path = os.path.join(tmpdir, "eve.json")
        matches = {}
        try:
            with open(eve_json_path, "r", encoding="utf-8") as eve_json:
                for line in eve_json:
                    try:
                        event = json.loads(line)
                    except JSONDecodeError:
                        continue
                    if event.get("event_type") == "alert":
                        if event["alert"]["signature_id"] in matches:
                            matches[event["alert"]["signature_id"]] += 1
                        else:
                            matches[event["alert"]["signature_id"]] = 1
        except FileNotFoundError as e:
            raise FileNotFoundError(
                "Eve JSON file not found for parsing matches"
            ) from e
        return matches

    def parse_profiling(self, tmpdir):
        json_path = os.path.join(tmpdir, "rule_perf.json")
        profiling = {}
        try:
            with open(json_path, "r", encoding="utf-8") as profiling_json:
                for line in profiling_json:
                    try:
                        rules = json.loads(line).get("rules")
                        return rules
                    except JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return profiling

    def check_rule_buffer(
        self,
        rule_buffer,
        engine_analysis=True,
        config_buffer=None,
        related_files=None,
        extra_buffers=None,
        **kwargs,
    ):
        related_files = related_files or {}
        prov_result = self.rule_buffer(
            rule_buffer,
            engine_analysis=engine_analysis,
            config_buffer=config_buffer,
            related_files=related_files,
            extra_buffers=extra_buffers,
            **kwargs,
        )

        if len(prov_result.get("errors", "")):
            res = self.parse_suricata_error(prov_result["errors"])
            if "errors" in res:
                prov_result["errors"] = res["errors"]
            if "warnings" in res:
                prov_result["warnings"].extend(res["warnings"])
        return prov_result

    def parse_engine_analysis(self, log_dir):
        if self.json_compat_version():
            json_path = os.path.join(log_dir, "rules.json")
            if os.path.isfile(json_path):
                return self.parse_engine_analysis_v2(json_path)
            else:
                # we end up in this case when no rules is valid in buffer
                return []
        return self.parse_engine_analysis_v1(log_dir)

    def parse_engine_analysis_v1(self, log_dir):
        analysis = []
        analysis_path = os.path.join(log_dir, "rules_analysis.txt")
        if not os.path.isfile(analysis_path):
            return analysis
        with open(analysis_path, "r", encoding="utf-8") as analysis_file:
            in_sid_data = False
            signature: dict[str, (str | list[str])] = {}
            for line in analysis_file:
                if line.startswith("== "):
                    in_sid_data = True
                    signature = {"sid": line.split(" ")[2]}
                    continue
                elif in_sid_data and len(line) == 1:
                    in_sid_data = False
                    analysis.append(signature)
                    signature = {}
                elif in_sid_data and "content" not in signature:
                    signature["content"] = line.strip()
                    continue
                elif in_sid_data and "Warning: " in line:
                    warning = line.split("Warning: ")[1]
                    if "warnings" not in signature:
                        signature["warnings"] = []
                    if isinstance(signature["warnings"], str):
                        raise ValueError("Signature warnings is not a list")
                    signature["warnings"].append(warning.strip())
                elif in_sid_data and "Fast Pattern" in line:
                    if "info" not in signature:
                        signature["info"] = []
                    if isinstance(signature["info"], str):
                        raise ValueError("Signature info is not a list")
                    signature["info"].append(line.strip())
        return analysis

    def parse_engine_analysis_v2(self, json_path):
        analysis = []
        with open(json_path, "r", encoding="utf-8") as analysis_file:
            for line in analysis_file:
                signature_info = {}
                try:
                    signature_info = json.loads(line)
                except JSONDecodeError:
                    pass
                signature_msg = {"content": signature_info["raw"]}
                if "type" in signature_info:
                    if "info" not in signature_msg:
                        signature_msg["info"] = []
                    type_msg = f'Rule type is "{signature_info["type"]}"'
                    signature_msg["info"].append(type_msg)
                if "id" in signature_info:
                    signature_msg["sid"] = signature_info["id"]
                if "flags" in signature_info:
                    if (
                        "toserver" in signature_info["flags"]
                        and "toclient" in signature_info["flags"]
                    ):
                        if "warnings" not in signature_msg:
                            signature_msg["warnings"] = []
                        signature_msg["warnings"].append(
                            "Rule inspect server and client side, consider adding a flow keyword"
                        )
                if "warnings" in signature_info:
                    if "warnings" not in signature_msg:
                        signature_msg["warnings"] = []
                    signature_msg["warnings"].extend(signature_info.get("warnings", []))
                if "notes" in signature_info:
                    if "info" not in signature_msg:
                        signature_msg["info"] = []
                    signature_msg["info"].extend(signature_info.get("notes", []))
                if "engines" in signature_info:
                    app_proto = None
                    multiple_app_proto = False
                    got_raw_match = False
                    got_content = False
                    got_pcre = False
                    for engine in signature_info["engines"]:
                        if "app_proto" in engine:
                            if app_proto is None:
                                app_proto = engine.get("app_proto")
                            else:
                                if app_proto != engine.get("app_proto"):
                                    if app_proto not in [
                                        "http",
                                        "http2",
                                        "dns",
                                        "doh2",
                                    ] or engine.get("app_proto") not in [
                                        "http",
                                        "http2",
                                        "dns",
                                        "doh2",
                                    ]:
                                        multiple_app_proto = True

                        else:
                            got_raw_match = True
                        for match in engine.get("matches", []):
                            if match["name"] == "content":
                                got_content = True
                            elif match["name"] == "pcre":
                                got_pcre = True
                    if got_pcre and not got_content:
                        if "warnings" not in signature_msg:
                            signature_msg["warnings"] = []
                        signature_msg["warnings"].append(
                            "Rule with pcre without content match (possible performance issue)"
                        )
                    if app_proto is not None and got_raw_match:
                        if "warnings" not in signature_msg:
                            signature_msg["warnings"] = []
                        signature_msg["warnings"].append(
                            'Application layer "%s" combined with raw match, '
                            "consider using a match on application buffer" % (app_proto)
                        )
                    if multiple_app_proto:
                        if "warnings" not in signature_msg:
                            signature_msg["warnings"] = []
                        signature_msg["warnings"].append(
                            "Multiple application layers in same signature"
                        )
                analysis.append(signature_msg)
        return analysis

    def mpm_parse_rules_json(self, log_dir):
        mpm_data = []
        mpm_analysis = {"buffer": {}, "sids": {}}
        try:
            with open(
                os.path.join(log_dir, "rules.json"), "r", encoding="utf-8"
            ) as rules_json:
                for line in rules_json:
                    # some suricata version have an invalid JSON formatted message
                    try:
                        rule_analysis = json.loads(line)
                    except json.JSONDecodeError:
                        return None
                    if "mpm" in rule_analysis:
                        rule_analysis["mpm"]["id"] = rule_analysis["id"]
                        rule_analysis["mpm"]["gid"] = rule_analysis["gid"]
                        mpm_data.append(rule_analysis["mpm"])
                    else:
                        if "engines" in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for engine in rule_analysis.get("engines", []):
                                if engine["is_mpm"]:
                                    fp_buffer = engine["name"]
                                    for match in engine.get("matches", []):
                                        if match.get("name") == "content":
                                            if match.get("content", {}).get(
                                                "is_mpm", False
                                            ):
                                                fp_pattern = match["content"]["pattern"]
                                                break
                                    if fp_pattern:
                                        break
                            if fp_buffer and fp_pattern:
                                mpm_data.append(
                                    {
                                        "id": rule_analysis["id"],
                                        "gid": rule_analysis["gid"],
                                        "buffer": fp_buffer,
                                        "pattern": fp_pattern,
                                    }
                                )
                            continue
                        if "lists" in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for key in rule_analysis["lists"]:
                                fp_buffer = key
                                for match in rule_analysis["lists"][key].get(
                                    "matches", []
                                ):
                                    if match.get("name") == "content":
                                        if match.get("content", {}).get(
                                            "is_mpm", False
                                        ):
                                            fp_pattern = match["content"]["pattern"]
                                            break
                                if fp_pattern:
                                    break
                            if fp_buffer and fp_pattern:
                                mpm_data.append(
                                    {
                                        "id": rule_analysis["id"],
                                        "gid": rule_analysis["gid"],
                                        "buffer": fp_buffer,
                                        "pattern": fp_pattern,
                                    }
                                )
                            continue
        except FileNotFoundError:
            return mpm_analysis
        # target to have
        # { 'http.host': { 'grosminet': { 'count': 34, sigs: [{'id': 2, 'gid':1}]} } }
        for sig in mpm_data:
            if "content" in sig:
                sig_pattern = sig["content"]["pattern"]
            else:
                sig_pattern = sig["pattern"]
            if sig["buffer"] in mpm_analysis["buffer"]:
                if sig_pattern in mpm_analysis["buffer"][sig["buffer"]]:
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern]["count"] += 1
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern]["sigs"].append(
                        {"id": sig["id"], "gid": sig["gid"]}
                    )
                else:
                    mpm_analysis["buffer"][sig["buffer"]][sig_pattern] = {
                        "count": 1,
                        "sigs": [{"id": sig["id"], "gid": sig["gid"]}],
                    }
            else:
                mpm_analysis["buffer"][sig["buffer"]] = {
                    sig_pattern: {
                        "count": 1,
                        "sigs": [{"id": sig["id"], "gid": sig["gid"]}],
                    }
                }
            mpm_analysis["sids"][sig["id"]] = {
                "buffer": sig["buffer"],
                "pattern": sig_pattern,
            }
        return mpm_analysis

    def get_keywords_from_json(self):
        keywords = {}
        try:
            ressource_path = (
                importlib.resources.files("suricatals")
                / "data"
                / "suricata-keywords.json"
            )
            file_content = ressource_path.read_text(encoding="utf-8")
            known_keywords = json.loads(file_content)
            for keyword in known_keywords:
                keywords[keyword["name"]] = keyword
        except FileNotFoundError:
            pass
        return keywords

    def build_keywords_list(self):
        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()
        self.suricmd.generate_config(tmpdir)
        outdata = self.suricmd.run(["--list-keywords=csv"])
        self.suricmd.cleanup()
        if outdata is None:
            return []
        official_keywords = self.get_keywords_from_json()
        keywords = outdata.splitlines()
        keywords.pop(0)
        keywords_list = []
        for keyword in keywords:
            keyword_array = keyword.split(";")
            try:
                detail = "No option"
                if "sticky" in keyword_array[3]:
                    detail = "Sticky Buffer"
                elif keyword_array[3] == "none":
                    detail = "No option"
                else:
                    detail = keyword_array[3]
                if keyword_array[0] in official_keywords:
                    detail = f'{detail} (min_version: {official_keywords[keyword_array[0]]["initial_version"]}, max_version: {official_keywords[keyword_array[0]]["last_version"]})'
                else:
                    detail = f"{detail} (custom keyword)"
                documentation = keyword_array[1]
                if len(keyword_array) > 5:
                    if "https" in keyword_array[4]:
                        documentation += "\n\n"
                        documentation += "[Documentation](" + keyword_array[4] + ")"
                        documentation = {"kind": "markdown", "value": documentation}
                keyword_item = {
                    "label": keyword_array[0],
                    "kind": 14,
                    "detail": detail,
                    "documentation": documentation,
                }
                if "content modifier" in keyword_array[3]:
                    keyword_item["tags"] = [1]
                    keyword_item["detail"] = "Content Modifier"
                keywords_list.append(keyword_item)
            except IndexError:
                pass
        return keywords_list

    def build_app_layer_list(self):
        self.suricmd.prepare()
        tmpdir = self.suricmd.get_tmpdir()
        self.suricmd.generate_config(tmpdir)
        suri_cmd = [
            "--list-app-layer-proto",
        ]

        outdata = self.suricmd.run(suri_cmd)
        # start suricata in test mode
        self.suricmd.cleanup()
        if outdata is None:
            return []
        applayers = outdata.splitlines()
        while not applayers[0].startswith("===="):
            applayers.pop(0)
        applayers.pop(0)
        applayers_list = [
            {"label": "tcp", "detail": "tcp", "kind": 14},
            {"label": "udp", "detail": "udp", "kind": 14},
        ]
        for app_layer in applayers:
            app_layer_item = {"label": app_layer, "detail": app_layer, "kind": 14}
            applayers_list.append(app_layer_item)
        return applayers_list

    def get_semantic_token_definitions(self) -> Dict[str, Any]:
        # we need to get the list of keywords from suricata
        keywords = self.build_keywords_list()
        sticky_buffers = [
            k["label"] for k in keywords if "Sticky Buffer" in k.get("detail", "")
        ]
        options = [
            k["label"] for k in keywords if "Sticky Buffer" not in k.get("detail", "")
        ]
        app_layers = [k["label"] for k in self.build_app_layer_list()]
        actions = [k["label"] for k in self.ACTIONS_ITEMS]
        return {
            "actions": actions,
            "protocols": app_layers,
            "sticky_buffers": sticky_buffers,
            "options": options,
        }
