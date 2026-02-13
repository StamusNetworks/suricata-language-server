"""
Copyright(C) 2018-2025 Stamus Networks SAS
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

import shutil
import os
import json
import re
import logging
import shlex
from suricatals.suricata_command import SuriCmd
from suricatals.suricata_error_parser import SuricataErrorParser, SuricataFileException
from suricatals.suricata_engine_analyzer import SuricataEngineAnalyzer
from suricatals.suricata_discovery import SuricataDiscovery
from typing import Dict, Any
from json import JSONDecodeError

log = logging.getLogger(__name__)

# Re-export for backward compatibility
__all__ = ["TestRules", "SuricataFileException"]


class TestRules:
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
        self.error_parser = SuricataErrorParser(
            self.suricata_version, self.suricata_config
        )
        self.engine_analyzer = SuricataEngineAnalyzer(self.suricata_version)
        self.discovery = SuricataDiscovery(self.suricmd)

    def create_suricmd(self):
        """Create and configure SuriCmd instance based on settings."""
        self.suricmd = SuriCmd(self.suricata_binary, self.suricata_config)
        if self.docker:
            self.suricmd.set_docker_mode(docker_image=self.docker_image)

    def __getstate__(self):
        # Create a copy of the instance's dictionary
        state = self.__dict__.copy()
        # Remove the unpicklable fields before pickling
        del state["suricmd"]
        del state["discovery"]  # Contains reference to suricmd
        return state

    def __setstate__(self, state):
        # Restore the attributes from the pickled state
        self.__dict__.update(state)
        self.create_suricmd()
        self.error_parser = SuricataErrorParser(
            self.suricata_version, self.suricata_config
        )
        self.engine_analyzer = SuricataEngineAnalyzer(self.suricata_version)
        self.discovery = SuricataDiscovery(self.suricmd)

    @property
    def SURICATA_SYNTAX_CHECK(self):
        """Access SURICATA_SYNTAX_CHECK constant from error parser."""
        return self.error_parser.SURICATA_SYNTAX_CHECK

    @property
    def SURICATA_ENGINE_ANALYSIS(self):
        """Access SURICATA_ENGINE_ANALYSIS constant from engine analyzer."""
        return self.engine_analyzer.SURICATA_ENGINE_ANALYSIS

    @property
    def ACTIONS_ITEMS(self):
        """Access ACTIONS_ITEMS constant from discovery."""
        return self.discovery.ACTIONS_ITEMS

    def build_keywords_list(self):
        """Delegate to discovery module."""
        return self.discovery.build_keywords_list()

    def build_app_layer_list(self):
        """Delegate to discovery module."""
        return self.discovery.build_app_layer_list()

    def get_semantic_token_definitions(self):
        """Delegate to discovery module."""
        return self.discovery.get_semantic_token_definitions()

    def get_suricata_version(self):
        """Get Suricata version string from binary.

        Returns:
            str: Version string (e.g., "7.0.0"), or "6.0.0" if unable to determine
        """
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

    def rules_infos(self, rule_buffer):
        """Get detailed information about rules using Suricata engine analysis.

        Args:
            rule_buffer: String containing Suricata rule(s)

        Returns:
            dict: Dictionary mapping signature IDs to rule analysis data

        Raises:
            IOError: If temporary directory cannot be created
            SuricataFileException: If rule buffer contains invalid directives
        """
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
        """Test and analyze a buffer of Suricata rules.

        Args:
            rule_buffer: String containing Suricata rule(s)
            engine_analysis: Whether to run engine analysis (default: True)
            config_buffer: Optional custom Suricata configuration
            related_files: Optional dict of related files to include
            reference_config: Optional reference.config content
            classification_config: Optional classification.config content
            extra_buffers: Optional list of extra rule buffers to include
            **kwargs: Additional options passed to configuration

        Returns:
            dict: Result with 'status', 'errors', 'warnings', 'info', and 'analysis' keys

        Raises:
            SuricataFileException: If rule buffer contains invalid directives
        """

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

            engine_analysis = self.engine_analyzer.parse_engine_analysis(tmpdir)
            for signature in engine_analysis:
                for warning in signature.get("warnings", []):
                    result["warnings"].append(
                        {
                            "message": warning,
                            "source": self.engine_analyzer.SURICATA_ENGINE_ANALYSIS,
                            "sid": signature.get("sid", "UNKNOWN"),
                            "content": signature["content"],
                        }
                    )

                for info in signature.get("info", []):
                    result["info"].append(
                        {
                            "message": info,
                            "source": self.engine_analyzer.SURICATA_ENGINE_ANALYSIS,
                            "content": signature["content"],
                            "sid": signature.get("sid", "UNKNOWN"),
                        }
                    )

            mpm_analysis = self.engine_analyzer.parse_mpm_data(tmpdir)
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
        """Parse EVE JSON output to extract alert matches.

        Args:
            tmpdir: Directory containing eve.json file

        Returns:
            dict: Mapping of signature IDs to match counts

        Raises:
            FileNotFoundError: If eve.json file is not found
        """
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
        """Parse rule profiling data from rule_perf.json.

        Args:
            tmpdir: Directory containing rule_perf.json file

        Returns:
            dict or list: Profiling data for rules, or empty dict if not found
        """
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
        """Check and validate a rule buffer, returning structured diagnostics.

        This is the main API method for rule validation, converting raw Suricata
        output into structured error/warning/info lists suitable for LSP clients.

        Args:
            rule_buffer: String containing Suricata rule(s)
            engine_analysis: Whether to run engine analysis (default: True)
            config_buffer: Optional custom Suricata configuration
            related_files: Optional dict of related files to include
            extra_buffers: Optional list of extra rule buffers to include
            **kwargs: Additional options passed to configuration

        Returns:
            dict: Result with 'errors', 'warnings', and 'info' lists containing
                  structured diagnostic information

        Raises:
            SuricataFileException: If rule buffer contains invalid directives
        """
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
            res = self.error_parser.parse_error(prov_result["errors"])
            if "errors" in res:
                prov_result["errors"] = res["errors"]
            if "warnings" in res:
                prov_result["warnings"].extend(res["warnings"])
        return prov_result
