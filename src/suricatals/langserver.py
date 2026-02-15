"""
Copyright(C) 2018-2021 Chris Hansen <hansec@uw.edu>
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

import logging
import os
import re
import uuid
from urllib.parse import unquote
from functools import wraps
import inspect
from typing import Optional
from importlib.metadata import version
import queue

from suricatals.signature_parser import SuricataFile
from suricatals.signature_validator import TestRules
from suricatals.suricata_command import SuriCmd
from suricatals.signature_tokenizer import SuricataSemanticTokenParser
from suricatals.mpm_cache import MpmCache


from pygls.lsp.server import LanguageServer
from lsprotocol import types

log = logging.getLogger(__name__)

SURICATA_RULES_EXT_REGEX = re.compile(r"^\.rules?$", re.I)


def path_from_uri(uri):
    # Convert file uri to path (strip html like head part)
    if not uri.startswith("file://"):
        return uri
    if os.name == "nt":
        if uri.startswith("file:///"):
            _, path = uri.split("file:///", 1)
        else:  # we should have an UNC path
            _, path = uri.split("file:", 1)
            return path
    else:
        _, path = uri.split("file://", 1)
    return os.path.normpath(unquote(path))


def register_feature(lsp_type, options=None):
    """
    Decorator that temporarily saves the configuration on the method
    so it can be read later by _register_all_features.
    """

    def decorator(func):
        # We attach these custom attributes to the method function
        func.lsp_type = lsp_type
        func.lsp_options = options
        return func

    return decorator


class LangServer:
    def __init__(self, debug_log=False, settings=None, batch_mode=False):
        self.running = True
        self.root_path = None
        self.fs = None
        self.source_dirs = []
        self.excl_paths = []
        self.excl_suffixes = []
        self.post_messages = []
        self.streaming = True
        self.debug_log = debug_log
        self.batch_mode = batch_mode
        # Get launch settings
        if settings is None:
            settings = {}
        self.nthreads = settings.get("nthreads", 4)
        self.notify_init = settings.get("notify_init", False)
        self.sync_type = settings.get("sync_type", 1)
        self.suricata_binary = settings.get("suricata_binary", "suricata")
        self.suricata_config = settings.get("suricata_config", None)
        self.max_lines = settings.get("max_lines", 1000)
        self.max_tracked_files = settings.get("max_tracked_files", 100)
        self.docker = settings.get("docker_mode", False)
        self.docker_image = settings.get(
            "docker_image", SuriCmd.SLS_DEFAULT_DOCKER_IMAGE
        )
        self.rules_tester = None
        if batch_mode:
            self.rules_tester = self.create_rule_tester()
        else:
            p_version = version("suricata-language-server")
            self.server = LanguageServer("Suricata Language Server", p_version)
            self._register_all_features()
        self.keywords_list = []
        self.app_layer_list = []
        # Workspace MPM data cache for cross-file pattern collision detection
        self.workspace_mpm = MpmCache()

    def _register_all_features(self):
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if hasattr(method, "lsp_type"):
                feature_type = getattr(method, "lsp_type", "")
                options = getattr(method, "lsp_options", None)
                # We use a helper function to create the wrapper.
                # This ensures 'method' is captured by value, not by reference.
                wrapper = self._create_wrapper(method)

                self.server.feature(feature_type, options)(wrapper)

    def _create_wrapper(self, bound_method):
        """
        Creates a wrapper function that keeps 'self' bound correctly.
        """

        @wraps(bound_method)
        def wrapper(*args, **kwargs):
            # bound_method already contains 'self', so we just pass the args
            return bound_method(*args, **kwargs)

        return wrapper

    def create_rule_tester(self):
        return TestRules(
            suricata_binary=self.suricata_binary,
            suricata_config=self.suricata_config,
            docker=self.docker,
            docker_image=self.docker_image,
        )

    @register_feature(types.INITIALIZED)
    def server_initialized(self, _params: types.InitializedParams):
        # Initialize the rules tester, this can take long in container
        # mode as it is going to trigger a fetch.
        progress_token = str(uuid.uuid4())

        self.server.work_done_progress.create(progress_token)

        if self.docker:
            title = "Suricata Container Init"
            message = "Initializing Suricata container and potentially fetching image"
        else:
            title = "Suricata Language Server Init"
            message = "Initializing Suricata and fetching various lists for autocompletion and diagnostics"

        self.server.work_done_progress.begin(
            progress_token,
            types.WorkDoneProgressBegin(
                title=title,
                message=message,
                cancellable=False,
            ),
        )

        self.rules_tester = self.create_rule_tester()
        if self.docker:
            message = (
                f"Suricata v{self.rules_tester.suricata_version} container initialized"
            )
        else:
            message = f"Suricata v{self.rules_tester.suricata_version} available"
        self.server.work_done_progress.report(
            progress_token,
            types.WorkDoneProgressReport(
                percentage=80,
                message=message,
            ),
        )

        self.keywords_list = self.rules_tester.build_keywords_list()

        self.server.work_done_progress.report(
            progress_token,
            types.WorkDoneProgressReport(
                percentage=90, message="Suricata keywords fetched"
            ),
        )
        self.app_layer_list = self.rules_tester.build_app_layer_list()
        self.server.work_done_progress.end(
            progress_token,
            types.WorkDoneProgressEnd(message="Suricata Language Server ready"),
        )

        # Analyze existing workspace folders for MPM data
        if self.server.workspace.folders:
            all_rules_files = []
            for folder in self.server.workspace.folders.values():
                path = path_from_uri(folder.uri)
                if os.path.isdir(path):
                    self.source_dirs.append(path)
                    rules_files = self.find_rules_files(path)
                    all_rules_files.extend(rules_files)

            if all_rules_files:
                log.info(
                    "Found %d rules files in workspace, starting MPM analysis",
                    len(all_rules_files),
                )
                self.analyze_workspace_files(all_rules_files)

    def run(self):
        # Run server
        self.server.start_io()

    def get_suricata_file(self, uri) -> Optional[SuricataFile]:
        file_obj = self.server.workspace.get_text_document(uri)
        path = path_from_uri(uri)
        s_file = SuricataFile(path, self.rules_tester)
        s_file.load_from_lsp(file_obj)
        return s_file

    def _initial_params_autocomplete(
        self, params: types.CompletionParams, file_obj
    ) -> Optional[types.CompletionList]:
        edit_index = params.position.line
        sig_content = file_obj.lines[edit_index]
        sig_index = params.position.character
        word_split = re.split(" +", sig_content[0:sig_index])
        if len(word_split) == 1:
            if self.rules_tester is None:
                self.rules_tester = self.create_rule_tester()
            lsp_completion_items = []
            for item in self.rules_tester.ACTIONS_ITEMS:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 3)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)
        if len(word_split) == 2:
            lsp_completion_items = []
            for item in self.app_layer_list:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 10)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)
        if edit_index == 0:
            return None
        elif not re.search(r"\\ *$", file_obj.contents_split[edit_index - 1]):
            return None

    @register_feature(
        types.TEXT_DOCUMENT_COMPLETION,
        options=types.CompletionOptions(trigger_characters=["."]),
    )
    def serve_autocomplete(
        self, params: types.CompletionParams
    ) -> Optional[types.CompletionList]:
        uri = params.text_document.uri
        file_obj = self.server.workspace.get_text_document(uri)
        if file_obj is None:
            return None
        edit_index = params.position.line
        sig_index = params.position.character

        sig_content = file_obj.lines[edit_index]
        # not yet in content matching so just return nothing
        if "(" not in sig_content[0:sig_index]:
            return self._initial_params_autocomplete(params, file_obj)
        cursor = sig_index - 1
        while cursor > 0:
            log.debug(
                "At index: %d of %d (%s)",
                cursor,
                len(sig_content),
                sig_content[cursor:sig_index],
            )
            if not sig_content[cursor].isalnum() and not sig_content[cursor] in [
                ".",
                "_",
            ]:
                break
            cursor -= 1
        log.debug("Final is: %d : %d", cursor, sig_index)
        if cursor == sig_index - 1:
            return None
        # this is an option edit so dont list keyword
        if sig_content[cursor] in [":", ","]:
            return None
        cursor += 1
        partial_keyword = sig_content[cursor:sig_index]
        log.debug("Got keyword start: '%s'", partial_keyword)
        items_list = []
        for item in self.keywords_list:
            if item["label"].startswith(partial_keyword):
                items_list.append(item)
        if len(items_list):
            lsp_completion_items = []
            for item in items_list:
                lsp_completion_items.append(
                    types.CompletionItem(
                        label=item["label"],
                        kind=types.CompletionItemKind(item.get("kind", 3)),
                        detail=item.get("detail", ""),
                        documentation=item.get("documentation", ""),
                        deprecated=item.get("deprecated", False),
                    )
                )
            return types.CompletionList(is_incomplete=False, items=lsp_completion_items)
        return None

    @register_feature(
        types.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        options=types.SemanticTokensLegend(
            token_types=SuricataSemanticTokenParser.TOKEN_TYPES,
            token_modifiers=SuricataSemanticTokenParser.TOKEN_MODIFIERS,
        ),
    )
    def serve_semantic_tokens(self, params: types.SemanticTokensParams):
        s_file = self.get_suricata_file(params.text_document.uri)
        if s_file is None:
            return types.SemanticTokens(data=[])
        # Add scopes to outline view
        data = s_file.get_semantic_tokens()
        return types.SemanticTokens(data=data)

    @register_feature(
        types.TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
        options=types.SemanticTokensLegend(
            token_types=SuricataSemanticTokenParser.TOKEN_TYPES,
            token_modifiers=SuricataSemanticTokenParser.TOKEN_MODIFIERS,
        ),
    )
    def serve_semantic_tokens_range(self, params: types.SemanticTokensRangeParams):
        s_file = self.get_suricata_file(params.text_document.uri)
        if s_file is None:
            return types.SemanticTokens(data=[])
        # Add scopes to outline view
        data = s_file.get_semantic_tokens(file_range=params.range)
        return types.SemanticTokens(data=data)

    def get_diagnostics(self, uri):
        file_obj = self.server.workspace.get_text_document(uri)
        if file_obj is not None and len(file_obj.lines) < self.max_lines:
            s_file = self.get_suricata_file(uri)
            if s_file is None:
                return None, None
            # Pass workspace_mpm for cross-file MPM analysis
            filepath = path_from_uri(uri)
            _, diags_list = s_file.check_lsp_file(
                file_obj,
                workspace=self.workspace_mpm.get_workspace_view(exclude_file=filepath),
            )

            # Update workspace_mpm with the analyzed file's MPM data
            self.workspace_mpm.add_file_from_suricata_file(filepath, s_file)

            diags = [diag.to_diagnostic() for diag in diags_list]
            # pylint: disable=W0703
            return diags, None
        return None, None

    @register_feature(types.TEXT_DOCUMENT_DID_OPEN)
    def serve_on_open(self, params):
        self.serve_on_save(params)

    @register_feature(types.TEXT_DOCUMENT_DID_CLOSE)
    def serve_on_close(self, params):
        self.serve_on_save(params)

    @register_feature(types.TEXT_DOCUMENT_DID_SAVE)
    def serve_on_save(self, params):
        # Update workspace from file on disk
        uri = params.text_document.uri
        filepath = path_from_uri(uri)
        progress_token = str(uuid.uuid4())
        self.server.work_done_progress.begin(
            progress_token,
            types.WorkDoneProgressBegin(
                title="Suricata Analysis started",
                message="Starting analysis of file %s by Suricata" % uri,
                cancellable=False,
            ),
        )
        diag_results, diag_exp = self.get_diagnostics(uri)

        self.server.work_done_progress.end(
            progress_token,
            types.WorkDoneProgressEnd(message="Suricata analysis completed"),
        )

        if diag_exp is not None:
            log.error("Error during diagnostics for file %s", filepath, exc_info=True)
            return
        if diag_results is None:
            log.error("Error during diagnostics for file %s", filepath)
            return
        self.server.text_document_publish_diagnostics(
            types.PublishDiagnosticsParams(
                uri=uri,
                diagnostics=diag_results,
            )
        )

    def find_rules_files(self, directory):
        """Recursively find all .rules files in a directory."""
        rules_files = []
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    if SURICATA_RULES_EXT_REGEX.match(os.path.splitext(file)[1]):
                        rules_files.append(os.path.join(root, file))
        except PermissionError as e:
            log.warning("Permission denied scanning directory %s: %s", directory, e)
        except OSError as e:
            log.warning("Error scanning directory %s: %s", directory, e)
        return rules_files

    def _store_file_mpm_data(self, filepath, s_file):
        """
        Store MPM data for an analyzed file.

        Args:
            filepath: Path to the rules file
            s_file: SuricataFile object with analysis results

        Returns:
            bool: True if MPM data was stored, False otherwise
        """
        return self.workspace_mpm.add_file_from_suricata_file(filepath, s_file)

    def _analyze_workspace_files_sequential(self, rules_files, progress_token):
        """
        Sequential fallback for workspace analysis.

        Used only as fallback when parallel processing fails critically.

        Args:
            rules_files: List of file paths to analyze
            progress_token: UUID token for progress reporting
        """
        analyzed_count = 0
        error_count = 0

        for filepath in rules_files:
            try:
                s_file, _, _ = self.analyse_file(filepath, engine_analysis=True)
                self._store_file_mpm_data(filepath, s_file)
                analyzed_count += 1
                self._report_analysis_progress(
                    progress_token, analyzed_count, error_count, len(rules_files)
                )
            # pylint: disable=W0703
            except Exception as e:
                error_count += 1
                log.error("Error analyzing file %s: %s", filepath, e, exc_info=True)

        self._finalize_workspace_analysis(progress_token, analyzed_count, error_count)

    def _setup_workspace_analysis(self, rules_files):
        """Setup progress tracking and return progress token."""
        progress_token = str(uuid.uuid4())
        self.server.work_done_progress.create(progress_token)
        self.server.work_done_progress.begin(
            progress_token,
            types.WorkDoneProgressBegin(
                title="Analyzing Workspace Rules",
                message=f"Analyzing {len(rules_files)} rules files for MPM information (parallel mode)",
                cancellable=False,
            ),
        )
        return progress_token

    def _process_future_result(self, future, filepath):
        """
        Process a single future result from workspace analysis.

        Returns:
            tuple: (analyzed_success: bool, had_error: bool)
        """
        try:
            # Get result with timeout (5 minutes per file)
            result_filepath, mpm_data, error = future.result(timeout=300)

            # Store successful results
            if error is None and mpm_data:
                self.workspace_mpm.add_file(result_filepath, mpm_data)
                return True, False

            if error:
                log.error("Failed to analyze file %s: %s", result_filepath, error)
            return False, True

        except TimeoutError:
            log.error("Timeout analyzing file %s (>5 minutes)", filepath)
            return False, True
        # pylint: disable=W0703
        except Exception as e:
            log.error(
                "Unexpected error processing file %s: %s",
                filepath,
                e,
                exc_info=True,
            )
            return False, True

    def _drain_progress_queue(self, progress_queue):
        """Drain progress queue non-blocking."""
        while not progress_queue.empty():
            try:
                progress_queue.get_nowait()
            except queue.Empty:
                break

    def _report_analysis_progress(
        self, progress_token, analyzed_count, error_count, total_files
    ):
        """Report workspace analysis progress periodically."""
        total_processed = analyzed_count + error_count
        if total_processed % 10 == 0 or total_processed == total_files:
            error_msg = f" ({error_count} errors)" if error_count > 0 else ""
            self.server.work_done_progress.report(
                progress_token,
                types.WorkDoneProgressReport(
                    percentage=int((total_processed / total_files) * 100),
                    message=f"Analyzed {analyzed_count}/{total_files} files{error_msg}",
                ),
            )

    def _finalize_workspace_analysis(self, progress_token, analyzed_count, error_count):
        """Finalize workspace analysis with progress update and logging."""
        error_msg = f", {error_count} errors" if error_count > 0 else ""
        self.server.work_done_progress.end(
            progress_token,
            types.WorkDoneProgressEnd(
                message=f"Workspace analysis complete: {analyzed_count} files analyzed{error_msg}"
            ),
        )

        stats = self.workspace_mpm.get_statistics()
        log.info(
            "Workspace MPM data: %d files analyzed, %d signatures, %d errors",
            analyzed_count,
            stats["total_sids"],
            error_count,
        )

    def analyze_workspace_files(self, rules_files):
        """Analyze rules files to extract MPM information using parallel processing."""
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor, as_completed
        from suricatals.worker_pool import analyze_file_worker

        if self.rules_tester is None:
            self.rules_tester = self.create_rule_tester()

        # Prepare configuration dict for workers (must be picklable)
        rules_tester_config = {
            "suricata_binary": self.suricata_binary,
            "suricata_config": self.suricata_config,
            "docker": self.docker,
            "docker_image": self.docker_image,
        }

        progress_token = self._setup_workspace_analysis(rules_files)
        manager = multiprocessing.Manager()
        progress_queue = manager.Queue()

        analyzed_count = 0
        error_count = 0

        try:
            with ProcessPoolExecutor(max_workers=self.nthreads) as executor:
                # Submit all files for processing
                futures = {
                    executor.submit(
                        analyze_file_worker,
                        filepath,
                        rules_tester_config,
                        progress_queue,
                    ): filepath
                    for filepath in rules_files
                }

                # Process results as they complete
                for future in as_completed(futures):
                    filepath = futures[future]
                    success, had_error = self._process_future_result(future, filepath)

                    if success:
                        analyzed_count += 1
                    if had_error:
                        error_count += 1

                    self._drain_progress_queue(progress_queue)
                    self._report_analysis_progress(
                        progress_token, analyzed_count, error_count, len(rules_files)
                    )

        # pylint: disable=W0703
        except Exception as e:
            log.error(
                "Critical error in parallel workspace analysis: %s", e, exc_info=True
            )
            log.info("Falling back to sequential processing")
            manager.shutdown()
            return self._analyze_workspace_files_sequential(rules_files, progress_token)
        finally:
            try:
                manager.shutdown()
            # pylint: disable=W0703
            except Exception:
                pass

        self._finalize_workspace_analysis(progress_token, analyzed_count, error_count)

    @register_feature(types.WORKSPACE_DID_CHANGE_WORKSPACE_FOLDERS)
    def serve_workspace_did_change_workspace_folders(self, params):
        # Update workspace folders
        for folder in params.event.added:
            path = path_from_uri(folder.uri)
            if os.path.isdir(path):
                self.source_dirs.append(path)
                # Find and analyze all .rules files in the added folder
                rules_files = self.find_rules_files(path)
                if rules_files:
                    log.info(
                        "Found %d rules files in added folder %s, analyzing for MPM data",
                        len(rules_files),
                        path,
                    )
                    self.analyze_workspace_files(rules_files)

        for folder in params.event.removed:
            path = path_from_uri(folder.uri)
            if path in self.source_dirs:
                self.source_dirs.remove(path)
                # Remove MPM data for files in removed folder
                removed_count = self.workspace_mpm.remove_by_prefix(path)
                if removed_count > 0:
                    log.info(
                        "Removed MPM data for %d files from removed folder",
                        removed_count,
                    )

    def analyse_file(self, filepath, engine_analysis=True, **kwargs):
        if self.rules_tester == None:
            self.rules_tester = self.create_rule_tester()
        file_obj = SuricataFile(filepath, self.rules_tester)
        file_obj.load_from_disk()
        status, diags = file_obj.check_file(engine_analysis=engine_analysis, **kwargs)
        return file_obj, status, diags

    def rules_infos(self, rule_buffer):
        if self.rules_tester == None:
            self.rules_tester = self.create_rule_tester()
        return self.rules_tester.rules_infos(rule_buffer)
