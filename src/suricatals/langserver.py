"""
Copyright(C) 2018-2021 Chris Hansen <hansec@uw.edu>
Copyright(C) 2021-2026 Stamus Networks
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

from .__init__ import __version__
from suricatals.parse_signatures import SuricataFile
from suricatals.tests_rules import TestRules
from suricatals.suri_cmd import SuriCmd
from suricatals.tokenize_sig import SuricataSemanticTokenParser


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


def init_file(filepath, rules_tester, line_limit):
    file_obj = SuricataFile(filepath, rules_tester)
    if file_obj.nLines < line_limit:
        file_obj.check_file()
    return file_obj, None


def register_feature(lsp_type, options=None):
    """
    Decorator that temporarily saves the configuration on the method
    so it can be read later by _register_all_features.
    """

    def decorator(func):
        # We attach these custom attributes to the method function
        func._lsp_type = lsp_type
        func._lsp_options = options
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
            self.server = LanguageServer("Suricata Language Server", __version__)
            self._register_all_features()
        self.keywords_list = []
        self.app_layer_list = []

    def _register_all_features(self):
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if hasattr(method, "_lsp_type"):
                feature_type = getattr(method, "_lsp_type", "")
                options = getattr(method, "_lsp_options", None)
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
    def server_initialized(self, params: types.InitializedParams):
        # Initialize the rules tester, this can take long in container
        # mode as it is going to trigger a fetch.
        progress_token = str(uuid.uuid4())

        self.server.work_done_progress.create(progress_token)

        self.server.work_done_progress.begin(
            progress_token,
            types.WorkDoneProgressBegin(
                title="Suricata Container Init",
                message="Initializing Suricata container and potentially fetching image",
                cancellable=False,
            ),
        )

        self.rules_tester = self.create_rule_tester()
        self.server.work_done_progress.report(
            progress_token,
            types.WorkDoneProgressReport(
                percentage=80,
                message=f"Suricata v{self.rules_tester.suricata_version} container ready.",
            ),
        )

        self.keywords_list = self.rules_tester.build_keywords_list()

        self.server.work_done_progress.report(
            progress_token,
            types.WorkDoneProgressReport(
                percentage=90, message="Suricata keywords fetched."
            ),
        )
        self.app_layer_list = self.rules_tester.build_app_layer_list()
        self.server.work_done_progress.end(
            progress_token,
            types.WorkDoneProgressEnd(message="Suricata Language Server ready."),
        )

    def run(self):
        # Run server
        self.server.start_io()

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
                        kind=types.CompletionItemKind.Function,
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
                        kind=types.CompletionItemKind.Property,
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
                        kind=types.CompletionItemKind.Function,
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
        # Get parameters from request
        uri = params.text_document.uri
        file_obj = self.server.workspace.get_text_document(uri)
        path = path_from_uri(uri)
        s_file = SuricataFile(path, self.rules_tester, empty=True)
        s_file.load_from_lsp(file_obj)
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
        # Get parameters from request
        uri = params.text_document.uri
        file_obj = self.server.workspace.get_text_document(uri)
        path = path_from_uri(uri)
        s_file = SuricataFile(path, self.rules_tester, empty=True)
        s_file.load_from_lsp(file_obj)
        # Add scopes to outline view
        data = s_file.get_semantic_tokens(file_range=params.range)
        return types.SemanticTokens(data=data)

    def get_diagnostics(self, uri):
        file_obj = self.server.workspace.get_text_document(uri)
        if file_obj is not None and len(file_obj.lines) < self.max_lines:
            s_file = SuricataFile(path_from_uri(uri), self.rules_tester, empty=True)
            s_file.load_from_lsp(file_obj)
            _, diags_list = s_file.check_lsp_file(file_obj)
            diags = [diag.to_diagnostic() for diag in diags_list]
            # pylint: disable=W0703
            return diags, None
        return None, None

    @register_feature(types.TEXT_DOCUMENT_DID_OPEN)
    def serve_onOpen(self, params):
        self.serve_onSave(params, did_open=True)

    @register_feature(types.TEXT_DOCUMENT_DID_CLOSE)
    def serve_onClose(self, params):
        self.serve_onSave(params, did_close=True)

    @register_feature(types.TEXT_DOCUMENT_DID_SAVE)
    def serve_onSave(self, params, did_open=False, did_close=False):
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

    def serve_exit(self, _):
        # Exit server
        self.workspace = {}
        self.running = False

    def analyse_file(self, filepath, engine_analysis=True, **kwargs):
        if self.rules_tester == None:
            self.rules_tester = self.create_rule_tester()
        file_obj = SuricataFile(filepath, self.rules_tester)
        file_obj.load_from_disk()
        return file_obj.check_file(engine_analysis=engine_analysis, **kwargs)

    def rules_infos(self, rule_buffer, **kwargs):
        if self.rules_tester == None:
            self.rules_tester = self.create_rule_tester()
        return self.rules_tester.rules_infos(rule_buffer, **kwargs)
