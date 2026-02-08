"""
Copyright(C) 2018-2021 Chris Hansen <hansec@uw.edu>
Copyright(C) 2021-2025 Stamus Networks

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
import traceback
import re
import uuid

from pygls.server import JsonRPCServer
from pygls.uris import to_fs_path
from lsprotocol.types import (
    TEXT_DOCUMENT_COMPLETION,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
    TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
    INITIALIZED,
    CompletionParams,
    CompletionList,
    CompletionItem,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
    DidCloseTextDocumentParams,
    DidChangeTextDocumentParams,
    SemanticTokensParams,
    SemanticTokens,
    SemanticTokensRangeParams,
    InitializedParams,
    Diagnostic,
    DiagnosticSeverity,
    PublishDiagnosticsParams,
    MessageType,
    WorkDoneProgressBegin,
    WorkDoneProgressReport,
    WorkDoneProgressEnd,
    InitializeParams,
    SemanticTokensLegend,
    SemanticTokensRegistrationOptions,
    TextDocumentSyncKind,
)

from suricatals.parse_signatures import SuricataFile
from suricatals.tests_rules import TestRules, SuricataFileException
from suricatals.suri_cmd import SuriCmd
from suricatals.tokenize_sig import SuricataSemanticTokenParser

log = logging.getLogger(__name__)

SURICATA_RULES_EXT_REGEX = re.compile(r"^\.rules?$", re.I)


def init_file(filepath, rules_tester, line_limit):
    file_obj = SuricataFile(filepath, rules_tester)
    if file_obj.nLines < line_limit:
        file_obj.check_file()
    return file_obj, None


class SuricataLanguageServer(JsonRPCServer):
    """Suricata Language Server implementation using pygls."""
    
    PROGRESS_MSG = "$/progress"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.workspace_files = {}
        self.source_dirs = []
        self.excl_paths = []
        self.excl_suffixes = []
        self.post_messages = []
        self.rules_tester = None
        self.keywords_list = []
        self.app_layer_list = []
        self.root_path = None
        # Will be set by create_language_server
        self.nthreads = 4
        self.notify_init = False
        self.sync_type = 1
        self.suricata_binary = "suricata"
        self.suricata_config = None
        self.max_lines = 1000
        self.max_tracked_files = 100
        self.docker = False
        self.docker_image = SuriCmd.SLS_DEFAULT_DOCKER_IMAGE
        self.debug_log = False

    def create_rule_tester(self):
        return TestRules(
            suricata_binary=self.suricata_binary,
            suricata_config=self.suricata_config,
            docker=self.docker,
            docker_image=self.docker_image,
        )

    def post_message(self, message, msg_type=MessageType.Info):
        self.show_message(message, msg_type)

    def send_diagnostics(self, uri):
        diag_results, diag_exp = self.get_diagnostics(uri)
        if diag_results is not None:
            self.publish_diagnostics(uri, diag_results)
        elif diag_exp is not None:
            if isinstance(diag_exp, SuricataFileException):
                log.error("File error: %s", diag_exp, exc_info=True)
                diag = diag_exp.get_diagnosis().to_lsp_diagnostic()
                self.publish_diagnostics(uri, [diag])
                return
            # For other exceptions, log but don't publish
            log.error("Diagnostic error: %s", diag_exp, exc_info=True)

    def get_diagnostics(self, uri):
        filepath = to_fs_path(uri)
        file_obj = self.workspace_files.get(filepath)
        if file_obj is not None and file_obj.nLines < self.max_lines:
            try:
                _, diags_list = file_obj.check_file(workspace=self.workspace_files)
                diags = [diag.to_lsp_diagnostic() for diag in diags_list]
            # pylint: disable=W0703
            except Exception as e:
                if os.path.isfile(file_obj.path):
                    return None, e
            else:
                return diags, None
        return None, None

    def update_workspace_file(self, filepath, read_file=False, allow_empty=False):
        # Update workspace from file contents and path
        try:
            file_obj = self.workspace_files.get(filepath)
            if read_file:
                if file_obj is None:
                    # Create empty file if not yet saved to disk
                    if not os.path.isfile(filepath):
                        file_obj = SuricataFile(filepath, self.rules_tester, empty=True)
                        if allow_empty:
                            self.workspace_files[filepath] = file_obj
                            return False, None
                        else:
                            return False, "File does not exist"  # Error during load
                    else:
                        file_obj = SuricataFile(filepath, self.rules_tester)
                hash_old = file_obj.hash
                err_string = None
                if os.path.isfile(filepath):
                    err_string = file_obj.load_from_disk()
                    file_obj.parse_file()
                if err_string is not None:
                    log.error("%s: %s", err_string, filepath)
                    return False, err_string  # Error during file read
                if hash_old == file_obj.hash:
                    return False, None
        # pylint: disable=W0703
        except Exception:
            log.error("Error while parsing file %s", filepath, exc_info=True)
            return False, "Error during parsing"  # Error during parsing
        if filepath not in self.workspace_files:
            self.workspace_files[filepath] = file_obj
        return True, None

    def workspace_init(self):
        # Get filenames
        file_list = []
        for source_dir in self.source_dirs:
            for filename in os.listdir(source_dir):
                _, ext = os.path.splitext(os.path.basename(filename))
                if SURICATA_RULES_EXT_REGEX.match(ext):
                    filepath = os.path.normpath(os.path.join(source_dir, filename))
                    if self.excl_paths.count(filepath) > 0:
                        continue
                    inc_file = True
                    for excl_suffix in self.excl_suffixes:
                        if filepath.endswith(excl_suffix):
                            inc_file = False
                            break
                    if inc_file:
                        file_list.append(filepath)
        # Process files
        # don't send to analysis if too many files
        if len(file_list) > self.max_tracked_files:
            return
        from multiprocessing import Pool

        pool = Pool(processes=self.nthreads)
        results = {}
        if self.rules_tester is None:
            self.rules_tester = self.create_rule_tester()
        for filepath in file_list:
            results[filepath] = pool.apply_async(
                init_file, args=(filepath, self.rules_tester, self.max_lines)
            )
        pool.close()
        pool.join()
        for path, result in results.items():
            result_obj = result.get()
            if result_obj[0] is None:
                self.post_messages.append(
                    [
                        MessageType.Error,
                        'Initialization failed for file "{0}": {1}'.format(
                            path, result_obj[1]
                        ),
                    ]
                )
                continue
            self.workspace_files[path] = result_obj[0]

    def _initial_params_autocomplete(self, params, file_obj):
        edit_index = params.position.line
        sig_content = file_obj.contents_split[edit_index]
        sig_index = params.position.character
        word_split = re.split(" +", sig_content[0:sig_index])
        if len(word_split) == 1:
            if self.rules_tester is None:
                self.rules_tester = self.create_rule_tester()
            return self.rules_tester.ACTIONS_ITEMS
        if len(word_split) == 2:
            return self.app_layer_list
        if edit_index == 0:
            return None
        elif not re.search(r"\\ *$", file_obj.contents_split[edit_index - 1]):
            return None

    def analyse_file(self, filepath, engine_analysis=True, **kwargs):
        if self.rules_tester is None:
            self.rules_tester = self.create_rule_tester()
        file_obj = SuricataFile(filepath, self.rules_tester)
        file_obj.load_from_disk()
        return file_obj.check_file(engine_analysis=engine_analysis, **kwargs)

    def rules_infos(self, rule_buffer, **kwargs):
        if self.rules_tester is None:
            self.rules_tester = self.create_rule_tester()
        return self.rules_tester.rules_infos(rule_buffer, **kwargs)


def create_language_server(debug_log=False, settings=None):
    """Create and configure a Suricata Language Server instance."""
    server = SuricataLanguageServer("suricata-language-server", "v1.0")
    
    # Get launch settings
    if settings is None:
        settings = {}
    server.nthreads = settings.get("nthreads", 4)
    server.notify_init = settings.get("notify_init", False)
    server.sync_type = settings.get("sync_type", 1)
    server.suricata_binary = settings.get("suricata_binary", "suricata")
    server.suricata_config = settings.get("suricata_config", None)
    server.max_lines = settings.get("max_lines", 1000)
    server.max_tracked_files = settings.get("max_tracked_files", 100)
    server.docker = settings.get("docker_mode", False)
    server.docker_image = settings.get(
        "docker_image", SuriCmd.SLS_DEFAULT_DOCKER_IMAGE
    )
    server.debug_log = debug_log
    
    # Register handlers
    @server.feature(INITIALIZED)
    async def server_initialized(ls: SuricataLanguageServer, params: InitializedParams):
        """Initialize the rules tester after server initialization."""
        progress_token = str(uuid.uuid4())
        await ls.progress.create_async(progress_token)
        ls.progress.begin(
            progress_token,
            WorkDoneProgressBegin(
                title="Suricata Container Init",
                message="Initializing Suricata container and potentially fetching image",
                cancellable=False,
            )
        )

        ls.rules_tester = ls.create_rule_tester()
        ls.progress.report(
            progress_token,
            WorkDoneProgressReport(
                percentage=80,
                message=f"Suricata v{ls.rules_tester.suricata_version} container ready.",
            )
        )

        ls.keywords_list = ls.rules_tester.build_keywords_list()
        ls.progress.report(
            progress_token,
            WorkDoneProgressReport(
                percentage=90,
                message="Suricata keywords fetched.",
            )
        )
        ls.app_layer_list = ls.rules_tester.build_app_layer_list()
        ls.progress.end(
            progress_token,
            WorkDoneProgressEnd(message="Suricata Language Server ready.")
        )

    @server.feature(TEXT_DOCUMENT_COMPLETION)
    def completions(ls: SuricataLanguageServer, params: CompletionParams):
        """Provide completion items."""
        uri = params.text_document.uri
        path = to_fs_path(uri)
        file_obj = ls.workspace_files.get(path)
        if file_obj is None:
            return None
        edit_index = params.position.line
        sig_content = file_obj.contents_split[edit_index]
        sig_index = params.position.character
        log.debug(sig_content)
        # not yet in content matching so just return nothing
        if "(" not in sig_content[0:sig_index]:
            return ls._initial_params_autocomplete(params, file_obj)
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
        for item in ls.keywords_list:
            if item["label"].startswith(partial_keyword):
                items_list.append(CompletionItem(**item))
        if len(items_list):
            return items_list
        return None

    @server.feature(TEXT_DOCUMENT_DID_OPEN)
    async def did_open(ls: SuricataLanguageServer, params: DidOpenTextDocumentParams):
        """Handle document open."""
        uri = params.text_document.uri
        filepath = to_fs_path(uri)
        
        # Skip update and remove objects if file is deleted
        if not os.path.isfile(filepath):
            return
        
        progress_token = str(uuid.uuid4())
        await ls.progress.create_async(progress_token)
        ls.progress.begin(
            progress_token,
            WorkDoneProgressBegin(
                title="File analysis",
                message="File analysis in progress",
                cancellable=False,
            )
        )

        did_change, err_str = ls.update_workspace_file(
            filepath, read_file=True, allow_empty=True
        )
        ls.progress.end(
            progress_token,
            WorkDoneProgressEnd(message="File analysis done")
        )

        if err_str is not None:
            ls.post_message(
                'Open request failed for file "{0}": {1}'.format(filepath, err_str),
                MessageType.Error
            )
            return
        if did_change:
            ls.send_diagnostics(uri)

    @server.feature(TEXT_DOCUMENT_DID_SAVE)
    async def did_save(ls: SuricataLanguageServer, params: DidSaveTextDocumentParams):
        """Handle document save."""
        uri = params.text_document.uri
        filepath = to_fs_path(uri)
        
        # Skip update and remove objects if file is deleted
        if not os.path.isfile(filepath):
            return
        
        progress_token = str(uuid.uuid4())
        await ls.progress.create_async(progress_token)
        ls.progress.begin(
            progress_token,
            WorkDoneProgressBegin(
                title="File analysis",
                message="File analysis in progress",
                cancellable=False,
            )
        )

        did_change, err_str = ls.update_workspace_file(
            filepath, read_file=True, allow_empty=False
        )
        ls.progress.end(
            progress_token,
            WorkDoneProgressEnd(message="File analysis done")
        )

        if err_str is not None:
            ls.post_message(
                'Save request failed for file "{0}": {1}'.format(filepath, err_str),
                MessageType.Error
            )
            return
        if did_change:
            ls.send_diagnostics(uri)

    @server.feature(TEXT_DOCUMENT_DID_CLOSE)
    def did_close(ls: SuricataLanguageServer, params: DidCloseTextDocumentParams):
        """Handle document close."""
        uri = params.text_document.uri
        filepath = to_fs_path(uri)
        # For now, we keep the file in workspace even when closed
        # This matches the original behavior

    @server.feature(TEXT_DOCUMENT_DID_CHANGE)
    def did_change(ls: SuricataLanguageServer, params: DidChangeTextDocumentParams):
        """Handle document change."""
        uri = params.text_document.uri
        path = to_fs_path(uri)
        file_obj = ls.workspace_files.get(path)
        if file_obj is None:
            ls.post_message(
                'Change request failed for unknown file "{0}"'.format(path),
                MessageType.Error
            )
            log.error('Change request failed for unknown file "%s"', path)
            return
        else:
            # Update file contents with changes
            reparse_req = True
            if ls.sync_type == 1:
                # Full sync
                if len(params.content_changes) > 0:
                    file_obj.apply_change(params.content_changes[0])
            else:
                # Incremental sync
                try:
                    reparse_req = False
                    for change in params.content_changes:
                        reparse_flag = file_obj.apply_change(change)
                        reparse_req = reparse_req or reparse_flag
                # pylint: disable=W0703
                except Exception:
                    ls.post_message(
                        'Change request failed for file "{0}": Could not apply change'.format(
                            path
                        ),
                        MessageType.Error
                    )
                    log.error(
                        'Change request failed for file "%s": Could not apply change',
                        path,
                        exc_info=True,
                    )
                    return
        # Parse newly updated file
        if reparse_req:
            _, err_str = ls.update_workspace_file(path)
            if err_str is not None:
                ls.post_message(
                    'Change request failed for file "{0}": {1}'.format(path, err_str),
                    MessageType.Error
                )

    @server.feature(TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL)
    def semantic_tokens(ls: SuricataLanguageServer, params: SemanticTokensParams):
        """Provide semantic tokens for the full document."""
        uri = params.text_document.uri
        path = to_fs_path(uri)
        file_obj = ls.workspace_files.get(path)
        if file_obj is None:
            return SemanticTokens(data=[])
        # Add scopes to outline view
        tokens = file_obj.get_semantic_tokens()
        return SemanticTokens(data=tokens.get("data", []))

    @server.feature(TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE)
    def semantic_tokens_range(ls: SuricataLanguageServer, params: SemanticTokensRangeParams):
        """Provide semantic tokens for a range."""
        uri = params.text_document.uri
        path = to_fs_path(uri)
        file_obj = ls.workspace_files.get(path)
        if file_obj is None:
            return SemanticTokens(data=[])
        # Add scopes to outline view
        tokens = file_obj.get_semantic_tokens(file_range=params.range)
        return SemanticTokens(data=tokens.get("data", []))

    @server.feature("initialize")
    def initialize(ls: SuricataLanguageServer, params: InitializeParams):
        """Handle initialization request."""
        # Setup language server
        ls.root_path = to_fs_path(
            params.root_uri or params.root_path or ""
        )
        ls.source_dirs.append(ls.root_path)
        # Recursively add sub-directories
        if len(ls.source_dirs) == 1:
            ls.source_dirs = []
            for dirName, subdirList, fileList in os.walk(ls.root_path):
                if ls.excl_paths.count(dirName) > 0:
                    while len(subdirList) > 0:
                        del subdirList[0]
                    continue
                contains_source = False
                for filename in fileList:
                    _, ext = os.path.splitext(os.path.basename(filename))
                    if SURICATA_RULES_EXT_REGEX.match(ext):
                        contains_source = True
                        break
                if contains_source:
                    ls.source_dirs.append(dirName)
        # Initialize workspace
        ls.workspace_init()
        
        if ls.notify_init:
            ls.post_messages.append([MessageType.Info, "suricatals initialization complete"])

    return server
