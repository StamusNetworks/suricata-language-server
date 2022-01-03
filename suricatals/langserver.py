import logging
import os
import traceback
import re

from suricatals.jsonrpc import path_from_uri
from suricatals.parse_signatures import SuricataFile
from suricatals.tests_rules import TestRules

log = logging.getLogger(__name__)

SURICATA_RULES_EXT_REGEX = re.compile(r'^\.rules?$', re.I)

def init_file(filepath, suricata_binary):
    file_obj = SuricataFile(filepath, suricata_binary=suricata_binary)
    err_str = file_obj.load_from_disk()
    if err_str is not None:
        return None, err_str
    #
    return file_obj, None


class LangServer:
    def __init__(self, conn, debug_log=False, settings={}):
        self.conn = conn
        self.running = True
        self.root_path = None
        self.fs = None
        self.workspace = {}
        self.source_dirs = []
        self.excl_paths = []
        self.excl_suffixes = []
        self.post_messages = []
        self.streaming = True
        self.debug_log = debug_log
        # Get launch settings
        self.nthreads = settings.get("nthreads", 4)
        self.notify_init = settings.get("notify_init", False)
        self.sync_type = settings.get("sync_type", 1)
        self.suricata_binary = settings.get("suricata_binary", 'suricata')
        self.max_lines = settings.get("max_lines", 1000)
        self.keywords_list = TestRules(suricata_binary=self.suricata_binary).build_keywords_list()

    def post_message(self, message, type=1):
        self.conn.send_notification("window/showMessage", {
            "type": type,
            "message": message
        })

    def run(self):
        # Run server
        while self.running:
            try:
                request = self.conn.read_message()
                self.handle(request)
            except EOFError:
                break
            except Exception as e:
                log.error("Unexpected error: %s", e, exc_info=True)
                break
            else:
                for message in self.post_messages:
                    self.post_message(message[1], message[0])
                self.post_messages = []

    def handle(self, request):
        def noop(request):
            return None
        # Request handler
        log.debug("REQUEST %s %s", request.get("id"), request.get("method"))
        handler = {
            "initialize": self.serve_initialize,
            "textDocument/documentSymbol": noop,
            "textDocument/completion": self.serve_autocomplete,
            "textDocument/signatureHelp": noop,
            "textDocument/definition": noop,
            "textDocument/references": noop,
            "textDocument/hover": noop,
            "textDocument/implementation": noop,
            "textDocument/rename": noop,
            "textDocument/didOpen": self.serve_onOpen,
            "textDocument/didSave": self.serve_onSave,
            "textDocument/didClose": self.serve_onClose,
            "textDocument/didChange": self.serve_onChange,
            "textDocument/codeAction": noop,
            "initialized": noop,
            "workspace/didChangeWatchedFiles": noop,
            "workspace/symbol": noop,
            "$/cancelRequest": noop,
            "shutdown": noop,
            "exit": self.serve_exit,
        }.get(request["method"], self.serve_default)
        # handler = {
        #     "workspace/symbol": self.serve_symbols,
        # }.get(request["method"], self.serve_default)
        # We handle notifications differently since we can't respond
        if "id" not in request:
            try:
                handler(request)
            except:
                log.warning(
                    "error handling notification %s", request, exc_info=True)
            return
        #
        try:
            resp = handler(request)
        except JSONRPC2Error as e:
            self.conn.write_error(
                request["id"], code=e.code, message=e.message, data=e.data)
            log.warning("RPC error handling request %s", request, exc_info=True)
        except Exception as e:
            self.conn.write_error(
                request["id"],
                code=-32603,
                message=str(e),
                data={
                    "traceback": traceback.format_exc(),
                })
            log.warning("error handling request %s", request, exc_info=True)
        else:
            self.conn.write_response(request["id"], resp)

    def serve_initialize(self, request):
        # Setup language server
        params = request["params"]
        self.root_path = path_from_uri(
            params.get("rootUri") or params.get("rootPath") or "")
        self.source_dirs.append(self.root_path)
        # Check for config file
        config_path = os.path.join(self.root_path, ".suricatals")
        config_exists = os.path.isfile(config_path)
        if config_exists:
            try:
                import json
                with open(config_path, 'r') as fhandle:
                    config_dict = json.load(fhandle)
                    for excl_path in config_dict.get("excl_paths", []):
                        self.excl_paths.append(os.path.join(self.root_path, excl_path))
                    source_dirs = config_dict.get("source_dirs", [])
                    ext_source_dirs = config_dict.get("ext_source_dirs", [])
                    # Legacy definition
                    if len(source_dirs) == 0:
                        source_dirs = config_dict.get("mod_dirs", [])
                    for source_dir in source_dirs:
                        dir_path = os.path.join(self.root_path, source_dir)
                        if os.path.isdir(dir_path):
                            self.source_dirs.append(dir_path)
                        else:
                            self.post_messages.append(
                                [2, r'Source directory "{0}" specified in '
                                 r'".suricatals" settings file does not exist'.format(dir_path)]
                            )
                    for ext_source_dir in ext_source_dirs:
                        if os.path.isdir(ext_source_dir):
                            self.source_dirs.append(ext_source_dir)
                        else:
                            self.post_messages.append(
                                [2, r'External source directory "{0}" specified in '
                                 r'".suricatals" settings file does not exist'.format(ext_source_dir)]
                            )
            except:
                self.post_messages.append([1, 'Error while parsing ".suricatals" settings file'])
        # Recursively add sub-directories
        if len(self.source_dirs) == 1:
            self.source_dirs = []
            for dirName, subdirList, fileList in os.walk(self.root_path):
                if self.excl_paths.count(dirName) > 0:
                    while(len(subdirList) > 0):
                        del subdirList[0]
                    continue
                contains_source = False
                for filename in fileList:
                    _, ext = os.path.splitext(os.path.basename(filename))
                    if SURICATA_RULES_EXT_REGEX.match(ext):
                        contains_source = True
                        break
                if contains_source:
                    self.source_dirs.append(dirName)
        # Initialize workspace
        self.workspace_init()
        #
        server_capabilities = {
            "completionProvider": {
                "resolveProvider": False,
                "triggerCharacters": ["%"]
            },
            #"definitionProvider": True,
            #"documentSymbolProvider": True,
            #"referencesProvider": True,
            #"hoverProvider": True,
            #"implementationProvider": True,
            #"renameProvider": True,
            #"workspaceSymbolProvider": True,
            "textDocumentSync": self.sync_type
        }
        if self.notify_init:
            self.post_messages.append([3, "suricatals initialization complete"])
        return {"capabilities": server_capabilities}
        #     "workspaceSymbolProvider": True,
        #     "streaming": False,
        # }

    def serve_autocomplete(self, request):
        params = request["params"]
        uri = params["textDocument"]["uri"]
        path = path_from_uri(uri)
        file_obj = self.workspace.get(path)
        if file_obj is None:
            return None
        sig_content = file_obj.line_content_map[params['position']['line']]
        sig_index = params['position']['character'] 
        log.debug(sig_content)
        # not yet in content matching so just return nothing
        if not '(' in sig_content[0:sig_index]:
            return None
        cursor = sig_index - 1
        while cursor > 0:
            log.debug("At index: %d of %d (%s)" % (cursor, len(sig_content), sig_content[cursor:sig_index]))
            if not sig_content[cursor].isalnum() and not sig_content[cursor] in ['.', '_']:
                break
            cursor -= 1
        log.debug("Final is: %d : %d" % (cursor, sig_index))
        if cursor == sig_index - 1:
            return None
        # this is an option edit so dont list keyword
        if sig_content[cursor] in [':', ',']:
            return None
        cursor += 1
        partial_keyword = sig_content[cursor:sig_index]
        log.debug("Got keyword start: '%s'" % (partial_keyword))
        items_list = []
        for item in self.keywords_list:
            if item['label'].startswith(partial_keyword):
                items_list.append(item)
        if len(items_list):
            return items_list
        return None

    def send_diagnostics(self, uri):
        diag_results, diag_exp = self.get_diagnostics(uri)
        if diag_results is not None:
            self.conn.send_notification("textDocument/publishDiagnostics", {
                "uri": uri,
                "diagnostics": diag_results
            })
        elif diag_exp is not None:
            self.conn.write_error(
                -1,
                code=-32603,
                message=str(diag_exp),
                data={
                    "traceback": traceback.format_exc(),
                })

    def get_diagnostics(self, uri):
        filepath = path_from_uri(uri)
        file_obj = self.workspace.get(filepath)
        if file_obj is not None and file_obj.nLines < self.max_lines:
            try:
                diags = file_obj.check_file()
            except Exception as e:
                if os.path.isfile(file_obj.path):
                    return None, e
                else:
                    return None, None
            else:
                return diags, None
        return None, None

    def serve_onChange(self, request):
        # Update workspace from file sent by editor
        params = request["params"]
        uri = params["textDocument"]["uri"]
        path = path_from_uri(uri)
        file_obj = self.workspace.get(path)
        if file_obj is None:
            self.post_message('Change request failed for unknown file "{0}"'.format(path))
            log.error('Change request failed for unknown file "%s"', path)
            return
        else:
            # Update file contents with changes
            reparse_req = True
            if self.sync_type == 1:
                file_obj.apply_change(params["contentChanges"][0])
            else:
                try:
                    reparse_req = False
                    for change in params["contentChanges"]:
                        reparse_flag = file_obj.apply_change(change)
                        reparse_req = (reparse_req or reparse_flag)
                except:
                    self.post_message('Change request failed for file "{0}": Could not apply change'.format(path))
                    log.error('Change request failed for file "%s": Could not apply change', path, exc_info=True)
                    return
        # Parse newly updated file
        if reparse_req:
            _, err_str = self.update_workspace_file(path)
            if err_str is not None:
                self.post_message('Change request failed for file "{0}": {1}'.format(path, err_str))
                return

    def serve_onOpen(self, request):
        self.serve_onSave(request, did_open=True)

    def serve_onClose(self, request):
        self.serve_onSave(request, did_close=True)

    def serve_onSave(self, request, did_open=False, did_close=False):
        # Update workspace from file on disk
        params = request["params"]
        uri = params["textDocument"]["uri"]
        filepath = path_from_uri(uri)
        # Skip update and remove objects if file is deleted
        if did_close and (not os.path.isfile(filepath)):
            return
        did_change, err_str = self.update_workspace_file(filepath, read_file=True, allow_empty=did_open)
        if err_str is not None:
            self.post_message('Save request failed for file "{0}": {1}'.format(filepath, err_str))
            return
        if did_change:
            file_obj = self.workspace.get(filepath)
        self.send_diagnostics(uri)

    def update_workspace_file(self, filepath, read_file=False, allow_empty=False):
        # Update workspace from file contents and path
        try:
            file_obj = self.workspace.get(filepath)
            if read_file:
                if file_obj is None:
                    file_obj = SuricataFile(filepath, suricata_binary=self.suricata_binary)
                    # Create empty file if not yet saved to disk
                    if not os.path.isfile(filepath):
                        if allow_empty:
                            self.workspace[filepath] = file_obj
                            return False, None
                        else:
                            return False, 'File does not exist'  # Error during load
                hash_old = file_obj.hash
                err_string = None
                if os.path.isfile(filepath):
                    err_string = file_obj.load_from_disk()
                    file_obj.parse_file()
                if err_string is not None:
                    log.error(err_string + ": %s", filepath)
                    return False, err_string  # Error during file read
                if hash_old == file_obj.hash:
                    return False, None
        except:
            log.error("Error while parsing file %s", filepath, exc_info=True)
            return False, 'Error during parsing'  # Error during parsing
        if filepath not in self.workspace:
            self.workspace[filepath] = file_obj
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
        from multiprocessing import Pool
        pool = Pool(processes=self.nthreads)
        results = {}
        for filepath in file_list:
            results[filepath] = pool.apply_async(init_file, args=(filepath, self.suricata_binary))
        pool.close()
        pool.join()
        for path, result in results.items():
            result_obj = result.get()
            if result_obj[0] is None:
                self.post_messages.append([1, 'Initialization failed for file "{0}": {1}'.format(path, result_obj[1])])
                continue
            self.workspace[path] = result_obj[0]

    def serve_exit(self, request):
        # Exit server
        self.workspace = {}
        self.running = False

    def serve_default(self, request):
        # Default handler (errors!)
        raise JSONRPC2Error(
            code=-32601,
            message="method {} not found".format(request["method"]))


class JSONRPC2Error(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data
