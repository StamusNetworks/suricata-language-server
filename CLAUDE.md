# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Suricata Language Server is a Language Server Protocol (LSP) implementation for Suricata IDS/IPS signature files. It provides syntax highlighting, auto-completion, semantic tokens, and diagnostics for `.rules` files by leveraging a Suricata binary (either local or in a Docker container).

Key architectural principle: The language server delegates signature validation and keyword discovery to Suricata itself, ensuring that syntax checking and auto-completion match the actual Suricata version being used.

## Development Commands

### Setup and Installation
```bash
# Install in development mode (editable install)
pip install -e .

# Install with system packages flag (for PEP 704 systems)
pip install --break-system-packages .

# Install pre-commit hooks (required for development)
pre-commit install
```

### Testing and Validation
```bash
# Run unit tests
python -m pytest src/suricatals/unit_tests.py

# Test in batch mode (parse single file and output diagnostics)
suricata-language-server --batch-file tests/clean.rules

# Test with container mode
suricata-language-server --container --batch-file tests/clean.rules

# Test without engine analysis
suricata-language-server --batch-file tests/clean.rules --no-engine-analysis
```

### Running the Server
```bash
# Standard mode (expects Suricata binary in PATH)
suricata-language-server

# With custom Suricata binary
suricata-language-server --suricata-binary=/path/to/suricata

# Container mode (uses Docker)
suricata-language-server --container --image=jasonish/suricata:7.0.13

# With debug logging
suricata-language-server --debug-log
```

### Code Quality
```bash
# Format code with Black
black src/

# Check code with pylint
pylint --disable=C,R src/suricatals

# Run pre-commit checks manually
pre-commit run --all-files
```

## Architecture

### Core Components

1. **LangServer** (`src/suricatals/langserver.py`)
   - Main LSP server implementation using pygls (v2.0+)
   - Registers LSP features using the `@register_feature` decorator pattern
   - Coordinates between LSP protocol handlers and Suricata validation
   - Handles initialization, text document events, completion, and semantic tokens

2. **SuriCmd** (`src/suricatals/suri_cmd.py`)
   - Abstraction layer for running Suricata commands
   - Supports both local binary execution and Docker container mode
   - Manages temporary directories for Suricata config/rules during validation
   - Generates dynamic Suricata YAML configs with embedded reference/classification configs

3. **TestRules** (`src/suricatals/tests_rules.py`)
   - Executes Suricata syntax checks and engine analysis
   - Parses Suricata JSON output (errors, warnings, engine analysis)
   - Builds keyword and app-layer protocol lists for auto-completion
   - Handles special SLS directives embedded in rule files (see below)

4. **SuricataFile** (`src/suricatals/parse_signatures.py`)
   - Represents a Suricata rules file
   - Parses individual signatures (including multiline rules)
   - Manages signature metadata (sid, rev, content patterns)
   - Converts Suricata diagnostics to LSP diagnostic format

5. **SuricataSemanticTokenParser** (`src/suricatals/tokenize_sig.py`)
   - Tokenizes Suricata signatures for semantic highlighting
   - Identifies keywords, actions, strings, operators, etc.

6. **Worker Pool** (`src/suricatals/worker_pool.py`)
   - Module-level worker function for parallel workspace analysis
   - Analyzes individual rules files in separate processes
   - Returns MPM data structure for cross-file analysis

### Multiprocessing Architecture

When a workspace folder is added (via `WORKSPACE_DID_CHANGE_WORKSPACE_FOLDERS`), the language server analyzes all `.rules` files to extract MPM (Multi-Pattern Matching) information for cross-file pattern collision detection.

**Parallel Processing:**
- Uses `ProcessPoolExecutor` with `nthreads` workers (default: 4)
- Each worker process analyzes files independently
- Worker function (`analyze_file_worker`) creates its own TestRules instance
- Docker mode: Each worker creates its own docker client (no shared state)
- Results aggregated via futures and stored in `workspace_mpm` dict

**Key Features:**
- Always uses parallel processing for workspace analysis
- Expected 3-4x speedup for large rulesets (e.g., 100 files in ~2 minutes vs ~8 minutes sequential)
- Progress reporting via multiprocessing Queue
- Per-file timeout: 5 minutes
- Automatic fallback to sequential processing on critical errors
- Error-tolerant: Failed files logged but don't block other files

**Architecture Details:**
- TestRules.__getstate__/__setstate__ handles pickling by removing/recreating SuriCmd
- Each worker process gets its own docker client via `docker.from_env()`
- Temporary directories isolated per worker (no file conflicts)
- Progress updates sent via Queue, main thread updates LSP progress API
- Results: `{filepath: {"buffer": {...}, "sids": {...}}}`

### Key Data Flow

1. User saves `.rules` file in editor
2. LSP `TEXT_DOCUMENT_DID_SAVE` event triggers `serve_onSave()`
3. `get_diagnostics()` creates a `SuricataFile` and calls `check_lsp_file()`
4. `SuricataFile.check_file()` calls `TestRules.test()` which:
   - Creates a temporary directory via `SuriCmd.prepare()`
   - Generates Suricata config and writes rules to temp file
   - Runs `suricata -T` (config test) via `SuriCmd.run()`
   - If config test passes, runs engine analysis with `--engine-analysis`
   - Parses JSON output to extract errors, warnings, hints
5. Diagnostics are converted to LSP format and published to the editor

### SLS Directives (Special Comments)

The language server supports custom directives embedded in rule files as comments:

- `## SLS suricata-options: <options>` - Pass custom CLI options to Suricata
- `## SLS dataset-dir: /path/to/datasets/` - Set dataset file directory for validation
- `## SLS replace: foo bar` - Replace text in rules buffer before validation
- `## SLS suricata-version: 7.0.13` - Select specific Suricata version in container mode
- `## SLS pcap-file: tests/file.pcap` - Run signatures against a PCAP and report performance

These directives are parsed in `TestRules.get_sls_info()` and applied during validation.

### Decorator Pattern for LSP Features

The codebase uses a custom `@register_feature` decorator to register LSP handlers:

```python
@register_feature(types.TEXT_DOCUMENT_COMPLETION, options=types.CompletionOptions(...))
def serve_autocomplete(self, params):
    # Handler implementation
```

The `_register_all_features()` method in `LangServer.__init__()` discovers all decorated methods and registers them with the pygls server. This keeps feature registration declarative and co-located with implementation.

### Docker/Container Mode

When `--container` is enabled:
- `SuriCmd` uses the `docker` Python library to run Suricata in containers
- Temporary directories are mounted into containers at `/tmp/`
- Commands are adjusted to use internal container paths
- Image tags can be overridden per-file using `## SLS suricata-version:` directive

## Important Development Notes

### pygls Migration (v1.1 → v2.0+)

The project is currently on pygls 2.0+. Key differences from older versions:
- Protocol types moved from `pygls.lsp.types` to `lsprotocol.types`
- Feature registration uses `server.feature()` decorator, not `@server.feature()`
- The custom `@register_feature` decorator was created to maintain declarative registration

### URI to File Path Handling

The `path_from_uri()` helper handles cross-platform URI conversion, including:
- Windows UNC paths (`file://server/share`)
- Windows drive letters (`file:///C:/path`)
- Unix paths (`file:///path`)

Always use this helper when converting LSP URIs to filesystem paths.

### Temporary File Management

`SuriCmd` creates temporary directories for each validation run:
- `prepare()` - Creates temp dir
- `generate_config()` - Writes Suricata YAML, reference.config, classification.config
- `cleanup()` - Removes temp dir

Always call `cleanup()` in a finally block or use context managers to prevent temp dir leaks.

### Parsing Multiline Signatures

Suricata rules can span multiple lines when escaped with backslash. The `Signature` class handles this:
- Tracks line ranges (`line`, `line_end`)
- Stores both `raw_content` (line-by-line) and concatenated `content`
- Diagnostic ranges must map back to specific lines in `raw_content`

### Error Code Filtering

TestRules ignores certain Suricata error codes that aren't useful for LSP diagnostics:
- Error 40, 43, 44 (defined in `USELESS_ERRNO`) - Suppressed
- Error 101 (`VARIABLE_ERROR`) - Suricata config variable errors
- Error 41 (`OPENING_RULE_FILE`) - File references that don't exist
- Error 322 (`OPENING_DATASET_FILE`) - Dataset files that don't exist

## Testing Strategy

Tests are located in `src/suricatals/unit_tests.py` and use the `tests/*.rules` files:
- `clean.rules` - Valid signatures for positive tests
- `invalid-*.rules` - Various invalid syntax patterns
- `pattern-syntax.rules` - Edge cases for pattern matching
- `pcap.rules` - Rules with PCAP performance testing directives

Test execution requires Suricata to be installed or use `--container` mode.

## Package Structure

```
src/suricatals/
├── __init__.py          # Entry point (main() function)
├── langserver.py        # LSP server implementation
├── suri_cmd.py          # Suricata command execution abstraction
├── tests_rules.py       # Signature validation logic
├── parse_signatures.py  # Signature parsing and file representation
├── tokenize_sig.py      # Semantic tokenization
├── lsp_helpers.py       # LSP protocol helpers (Diagnosis, FileRange)
├── unit_tests.py        # Unit tests
└── data/
    └── suricata-keywords.json  # Cached keyword metadata
```

## Publishing

The package is published to PyPI as `suricata-language-server`. Version is defined in `pyproject.toml`.

Build and publish:
```bash
# Build distribution
python -m build

# Upload to PyPI (requires credentials)
python -m twine upload dist/*
```
