# Workspace SID Conflict Detection - Features

## Overview

The Suricata Language Server now provides **automatic SID conflict detection** across workspace files with **real-time diagnostic updates** when the workspace changes.

## Key Features

### 1. Workspace-Wide SID Tracking

When a workspace folder is opened:
- All `.rules` files are analyzed in parallel (4+ worker threads)
- SIDs from all files are extracted and cached
- Analysis completes in the background with progress reporting

### 2. Cross-File Conflict Detection

When editing a rules file:
- Language server checks for SID conflicts with other workspace files
- Conflicts generate **LSP warning diagnostics** at the SID location
- Warnings show which files contain the conflicting SID

**Example Diagnostic:**
```
⚠️  Line 5: SID 2025002 conflicts with signature(s) in: emerging-threats.rules
```

### 3. Automatic Diagnostic Refresh

**NEW:** When workspace changes, open files are automatically updated:

#### Triggers
- ✅ Workspace folder added → All .rules files analyzed → Open files refreshed
- ✅ Workspace folder removed → MPM cache updated → Open files refreshed
- ✅ Workspace analysis completes → Open files refreshed

#### Benefits
- **No manual file reload required**
- **Instant feedback** when adding/removing rulesets
- **Real-time conflict resolution** when editing across multiple files

### 4. Intelligent Cache Management

The language server maintains a workspace-wide cache:
- **Thread-safe**: Multiple files can be checked simultaneously
- **Efficient**: Only SIDs are tracked (not full rule content)
- **Automatic updates**: Cache updates when files are saved
- **Smart exclusion**: Files don't report conflicts with themselves

## Example Workflow

```
1. User opens workspace folder:
   📁 /rules/
   ├── emerging-threats.rules (SIDs: 2025001-2025005, 1000001)
   └── local-custom.rules     (SIDs: 1000001-1000005, 2025002)

2. Language server analyzes workspace:
   ⏳ Analyzing 2 files...
   ✓ Workspace analysis complete: 10 SIDs tracked

3. User opens local-custom.rules:
   📄 File opened
   🔍 Checking for conflicts...
   ⚠️  SID 1000001 conflicts with emerging-threats.rules
   ⚠️  SID 2025002 conflicts with emerging-threats.rules

4. User adds another workspace folder:
   📁 /rules-2/ added
   ⏳ Analyzing new workspace files...
   ✓ Analysis complete
   🔄 Automatically refreshing open files...
   ⚠️  New conflicts detected (if any)
```

## Configuration

### Workspace Analysis Settings

Controlled by LangServer initialization parameters:
- `nthreads`: Number of parallel workers (default: 4)
- `source_dirs`: List of workspace folder paths
- `workspace_mpm`: MpmCache instance for SID tracking

### Performance

Typical performance (Suricata 7.0+):
- **Workspace analysis**: 100 files in ~2 minutes (parallel)
- **Individual file check**: <1 second
- **Diagnostic refresh**: <500ms per open file

## Implementation Details

### Core Components

1. **MpmCache** (`src/suricatals/mpm_cache.py`)
   - `get_sid_conflicts()`: Find conflicts between current and workspace SIDs
   - Thread-safe dictionary with reentrant locks

2. **SuricataFile** (`src/suricatals/signature_parser.py`)
   - `_compute_sid_conflicts()`: Compare file SIDs against workspace
   - `build_sid_conflict_diagnostics()`: Generate LSP diagnostics

3. **LangServer** (`src/suricatals/langserver.py`)
   - `_refresh_open_file_diagnostics()`: Auto-update open files
   - Called after workspace analysis and folder changes

### Data Flow

```
Workspace Analysis
─────────────────────────────────────────────────
workspace_did_change_folders()
    ↓
analyze_workspace_files()  [parallel workers]
    ↓
workspace_mpm.add_file()   [for each file]
    ↓
_finalize_workspace_analysis()
    ↓
_refresh_open_file_diagnostics()  [NEW]
    ↓
text_document_publish_diagnostics()  [for each open file]


File Check
─────────────────────────────────────────────────
text_document_did_save()
    ↓
get_diagnostics()
    ↓
check_lsp_file(workspace=workspace_mpm.get_workspace_view())
    ↓
build_all_diags() → _compute_sid_conflicts() → build_sid_conflict_diagnostics()
    ↓
text_document_publish_diagnostics()
```

## Testing

### Test Coverage

- ✅ 18 unit tests (test_sid_conflicts.py, test_workspace_conflicts.py)
- ✅ Integration tests (test_workspace_integration.py)
- ✅ Auto-refresh tests (test_refresh_diagnostics.py)
- ✅ Complete workflow demo (test_complete_workflow.py)

### Test Workspace

This directory (`workspace_conflict_test/`) contains:
- 2 test files with intentional SID conflicts
- Expected conflicts: SID 1000001 and 2025002
- Used by all integration tests

## Future Enhancements

Potential improvements:
- [ ] Configurable conflict severity (warning vs error)
- [ ] Quick-fix actions (auto-increment SID, show all conflicts)
- [ ] Conflict resolution UI (suggest available SID ranges)
- [ ] Export conflict report (markdown/JSON)
