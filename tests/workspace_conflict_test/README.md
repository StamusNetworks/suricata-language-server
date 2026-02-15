# Workspace SID Conflict Detection Test

This directory contains test files for validating the workspace-wide SID conflict detection feature.

## Test Files

### emerging-threats.rules
Simulates rules from the Emerging Threats (ET) ruleset with SIDs in the 2025000 range and 1000000 range.

**SIDs in this file:**
- 1000001 - SQL Injection detection (⚠️ **CONFLICTS with local-custom.rules**)
- 2025001 - Malware C&C detection
- 2025002 - Suspicious SSL Certificate (⚠️ **CONFLICTS with local-custom.rules**)
- 2025003 - Nmap scan detection
- 2025005 - Malicious domain query

### local-custom.rules
Simulates local/custom rules written by users with SIDs in the 1000000 range.

**SIDs in this file:**
- 1000001 - SSH Brute Force (⚠️ **CONFLICTS with emerging-threats.rules**)
- 1000002 - RDP connection detection
- 1000003 - Suspicious User-Agent
- 1000005 - Data exfiltration detection
- 2025002 - TLS 1.0 detection (⚠️ **CONFLICTS with emerging-threats.rules**)

## Expected Behavior

When the language server analyzes this workspace:

1. **Workspace Analysis Phase**: Both files are scanned and their SIDs are cached
2. **File Check Phase**: When opening either file, the language server detects:
   - SID 1000001 conflicts (appears in both files)
   - SID 2025002 conflicts (appears in both files)

3. **Diagnostic Messages**: LSP warning diagnostics are generated:
   ```
   ⚠️  Line X: SID 1000001 conflicts with signature(s) in: local-custom.rules
   ⚠️  Line Y: SID 2025002 conflicts with signature(s) in: emerging-threats.rules
   ```

## Running Tests

### Integration Test
```bash
python tests/test_workspace_integration.py
```

### Pytest Suite
```bash
python -m pytest src/suricatals/test_workspace_conflicts.py -v
```

## Real-World Scenario

This simulates a common problem in Suricata deployments:

1. **Emerging Threats** ruleset uses SIDs 2000000-2999999
2. **Local/Custom** rules typically use 1000000-1999999
3. When organizations mix rulesets, SID collisions can occur:
   - Copy/pasting rules without updating SIDs
   - Reusing SIDs from old rules
   - Multiple teams creating rules independently

The language server now catches these conflicts automatically, preventing deployment issues.
