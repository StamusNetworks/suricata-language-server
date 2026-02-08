# Semantic Commit Messages

This branch uses semantic commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification.

## Commit History

1. **refactor: migrate from custom JSON-RPC to pygls framework**
   - Replaces custom JSON-RPC implementation with pygls library
   - Removes 315 lines of custom protocol code
   - Uses standard LSP types from lsprotocol

2. **fix: return InitializeResult from initialize handler**
   - Fixes critical bug where server didn't appear in LSP clients
   - Returns proper ServerCapabilities from initialize request

3. **chore: update pygls requirement to >=2.0.0**
   - Updates dependency from >=1.0.0 to >=2.0.0
   - Tested with pygls 2.0.1

## Format

Each commit follows the pattern:
```
<type>: <subject>

<body>

<footer>
```

Types used:
- `feat:` - New features
- `fix:` - Bug fixes
- `refactor:` - Code restructuring
- `chore:` - Maintenance tasks
