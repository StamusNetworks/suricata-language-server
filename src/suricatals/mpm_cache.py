"""
MPM Cache management for cross-file pattern collision detection.

Copyright(C) 2026 Stamus Networks SAS
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
from typing import Dict, Optional, List, Any
from threading import RLock

log = logging.getLogger(__name__)


class MpmCache:
    """
    Thread-safe cache for Multi-Pattern Matching (MPM) data across workspace files.

    Stores MPM analysis results for fast pattern collision detection across
    multiple rules files. The cache is populated during workspace analysis
    and queried during individual file diagnostics.

    Data structure:
        {
            filepath: {
                "buffer": {
                    buffer_name: {
                        pattern: {"count": int, ...},
                        ...
                    },
                    ...
                },
                "sids": {
                    sid: {"buffer": str, "pattern": str, "count": int, ...},
                    ...
                }
            },
            ...
        }

    Example:
        cache = MpmCache()
        cache.add_file("/path/to.rules", s_file)

        # Query for cross-file pattern analysis
        pattern_count = cache.get_pattern_usage(
            buffer="http_uri",
            pattern="/api/v1/",
            exclude_file="/current/file.rules"
        )
    """

    def __init__(self):
        """Initialize an empty MPM cache with thread safety."""
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()  # Reentrant lock for nested operations

    def add_file(self, filepath: str, mpm_data: Dict[str, Any]) -> bool:
        """
        Add or update MPM data for a single file.

        Args:
            filepath: Absolute path to rules file
            mpm_data: Dict with keys "buffer" (file-level MPM) and "sids" (per-signature MPM)
                     Expected structure: {"buffer": {...}, "sids": {...}}

        Returns:
            True if data was added, False if mpm_data was invalid
        """
        if not mpm_data or not isinstance(mpm_data, dict):
            return False

        if "buffer" not in mpm_data:
            log.warning("MPM data for %s missing 'buffer' key", filepath)
            return False

        with self._lock:
            self._data[filepath] = {
                "buffer": mpm_data.get("buffer", {}),
                "sids": mpm_data.get("sids", {}),
            }

        log.debug(
            "Added MPM data for %s (%d sids)", filepath, len(mpm_data.get("sids", {}))
        )
        return True

    def add_file_from_suricata_file(self, filepath: str, s_file: Any) -> bool:
        """
        Extract and add MPM data from a SuricataFile object.

        Args:
            filepath: Absolute path to rules file
            s_file: SuricataFile object with mpm attribute and sigset.signatures

        Returns:
            True if MPM data was extracted and stored, False otherwise
        """
        if not (s_file and hasattr(s_file, "mpm") and s_file.mpm):
            return False

        mpm_data = {"buffer": s_file.mpm, "sids": {}}

        # Extract per-signature info (all SIDs for conflict detection, not just those with MPM)
        if hasattr(s_file, "sigset") and hasattr(s_file.sigset, "signatures"):
            for sig in s_file.sigset.signatures:
                if hasattr(sig, "sid") and sig.sid != 0:
                    # Store MPM data if available, otherwise store empty dict
                    mpm_data["sids"][sig.sid] = (
                        sig.mpm if hasattr(sig, "mpm") and sig.mpm else {}
                    )

        return self.add_file(filepath, mpm_data)

    def remove_file(self, filepath: str) -> bool:
        """
        Remove MPM data for a single file.

        Args:
            filepath: Absolute path to rules file

        Returns:
            True if file was in cache and removed, False otherwise
        """
        with self._lock:
            if filepath in self._data:
                del self._data[filepath]
                log.debug("Removed MPM data for %s", filepath)
                return True
        return False

    def remove_by_prefix(self, path_prefix: str) -> int:
        """
        Remove all files under a directory path.

        Useful when a workspace folder is removed.

        Args:
            path_prefix: Directory path prefix (e.g., "/workspace/rules/")

        Returns:
            Number of files removed
        """
        with self._lock:
            files_to_remove = [
                fp for fp in self._data.keys() if fp.startswith(path_prefix)
            ]

            for fp in files_to_remove:
                del self._data[fp]

            if files_to_remove:
                log.info(
                    "Removed MPM data for %d files with prefix %s",
                    len(files_to_remove),
                    path_prefix,
                )

            return len(files_to_remove)

    def get_file_data(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Get MPM data for a specific file.

        Args:
            filepath: Absolute path to rules file

        Returns:
            Dict with "buffer" and "sids" keys, or None if not found
        """
        with self._lock:
            return self._data.get(filepath)

    def get_all_files(self) -> List[str]:
        """
        Get list of all files in the cache.

        Returns:
            List of absolute file paths
        """
        with self._lock:
            return list(self._data.keys())

    def get_workspace_view(
        self, exclude_file: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get workspace MPM data for cross-file analysis.

        This returns a dict suitable for passing to SuricataFile.check_file()
        as the workspace parameter.

        Args:
            exclude_file: Optional filepath to exclude from results

        Returns:
            Dict mapping filepath -> {"buffer": {...}, "sids": {...}}
        """
        with self._lock:
            if exclude_file:
                return {
                    fp: data for fp, data in self._data.items() if fp != exclude_file
                }
            return self._data.copy()

    def get_pattern_usage(
        self, buffer: str, pattern: str, exclude_file: Optional[str] = None
    ) -> int:
        """
        Count how many times a pattern appears on a buffer across all files.

        Args:
            buffer: MPM buffer name (e.g., "http_uri", "http_header")
            pattern: Pattern string to search for
            exclude_file: Optional filepath to exclude from count

        Returns:
            Total count of pattern usage across workspace
        """
        count = 0
        with self._lock:
            for filepath, data in self._data.items():
                if exclude_file and filepath == exclude_file:
                    continue

                buffer_data = data.get("buffer", {})
                buffer_patterns = buffer_data.get(buffer, {})

                if pattern in buffer_patterns:
                    pattern_info = buffer_patterns[pattern]
                    if isinstance(pattern_info, dict) and "count" in pattern_info:
                        count += pattern_info["count"]

        return count

    def get_sid_conflicts(
        self, current_file_sids: Dict[int, Any], exclude_file: Optional[str] = None
    ) -> Dict[int, List[str]]:
        """
        Find SID conflicts between current file and workspace files.

        Args:
            current_file_sids: Dict mapping SID -> signature info for current file
            exclude_file: Optional filepath to exclude from conflict detection

        Returns:
            Dict mapping conflicting SID -> list of filepaths where it appears
            Only includes SIDs that appear in both current file and other workspace files
        """
        conflicts = {}
        with self._lock:
            for sid in current_file_sids.keys():
                if sid == 0:  # Skip signatures without SID
                    continue

                conflicting_files = []
                for filepath, data in self._data.items():
                    if exclude_file and filepath == exclude_file:
                        continue

                    sids_data = data.get("sids", {})
                    if sid in sids_data:
                        conflicting_files.append(filepath)

                if conflicting_files:
                    conflicts[sid] = conflicting_files

        return conflicts

    def clear(self):
        """Clear all MPM data from cache."""
        with self._lock:
            file_count = len(self._data)
            self._data.clear()
            if file_count > 0:
                log.info("Cleared MPM cache (%d files)", file_count)

    def get_statistics(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dict with keys:
                - file_count: Number of files in cache
                - total_sids: Total number of signatures across all files
                - files_with_mpm: Number of files with non-empty MPM data
        """
        with self._lock:
            total_sids = sum(len(data.get("sids", {})) for data in self._data.values())
            files_with_mpm = sum(
                1 for data in self._data.values() if data.get("buffer")
            )

            return {
                "file_count": len(self._data),
                "total_sids": total_sids,
                "files_with_mpm": files_with_mpm,
            }

    def __len__(self) -> int:
        """Return number of files in cache."""
        with self._lock:
            return len(self._data)

    def __contains__(self, filepath: str) -> bool:
        """Check if a file is in the cache."""
        with self._lock:
            return filepath in self._data

    def __repr__(self) -> str:
        stats = self.get_statistics()
        return (
            f"MpmCache(files={stats['file_count']}, "
            f"sids={stats['total_sids']}, "
            f"with_mpm={stats['files_with_mpm']})"
        )
