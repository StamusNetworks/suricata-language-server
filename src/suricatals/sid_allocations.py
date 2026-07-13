"""
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

import os
import time
import urllib.request
from bisect import bisect_right
from collections import Counter

import yaml

DEFAULT_ALLOCATIONS_URL = (
    "https://raw.githubusercontent.com/sidallocation/sidallocation.org/"
    "refs/heads/gh-pages/allocations.yml"
)

DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".cache", "suricata-language-server", "allocations.yml"
)
DEFAULT_CACHE_TTL = 7 * 24 * 3600  # one week

UNALLOCATED = "UNALLOCATED"


class SidAllocations:
    """Lookup a signature ID against the sidallocation.org registry."""

    def __init__(self, allocations):
        """Initialize from parsed YAML.

        Args:
            allocations: dict mapping allocation-key -> {org, name, ranges, ...}
        """
        self.allocations = allocations
        # Build a sorted list of (start, end_exclusive, key) tuples for bisect lookup.
        # Overlapping ranges are allowed by the upstream data; we return the first
        # matching range in sort order — sufficient for the summary use case.
        self._starts = []
        self._entries = []  # parallel list of (end_exclusive, key)
        for key, entry in allocations.items():
            for r in entry.get("ranges", []) or []:
                start = int(r["start"])
                size = int(r["size"])
                self._starts.append(start)
                self._entries.append((start + size, key))
        # Sort by start
        pairs = sorted(zip(self._starts, self._entries))
        self._starts = [p[0] for p in pairs]
        self._entries = [p[1] for p in pairs]

    @classmethod
    def load(cls, source=None, cache_path=None, cache_ttl=DEFAULT_CACHE_TTL):
        """Load allocations from a URL, filesystem path, or the default source.

        Args:
            source: URL, local file path, or None for the default upstream URL.
            cache_path: Optional path to cache the fetched YAML. Defaults to
                ~/.cache/suricata-language-server/allocations.yml when source
                is a URL.
            cache_ttl: How old the cache can be before re-fetching (seconds).

        Returns:
            SidAllocations instance.
        """
        source = source or DEFAULT_ALLOCATIONS_URL

        if os.path.isfile(source):
            with open(source, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            return cls(data.get("allocations", {}))

        cache_path = cache_path or DEFAULT_CACHE_PATH
        text = _load_via_cache(source, cache_path, cache_ttl)
        data = yaml.safe_load(text)
        return cls(data.get("allocations", {}))

    def lookup(self, sid):
        """Return the allocation key for the given SID, or None if unallocated.

        Args:
            sid: integer SID

        Returns:
            allocation key (str) or None
        """
        if not self._starts:
            return None
        # Find the rightmost start that is <= sid
        idx = bisect_right(self._starts, sid) - 1
        if idx < 0:
            return None
        end_exclusive, key = self._entries[idx]
        if sid < end_exclusive:
            return key
        # Also check subsequent entries in case of overlap (rare in the data)
        for j in range(idx + 1, len(self._starts)):
            if self._starts[j] > sid:
                break
            end_j, key_j = self._entries[j]
            if sid < end_j:
                return key_j
        return None

    def summary(self, sids):
        """Aggregate a list of SIDs into a provenance breakdown.

        Args:
            sids: iterable of integer SIDs

        Returns:
            dict with:
              - counts: {allocation_key: count} (including UNALLOCATED)
              - unallocated_sids: [sids that fell outside any range]
        """
        counts = Counter()
        unallocated = []
        for sid in sids:
            key = self.lookup(sid)
            if key is None:
                counts[UNALLOCATED] += 1
                unallocated.append(sid)
            else:
                counts[key] += 1
        return {"counts": dict(counts), "unallocated_sids": unallocated}

    def describe(self, key):
        """Return a human-readable descriptor for an allocation key.

        Args:
            key: allocation key or UNALLOCATED

        Returns:
            dict with 'name', 'org', 'ranges' (or empty when UNALLOCATED)
        """
        if key == UNALLOCATED:
            return {"name": UNALLOCATED, "org": "", "ranges": []}
        entry = self.allocations.get(key, {})
        return {
            "name": entry.get("name", key),
            "org": entry.get("org", ""),
            "ranges": entry.get("ranges", []),
        }


def _load_via_cache(url, cache_path, ttl):
    """Return the YAML content, using a filesystem cache when the URL is fresh enough."""
    if os.path.isfile(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < ttl:
            with open(cache_path, "r", encoding="utf-8") as handle:
                return handle.read()
    text = _fetch_url(url)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return text


def _fetch_url(url, timeout=15):
    """Download the URL and return its body as text."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "suricata-ruleset-analyze"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8")
