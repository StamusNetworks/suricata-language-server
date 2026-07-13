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

BUNDLED_ALLOCATIONS_PATH = os.path.join(
    os.path.dirname(__file__), "data", "sid_allocations.yml"
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
        pairs = sorted(zip(self._starts, self._entries))
        self._starts = [p[0] for p in pairs]
        self._entries = [p[1] for p in pairs]

    @classmethod
    def load(
        cls,
        source=None,
        cache_path=None,
        cache_ttl=DEFAULT_CACHE_TTL,
        offline=False,
    ):
        """Load allocations. Loading strategy:

        - If ``source`` is a local file path: read that file.
        - If ``source`` is an ``http(s)://`` URL: fetch it (writes cache if a
          cache path is provided).
        - If ``source`` is None (default): try the on-disk cache first
          (``~/.cache/suricata-language-server/allocations.yml`` unless overridden
          with ``cache_path``); refresh from the upstream URL if the cache is
          missing or older than ``cache_ttl``. When the network is unreachable or
          ``offline=True``, fall back to the bundled copy shipped with the package.

        Args:
            source: URL, local file path, or None.
            cache_path: Override the on-disk cache location.
            cache_ttl: Max cache age in seconds before refresh (default: 1 week).
            offline: If True, skip any network fetch — use bundled or explicit source.

        Returns:
            SidAllocations instance.
        """
        if source and os.path.isfile(source):
            return cls._from_file(source)

        if source:  # explicit URL
            if offline:
                raise RuntimeError(
                    f"Cannot fetch {source} in offline mode; pass a local file "
                    "path or drop --offline."
                )
            text = _fetch_url(source)
            return cls._from_text(text)

        cache_path = cache_path or DEFAULT_CACHE_PATH

        if offline:
            if os.path.isfile(cache_path):
                return cls._from_file(cache_path)
            return cls._from_file(BUNDLED_ALLOCATIONS_PATH)

        if _cache_is_fresh(cache_path, cache_ttl):
            return cls._from_file(cache_path)

        try:
            text = _fetch_url(DEFAULT_ALLOCATIONS_URL)
        except (OSError, ValueError):
            # Network unreachable / URL unresolvable — fall back gracefully
            if os.path.isfile(cache_path):
                return cls._from_file(cache_path)
            return cls._from_file(BUNDLED_ALLOCATIONS_PATH)

        _write_cache(cache_path, text)
        return cls._from_text(text)

    @classmethod
    def refresh_bundled(cls, url=None):
        """Fetch the latest allocations.yml from upstream and update the bundled copy.

        Args:
            url: Override for the upstream URL (default: DEFAULT_ALLOCATIONS_URL).

        Returns:
            Path to the updated bundled file.
        """
        url = url or DEFAULT_ALLOCATIONS_URL
        text = _fetch_url(url)
        # Validate before writing
        yaml.safe_load(text)
        os.makedirs(os.path.dirname(BUNDLED_ALLOCATIONS_PATH), exist_ok=True)
        with open(BUNDLED_ALLOCATIONS_PATH, "w", encoding="utf-8") as handle:
            handle.write(text)
        return BUNDLED_ALLOCATIONS_PATH

    @classmethod
    def _from_file(cls, path):
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return cls(data.get("allocations", {}))

    @classmethod
    def _from_text(cls, text):
        data = yaml.safe_load(text)
        return cls(data.get("allocations", {}))

    def lookup(self, sid):
        """Return the allocation key for the given SID, or None if unallocated."""
        if not self._starts:
            return None
        idx = bisect_right(self._starts, sid) - 1
        if idx < 0:
            return None
        end_exclusive, key = self._entries[idx]
        if sid < end_exclusive:
            return key
        for j in range(idx + 1, len(self._starts)):
            if self._starts[j] > sid:
                break
            end_j, key_j = self._entries[j]
            if sid < end_j:
                return key_j
        return None

    def summary(self, sids):
        """Aggregate a list of SIDs into a provenance breakdown."""
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
        """Return a human-readable descriptor for an allocation key."""
        if key == UNALLOCATED:
            return {"name": UNALLOCATED, "org": "", "ranges": []}
        entry = self.allocations.get(key, {})
        return {
            "name": entry.get("name", key),
            "org": entry.get("org", ""),
            "ranges": entry.get("ranges", []),
        }


def _cache_is_fresh(cache_path, ttl):
    if not os.path.isfile(cache_path):
        return False
    return (time.time() - os.path.getmtime(cache_path)) < ttl


def _write_cache(cache_path, text):
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _fetch_url(url, timeout=15):
    """Download the URL and return its body as text."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "suricata-ruleset-analyze"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8")
