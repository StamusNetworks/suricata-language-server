"""
Copyright(C) 2026 Stamus Networks
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
import queue
from typing import Dict, Optional, Tuple, Any

from suricatals.parse_signatures import SuricataFile
from suricatals.signature_validator import TestRules

log = logging.getLogger(__name__)


def analyze_file_worker(
    filepath: str,
    rules_tester_config: Dict[str, Any],
    progress_queue: Any,
) -> Tuple[str, Optional[Dict], Optional[Exception]]:
    """
    Worker function to analyze a single rules file in a separate process.

    This function is designed to be run in a separate process via
    ProcessPoolExecutor. It creates its own TestRules instance
    (including Docker client if needed) to avoid sharing state across
    process boundaries.

    Args:
        filepath: Absolute path to rules file to analyze
        rules_tester_config: Dict with TestRules configuration:
            - suricata_binary: Path to suricata binary
            - suricata_config: Path to config file or None
            - docker: Boolean, whether to use Docker mode
            - docker_image: Docker image name if docker=True
        progress_queue: Multiprocessing queue for progress updates

    Returns:
        Tuple of (filepath, mpm_data, error):
            - filepath: The file that was analyzed
            - mpm_data: Dict {"buffer": {...}, "sids": {...}} or None if no MPM data
            - error: Exception if analysis failed, otherwise None
    """
    try:
        # Create TestRules instance in this worker process
        # If this was unpickled, __setstate__ recreates suricmd with its own docker client
        rules_tester = TestRules(
            suricata_binary=rules_tester_config["suricata_binary"],
            suricata_config=rules_tester_config["suricata_config"],
            docker=rules_tester_config["docker"],
            docker_image=rules_tester_config["docker_image"],
        )

        # Create and load file from disk
        s_file = SuricataFile(filepath, rules_tester)
        s_file.load_from_disk()

        # Run analysis with engine analysis enabled
        _, _ = s_file.check_file(engine_analysis=True)

        # Extract MPM data if available
        mpm_data = None
        if s_file.mpm:
            mpm_data = {"buffer": s_file.mpm, "sids": {}}
            # Store per-signature MPM info
            for sig in s_file.sigset.signatures:
                if sig.mpm:
                    mpm_data["sids"][sig.sid] = sig.mpm

        # Send progress update (non-blocking)
        try:
            progress_queue.put_nowait(("completed", filepath, 1))
        except queue.Full:
            # If queue is full or fails, skip progress update
            # Not critical for correctness, only user feedback
            pass

        return (filepath, mpm_data, None)

    # pylint: disable=W0703
    except Exception as e:
        # Log error in worker process
        log.error("Error analyzing file %s: %s", filepath, e, exc_info=True)

        # Send error notification via progress queue
        try:
            progress_queue.put_nowait(("error", filepath, str(e)))
        except queue.Full:
            # If queue fails, error will still be returned in tuple
            pass

        # Return error in tuple so main process can handle it
        return (filepath, None, e)
