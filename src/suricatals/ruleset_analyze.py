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

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from importlib.metadata import version
from pathlib import Path

import yaml

from suricatals.langserver import LangServer
from suricatals.metadata_parser import parse_rules_file
from suricatals.sid_allocations import SidAllocations, UNALLOCATED
from suricatals.suricata_command import SuriCmd
from suricatals.suricata_read import build_sid_msg_index, reshape_profile

__version__ = version("suricata-language-server")

ALL_SECTIONS = ["composition", "engine", "cve", "metadata", "reference", "mpm"]
DEFAULT_SECTIONS = list(ALL_SECTIONS)

REF_RE = re.compile(r"reference\s*:\s*([a-zA-Z0-9_\-]+)\s*,\s*([^;\s]+)", re.IGNORECASE)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")


def error_exit(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(-1)


# --------------------------------------------------------------------------
# Analysis functions — each returns a plain dict, suitable for JSON output
# --------------------------------------------------------------------------


def analyze_composition(parsed_rules, allocations=None):
    """Section 1 — sig counts, provenance, protocols."""
    total = len(parsed_rules)
    # Protocol distribution from rule header (2nd token: alert http any …)
    protocols = Counter()
    for rule in parsed_rules:
        header = rule.get("header") or ""
        tokens = header.split()
        if len(tokens) >= 2:
            protocols[tokens[1]] += 1

    # Provenance via SID allocation
    provenance = None
    if allocations is not None:
        sids = [r["sid"] for r in parsed_rules if isinstance(r.get("sid"), int)]
        summary = allocations.summary(sids)
        provenance = {
            "counts": summary["counts"],
            "descriptors": {
                key: allocations.describe(key)
                for key in summary["counts"]
                if key != UNALLOCATED
            },
        }

    return {
        "total_valid_rules": total,
        "protocol_distribution": dict(protocols.most_common()),
        "provenance": provenance,
    }


def analyze_cve(parsed_rules, text):
    """Section 4 in the analysis doc — CVE tagging."""
    ref_cve_values = REF_RE.findall(text)
    ref_cve_only = [v for k, v in ref_cve_values if k.lower() == "cve"]

    meta_cve_sigs = 0
    meta_cve_values = []
    for rule in parsed_rules:
        if rule.get("metadata", {}).get("cve"):
            meta_cve_sigs += 1
            meta_cve_values.extend(rule["metadata"]["cve"])

    # Per-sig cross-check: build sid -> {has_ref, has_meta}
    per_sid = {}
    for rule in parsed_rules:
        sid = rule.get("sid")
        if not isinstance(sid, int):
            continue
        per_sid[sid] = {
            "has_meta_cve": bool(rule.get("metadata", {}).get("cve")),
            "has_ref_cve": False,
        }
    # Scan raw text lines for reference:cve
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "reference" not in line.lower():
            continue
        if not REF_RE.search(line):
            continue
        sid_match = SID_RE.search(line)
        if not sid_match:
            continue
        sid = int(sid_match.group(1))
        if sid not in per_sid:
            continue
        if any(k.lower() == "cve" for k, _ in REF_RE.findall(line)):
            per_sid[sid]["has_ref_cve"] = True

    both = only_ref = only_meta = neither = 0
    for state in per_sid.values():
        if state["has_ref_cve"] and state["has_meta_cve"]:
            both += 1
        elif state["has_ref_cve"]:
            only_ref += 1
        elif state["has_meta_cve"]:
            only_meta += 1
        else:
            neither += 1

    ref_shapes = Counter(re.sub(r"\d", "N", v) for v in ref_cve_only)
    meta_shapes = Counter(re.sub(r"\d", "N", v) for v in meta_cve_values)

    return {
        "reference_cve_count": len(ref_cve_only),
        "metadata_cve_sig_count": meta_cve_sigs,
        "presence": {
            "both": both,
            "only_reference": only_ref,
            "only_metadata": only_meta,
            "neither": neither,
        },
        "reference_cve_shapes": dict(ref_shapes.most_common()),
        "metadata_cve_shapes": dict(meta_shapes.most_common()),
    }


def analyze_metadata(parsed_rules):
    """Section 3 — metadata key vocabulary + coverage + MITRE consistency."""
    total = len(parsed_rules)
    key_counts = Counter()
    per_key_values = defaultdict(Counter)
    per_key_sids = defaultdict(list)
    multi_value_by_key = Counter()

    for rule in parsed_rules:
        sid = rule.get("sid") if isinstance(rule.get("sid"), int) else None
        for key, values in rule.get("metadata", {}).items():
            key_counts[key] += 1
            per_key_values[key].update(values)
            if sid is not None:
                per_key_sids[key].append(sid)
            if len(values) > 1:
                multi_value_by_key[key] += 1

    # Value format-drift per key: unique shapes normalised to \d -> N.
    # For every key with >1 shape, also record which SIDs use which shape so
    # downstream views (e.g. --errors-only) can list them.
    shape_drift = {}
    shape_drift_sids = {}
    for key, values in per_key_values.items():
        shapes = Counter()
        for value, count in values.items():
            shapes[re.sub(r"\d", "N", value)] += count
        if len(shapes) > 1:
            shape_drift[key] = dict(shapes)
            per_shape_sids = defaultdict(list)
            for rule in parsed_rules:
                sid = rule.get("sid")
                if not isinstance(sid, int):
                    continue
                for value in rule.get("metadata", {}).get(key, []):
                    per_shape_sids[re.sub(r"\d", "N", value)].append(sid)
            shape_drift_sids[key] = {
                shape: sorted(set(sids)) for shape, sids in per_shape_sids.items()
            }

    # MITRE ID <-> name consistency
    id_name_mismatches = {}
    for id_key, name_key in [
        ("mitre_tactic_id", "mitre_tactic_name"),
        ("mitre_technique_id", "mitre_technique_name"),
    ]:
        id_to_names = defaultdict(Counter)
        for rule in parsed_rules:
            m = rule.get("metadata", {})
            ids = m.get(id_key, [])
            names = m.get(name_key, [])
            for i, n in zip(ids, names):
                id_to_names[i][n] += 1
        conflicts = {i: dict(n) for i, n in id_to_names.items() if len(n) > 1}
        if conflicts:
            id_name_mismatches[id_key] = conflicts

    coverage = {
        key: {"count": count, "share": count / total if total else 0}
        for key, count in key_counts.most_common()
    }

    return {
        "total_valid_rules": total,
        "key_coverage": coverage,
        "sids_by_key": {k: sorted(set(v)) for k, v in per_key_sids.items()},
        "multi_value_sigs_by_key": dict(multi_value_by_key),
        "format_drift_by_key": shape_drift,
        "format_drift_sids_by_key": shape_drift_sids,
        "mitre_id_name_mismatches": id_name_mismatches,
    }


def analyze_reference(parsed_rules, text):
    """Section 5 — reference keyword usage."""
    total = len(parsed_rules)
    ref_types = Counter()
    per_sig_ref_count = Counter()
    sigs_with_ref = 0

    # Re-scan per line to count refs per rule
    sig_lines = []
    rule_start = re.compile(r"^\s*(alert|drop|reject|pass|log)\b")
    for line in text.splitlines():
        if not rule_start.match(line):
            continue
        sig_lines.append(line)

    for line in sig_lines:
        refs = REF_RE.findall(line)
        if refs:
            sigs_with_ref += 1
            per_sig_ref_count[len(refs)] += 1
            for k, _ in refs:
                ref_types[k.lower()] += 1

    return {
        "total_valid_rules": total,
        "sigs_with_reference": sigs_with_ref,
        "coverage": sigs_with_ref / total if total else 0,
        "reference_types": dict(ref_types.most_common()),
        "refs_per_sig_distribution": dict(sorted(per_sig_ref_count.items())),
    }


def analyze_engine_and_mpm(rules_path, settings):
    """Sections 2/6 — engine diagnostics + MPM analysis via SLS batch mode.

    Returns None when SLS analysis fails to run.
    """
    server = LangServer(settings=settings, batch_mode=True)
    try:
        _, _, diags = server.analyse_file(str(rules_path), True)
    except (
        Exception
    ) as exc:  # pragma: no cover  # pylint: disable=broad-exception-caught
        return {"error": f"SLS analysis failed: {exc}"}

    warn_categories = Counter()
    warn_sids = set()
    err_sids = set()
    err_messages = []  # [(sid, message), …] for the --errors-only view
    mpm_conflicts = 0
    mpm_conflict_sids = set()
    mpm_worst = {}  # (pattern, buffer) -> max N
    no_fp_sids = set()

    fp_msg_re = re.compile(
        r"Fast Pattern '(.+)' on '([^']+)' buffer is used in (\d+) different signatures"
    )

    for diag in diags:
        msg = diag.message
        sev = diag.severity.value
        source = getattr(diag, "source", "")
        sid = getattr(diag, "sid", None)
        if sev == 1:  # error
            if sid:
                err_sids.add(sid)
            err_messages.append({"sid": sid, "message": msg})
        elif sev == 2:  # warning
            if sid:
                warn_sids.add(sid)
            if "flow keyword" in msg:
                warn_categories["flow-missing"] += 1
            elif "Multiple application layers" in msg:
                warn_categories["multi-app-layer"] += 1
            elif "pcre without content match" in msg:
                warn_categories["pcre-no-content"] += 1
            elif "Signature with newer revision" in msg:
                warn_categories["old-rev-replaced"] += 1
            else:
                warn_categories["other"] += 1
        # MPM analyses
        if source == "SLS MPM Analysis":
            m = fp_msg_re.search(msg)
            if m:
                pattern, buf, n_str = m.group(1), m.group(2), int(m.group(3))
                mpm_conflicts += 1
                if sid:
                    mpm_conflict_sids.add(sid)
                mpm_worst[(pattern, buf)] = max(mpm_worst.get((pattern, buf), 0), n_str)
        if source == "Suricata MPM Analysis" and msg.startswith("No Fast Pattern used"):
            if sid:
                no_fp_sids.add(sid)

    worst_top = sorted(mpm_worst.items(), key=lambda kv: -kv[1])[:10]

    return {
        "errors_sid_count": len(err_sids),
        "errors": err_messages,
        "warning_sid_count": len(warn_sids),
        "warning_categories": dict(warn_categories),
        "mpm_conflicts_total": mpm_conflicts,
        "mpm_conflict_sig_count": len(mpm_conflict_sids),
        "mpm_worst_top": [
            {"pattern": p, "buffer": b, "shared_sigs": n} for (p, b), n in worst_top
        ],
        "no_fast_pattern_sig_count": len(no_fp_sids),
        "no_fast_pattern_sids": sorted(s for s in no_fp_sids if s),
    }


def analyze_runtime(pcap_path, rules_content, top_n, settings):
    """Section 7 — runtime profiling via SuriCmd.read_pcap_profile."""
    suricmd = SuriCmd(
        suricata_binary=settings.get("suricata_binary", "suricata"),
        suricata_config=settings.get("suricata_config"),
    )
    if settings.get("docker_mode"):
        suricmd.set_docker_mode(docker_image=settings["docker_image"])
    perf_json, pcap_stats = suricmd.read_pcap_profile(
        pcap_path, rules_content, top_n=top_n
    )
    reshaped = reshape_profile(perf_json, build_sid_msg_index(rules_content), top_n)
    total_ticks = sum((e.get("ticks_total") or 0) for e in reshaped)
    zero_match = [e for e in reshaped if (e.get("matches") or 0) == 0]
    wasted_ticks = sum((e.get("ticks_total") or 0) for e in zero_match)
    total_checks = sum((e.get("checks") or 0) for e in reshaped)
    total_matches = sum((e.get("matches") or 0) for e in reshaped)
    return {
        "processing": pcap_stats,
        "top_n": top_n,
        "top_100_total_ticks": total_ticks,
        "wasted_ticks": wasted_ticks,
        "wasted_ticks_share": wasted_ticks / total_ticks if total_ticks else 0,
        "top_100_total_checks": total_checks,
        "top_100_total_matches": total_matches,
        "match_rate": total_matches / total_checks if total_checks else 0,
        "top_rules": reshaped,
    }


# --------------------------------------------------------------------------
# Human-readable renderer
# --------------------------------------------------------------------------


def extract_error_report(report):
    """Reduce a full report to just the error-level indicators.

    Returned dict has keys (each present only when non-empty):
      - syntax_errors: list of {sid, message}
      - cve_format_drift: {"reference_cve": {...}, "metadata_cve": {...}}
      - mitre_format_drift: {key: {shape: count, …}, …}
      - mitre_id_name_mismatches: {id_key: {id: {name: count, …}, …}}
    """
    errors = {}

    engine = report.get("engine") or {}
    syntax_errors = engine.get("errors") or []
    if syntax_errors:
        errors["syntax_errors"] = syntax_errors

    no_fp_sids = engine.get("no_fast_pattern_sids") or []
    if no_fp_sids:
        errors["no_fast_pattern"] = no_fp_sids

    cve = report.get("cve") or {}
    cve_drift = {}
    if len(cve.get("reference_cve_shapes") or {}) > 1:
        cve_drift["reference_cve"] = cve["reference_cve_shapes"]
    if len(cve.get("metadata_cve_shapes") or {}) > 1:
        cve_drift["metadata_cve"] = cve["metadata_cve_shapes"]
    if cve_drift:
        errors["cve_format_drift"] = cve_drift

    # Shape drift only makes sense for MITRE ID fields whose values follow a
    # regular shape (`TAxxxx` or `Txxxx[.NNN]`). Name/label fields like
    # `mitre_tactic_name` / `mitre_technique_name` are free-form strings
    # without digits — every distinct name registers as a fake shape and
    # floods the report. Bare `mitre_technique` (see below) is treated
    # separately as a non-canonical-key error, not as drift.
    mitre_id_keys = {"mitre_tactic_id", "mitre_technique_id"}
    metadata = report.get("metadata") or {}
    mitre_drift_sids = {
        key: shape_sids
        for key, shape_sids in (metadata.get("format_drift_sids_by_key") or {}).items()
        if key in mitre_id_keys
    }
    if mitre_drift_sids:
        errors["mitre_format_drift"] = mitre_drift_sids

    # Any use of the bare `mitre_technique` metadata key is itself an error —
    # rules should use the canonical `mitre_technique_id` / `mitre_technique_name`
    # pair. List the offending SIDs.
    noncanonical_mitre_sids = (metadata.get("sids_by_key") or {}).get("mitre_technique")
    if noncanonical_mitre_sids:
        errors["mitre_noncanonical_key"] = {"mitre_technique": noncanonical_mitre_sids}

    mitre_mismatches = metadata.get("mitre_id_name_mismatches") or {}
    if mitre_mismatches:
        errors["mitre_id_name_mismatches"] = mitre_mismatches

    return errors


def render_error_report(errors):
    """Format the errors-only report as text."""
    if not errors:
        return (
            "No errors, no-fast-pattern rules, CVE/MITRE format drift, "
            "non-canonical MITRE keys, or MITRE id↔name mismatches."
        )

    lines = []

    def header(text):
        lines.append("")
        lines.append(text)
        lines.append("=" * len(text))

    if "syntax_errors" in errors:
        header("Syntax errors")
        for item in errors["syntax_errors"]:
            lines.append(
                f"  sid={item.get('sid') or '?':<10}  {item.get('message', '')}"
            )

    if "no_fast_pattern" in errors:
        header("No fast_pattern (sigs that should have one but don't)")
        sids = errors["no_fast_pattern"]
        lines.append(f"  {len(sids)} signature(s):")
        for sid in sids[:50]:
            lines.append(f"    sid={sid}")
        if len(sids) > 50:
            lines.append(f"    … and {len(sids) - 50} more")

    if "cve_format_drift" in errors:
        header("CVE format drift")
        for field, shapes in errors["cve_format_drift"].items():
            lines.append(f"  {field}:")
            for shape, count in shapes.items():
                lines.append(f"    {shape}   {count}")

    if "mitre_noncanonical_key" in errors:
        header("MITRE non-canonical metadata key")
        for key, sids in errors["mitre_noncanonical_key"].items():
            lines.append(
                f"  {key}: use `mitre_technique_id` / `mitre_technique_name` "
                f"instead ({len(sids)} sig(s)):"
            )
            for sid in sids[:50]:
                lines.append(f"    sid={sid}")
            if len(sids) > 50:
                lines.append(f"    … and {len(sids) - 50} more")

    if "mitre_format_drift" in errors:
        header("MITRE format drift")
        for key, shape_sids in errors["mitre_format_drift"].items():
            # The most-common shape is treated as the norm; only sigs using
            # any other shape are listed here.
            if not shape_sids:
                continue
            majority = max(shape_sids.items(), key=lambda kv: len(kv[1]))[0]
            lines.append(f"  {key}  (norm: {majority}):")
            for shape, sids in shape_sids.items():
                if shape == majority:
                    continue
                lines.append(f"    {shape}  ({len(sids)} sig(s)):")
                for sid in sids[:50]:
                    lines.append(f"      sid={sid}")
                if len(sids) > 50:
                    lines.append(f"      … and {len(sids) - 50} more")

    if "mitre_id_name_mismatches" in errors:
        header("MITRE id ↔ name mismatches")
        for id_key, conflicts in errors["mitre_id_name_mismatches"].items():
            lines.append(f"  {id_key}: {len(conflicts)} conflicting ID(s)")
            for mitre_id, names in list(conflicts.items())[:10]:
                names_summary = ", ".join(f"{n} (x{c})" for n, c in names.items())
                lines.append(f"    {mitre_id}: {names_summary}")

    return "\n".join(lines).lstrip("\n")


def render_text_report(report, top_n=10):
    """Format a report dict as a human-readable string report."""
    lines = []

    def header(text):
        lines.append("")
        lines.append(text)
        lines.append("=" * len(text))

    def row(label, value):
        lines.append(f"  {label:<32}  {value}")

    if "composition" in report:
        comp = report["composition"]
        header("Composition")
        row("Total valid rules", comp["total_valid_rules"])
        row("Protocol distribution (top 5)", "")
        for proto, count in list(comp["protocol_distribution"].items())[:5]:
            row(f"  {proto}", count)
        if comp.get("provenance"):
            row("SID provenance", "")
            counts = comp["provenance"]["counts"]
            for key, count in sorted(counts.items(), key=lambda kv: -kv[1]):
                desc = comp["provenance"]["descriptors"].get(key, {})
                name = desc.get("name") or key
                row(f"  {key}", f"{count}   {name}")

    if "engine" in report:
        eng = report["engine"]
        header("Engine diagnostics")
        if "error" in eng:
            row("Error", eng["error"])
        else:
            row("Errors (unique SIDs)", eng["errors_sid_count"])
            row("Warnings (unique SIDs)", eng["warning_sid_count"])
            for cat, count in eng["warning_categories"].items():
                row(f"  {cat}", count)
            row("MPM conflicts (sigs)", eng["mpm_conflict_sig_count"])
            row("No fast_pattern used (sigs)", eng["no_fast_pattern_sig_count"])
            if eng["mpm_worst_top"]:
                row("Worst shared fast_patterns", "")
                for entry in eng["mpm_worst_top"][:top_n]:
                    row(
                        f"  N={entry['shared_sigs']}",
                        f"{entry['buffer']:<20} {entry['pattern'][:60]!r}",
                    )

    if "cve" in report:
        cve = report["cve"]
        header("CVE tagging")
        row("reference:cve entries", cve["reference_cve_count"])
        row("metadata:cve sigs", cve["metadata_cve_sig_count"])
        p = cve["presence"]
        row(
            "Presence matrix (both/ref/meta/neither)",
            f"{p['both']} / {p['only_reference']} / {p['only_metadata']} / {p['neither']}",
        )
        if cve["reference_cve_shapes"]:
            row("reference:cve shapes", "")
            for shape, count in list(cve["reference_cve_shapes"].items())[:top_n]:
                row(f"  {shape}", count)

    if "metadata" in report:
        meta = report["metadata"]
        header("Metadata")
        row("Total valid rules", meta["total_valid_rules"])
        row("Keys (top by coverage)", "")
        for key, info in list(meta["key_coverage"].items())[:20]:
            row(f"  {key}", f"{info['count']}  ({info['share']*100:.1f}%)")
        if meta["format_drift_by_key"]:
            row("Format-drift alerts", "")
            for key, shapes in meta["format_drift_by_key"].items():
                row(f"  {key} ({len(shapes)} shapes)", "")
                for shape, count in list(shapes.items())[:3]:
                    row(f"    {shape}", count)
        if meta["mitre_id_name_mismatches"]:
            row("MITRE id ↔ name mismatches", "")
            for id_key, conflicts in meta["mitre_id_name_mismatches"].items():
                row(f"  {id_key}", f"{len(conflicts)} mismatched IDs")

    if "reference" in report:
        ref = report["reference"]
        header("Reference keyword")
        row("Sigs with >=1 reference:", ref["sigs_with_reference"])
        row("Coverage", f"{ref['coverage']*100:.1f}%")
        row("Types used", "")
        for t, n in ref["reference_types"].items():
            row(f"  {t}", n)
        row("Refs per signature", "")
        for c, n in ref["refs_per_sig_distribution"].items():
            row(f"  {c} refs", n)

    if "runtime" in report:
        rt = report["runtime"]
        header("Runtime cost (PCAP replay)")
        p = rt["processing"]
        row("Replay time (s)", p.get("seconds"))
        row("Packets", p.get("packets"))
        row("Bytes", p.get("bytes"))
        row(f"Top-{rt['top_n']} total ticks", f"{rt['top_100_total_ticks']:,}")
        row("Wasted ticks (zero-match)", f"{rt['wasted_ticks']:,}")
        row("Wasted ticks share", f"{rt['wasted_ticks_share']*100:.1f}%")
        row(
            "Match rate (checks vs matches)",
            f"{rt['top_100_total_matches']:,} / {rt['top_100_total_checks']:,} "
            f"({rt['match_rate']*100:.2f}%)",
        )
        row("Top 5 rules", "")
        for entry in rt["top_rules"][:5]:
            msg = (entry.get("msg") or "")[:60]
            row(
                f"  sid={entry['sid']}",
                f"ticks={entry['ticks_total']:>13,}  checks={entry['checks']:>7,}  "
                f"matches={entry['matches']:>5}  {msg}",
            )

    return "\n".join(lines).lstrip("\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(prog="suricata-ruleset-analyze")
    parser.description = f"Suricata ruleset analyzer ({__version__})"
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument(
        "--container",
        action="store_true",
        default=False,
        help="Run Suricata in a container",
    )
    parser.add_argument(
        "--image",
        default=SuriCmd.SLS_DEFAULT_DOCKER_IMAGE,
        help="Suricata image to use in container mode",
    )
    parser.add_argument(
        "--suricata-binary", default="suricata", help="Path to Suricata binary"
    )
    parser.add_argument(
        "--suricata-config", default=None, help="Path to Suricata config"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a text report"
    )
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help=(
            "Show only error-level findings: syntax errors, CVE format drift, "
            "MITRE format drift, and MITRE id↔name mismatches. Skips coverage "
            "and distribution output."
        ),
    )
    parser.add_argument(
        "--sections",
        default=",".join(DEFAULT_SECTIONS),
        help=(
            "Comma-separated list of analyses to run: "
            f"{','.join(ALL_SECTIONS)} (default: all except runtime)"
        ),
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Cap top-K lists per section (default: 10)",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Also run runtime profiling against this PCAP",
    )
    parser.add_argument(
        "--profile-top",
        type=int,
        default=100,
        help="Number of top sigs to report in runtime section (default: 100)",
    )
    parser.add_argument(
        "--sid-allocations",
        default=None,
        help=(
            "Override the SID allocation registry source (URL or local file). "
            "Default: use the user cache under ~/.cache/, refreshing weekly "
            "from sidallocation.org and falling back to the bundled copy "
            "shipped with the package if the network is unreachable."
        ),
    )
    parser.add_argument(
        "--offline-sid-allocations",
        action="store_true",
        help=(
            "Never touch the network for the SID allocations lookup. Uses the "
            "on-disk cache if present, otherwise the bundled copy shipped with "
            "the package."
        ),
    )
    parser.add_argument(
        "--refresh-sid-allocations",
        action="store_true",
        help=(
            "Fetch the latest allocations.yml from sidallocation.org, "
            "overwrite the bundled copy in-place, then exit."
        ),
    )
    parser.add_argument(
        "--no-sid-allocations",
        action="store_true",
        help="Skip SID provenance lookup entirely",
    )
    parser.add_argument("rules_file", nargs="?", help="Path to rules file")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    if args.refresh_sid_allocations:
        path = SidAllocations.refresh_bundled()
        print(f"Refreshed bundled SID allocations at {path}")
        sys.exit(0)

    if not args.rules_file:
        parser.error("the following arguments are required: rules_file")

    rules_path = Path(args.rules_file)
    if not rules_path.is_file():
        error_exit(f"rules file not found: {rules_path}")

    sections = [s.strip() for s in args.sections.split(",") if s.strip()]
    unknown = [s for s in sections if s not in ALL_SECTIONS]
    if unknown:
        parser.error(f"unknown section(s): {unknown}")

    text = rules_path.read_text(encoding="utf-8", errors="replace")
    parsed_rules = parse_rules_file(text)

    settings = {
        "suricata_binary": args.suricata_binary,
        "suricata_config": args.suricata_config,
        "docker_mode": args.container,
        "docker_image": args.image,
        "max_lines": 10_000_000,
        "max_tracked_files": 10_000,
        "idle_timeout": 0.0,
    }

    allocations = None
    if not args.no_sid_allocations and "composition" in sections:
        try:
            allocations = SidAllocations.load(
                args.sid_allocations, offline=args.offline_sid_allocations
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            yaml.YAMLError,
        ) as exc:  # pragma: no cover
            print(
                f"warning: could not load SID allocations ({exc}); skipping provenance",
                file=sys.stderr,
            )

    report = {}
    if "composition" in sections:
        report["composition"] = analyze_composition(parsed_rules, allocations)
    if "cve" in sections:
        report["cve"] = analyze_cve(parsed_rules, text)
    if "metadata" in sections:
        report["metadata"] = analyze_metadata(parsed_rules)
    if "reference" in sections:
        report["reference"] = analyze_reference(parsed_rules, text)
    if "engine" in sections or "mpm" in sections:
        report["engine"] = analyze_engine_and_mpm(rules_path, settings)
    if args.pcap:
        report["runtime"] = analyze_runtime(args.pcap, text, args.profile_top, settings)

    if args.errors_only:
        errors = extract_error_report(report)
        if args.json:
            print(json.dumps(errors, indent=2, ensure_ascii=False))
        else:
            print(render_error_report(errors))
    elif args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_text_report(report, top_n=args.top))
