from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _flatten_eval_tree(eval_tree: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for group_name, group_payload in eval_tree.items():
        if not isinstance(group_payload, dict):
            continue
        group_summary = group_payload.get("_summary", {})
        for probe_name, probe_payload in group_payload.items():
            if probe_name == "_summary" or not isinstance(probe_payload, dict):
                continue
            probe_summary = probe_payload.get("_summary", {})
            for detector_name, detector_payload in probe_payload.items():
                if detector_name == "_summary" or not isinstance(detector_payload, dict):
                    continue
                summaries.append(
                    {
                        "group": group_name,
                        "probe_name": probe_name,
                        "detector_name": detector_name,
                        "group_summary": group_summary,
                        "probe_summary": probe_summary,
                        "detector_summary": detector_payload,
                        "score": detector_payload.get("absolute_score"),
                        "defcon": detector_payload.get("absolute_defcon") or detector_payload.get("detector_defcon"),
                        "total_evaluated": detector_payload.get("total_evaluated"),
                        "passed": detector_payload.get("passed"),
                    }
                )
    return summaries


def parse_garak_report(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path)
    setup_entry: dict[str, Any] | None = None
    init_entry: dict[str, Any] | None = None
    completion_entry: dict[str, Any] | None = None
    digest_entry: dict[str, Any] | None = None
    plugin_cache_entry: dict[str, Any] | None = None
    attempts: list[dict[str, Any]] = []
    eval_entries: list[dict[str, Any]] = []
    unknown_entries: list[dict[str, Any]] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        entry_type = entry.get("entry_type")
        if entry_type == "start_run setup":
            setup_entry = entry
        elif entry_type == "init":
            init_entry = entry
        elif entry_type == "plugin_cache":
            plugin_cache_entry = entry
        elif entry_type == "attempt":
            attempts.append(entry)
        elif entry_type == "eval":
            eval_entries.append(entry)
        elif entry_type == "completion":
            completion_entry = entry
        elif entry_type == "digest":
            digest_entry = entry
        else:
            unknown_entries.append(entry)

    digest_meta = (digest_entry or {}).get("meta", {})
    setup = setup_entry or digest_meta.get("setup", {})
    eval_tree = (digest_entry or {}).get("eval", {})
    eval_summaries = _flatten_eval_tree(eval_tree)
    probe_names = sorted(
        {
            *[str(attempt.get("probe_classname", "")) for attempt in attempts if attempt.get("probe_classname")],
            *[str(summary["probe_name"]) for summary in eval_summaries],
        }
    )
    detector_names = sorted(
        {
            *[str(entry.get("detector", "")) for entry in eval_entries if entry.get("detector")],
            *[str(summary["detector_name"]) for summary in eval_summaries],
        }
    )

    return {
        "report_path": str(path),
        "entries_count": len(attempts) + len(eval_entries) + len(unknown_entries) + sum(
            1 for item in (setup_entry, init_entry, plugin_cache_entry, completion_entry, digest_entry) if item is not None
        ),
        "metadata": {
            "garak_version": (init_entry or {}).get("garak_version") or digest_meta.get("garak_version") or setup.get("_config.version"),
            "run_uuid": (init_entry or {}).get("run") or digest_meta.get("run_uuid") or setup.get("transient.run_id"),
            "start_time": (init_entry or {}).get("start_time") or digest_meta.get("start_time") or setup.get("transient.starttime_iso"),
            "end_time": (completion_entry or {}).get("end_time"),
            "target_type": digest_meta.get("target_type") or setup.get("plugins.target_type"),
            "target_name": digest_meta.get("target_name") or setup.get("plugins.target_name"),
            "probe_spec": digest_meta.get("probespec") or setup.get("plugins.probe_spec"),
            "detector_spec": setup.get("plugins.detector_spec"),
            "report_filename": digest_meta.get("reportfile") or Path(str(setup.get("transient.report_filename", path.name))).name,
        },
        "setup": setup_entry or {},
        "init": init_entry or {},
        "plugin_cache": plugin_cache_entry or {},
        "attempts": attempts,
        "eval_entries": eval_entries,
        "eval_summaries": eval_summaries,
        "digest": digest_entry or {},
        "completion": completion_entry or {},
        "probe_names": probe_names,
        "detector_names": detector_names,
        "unknown_entries": unknown_entries,
    }
