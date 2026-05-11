from __future__ import annotations

import json
from pathlib import Path

from garak_poc.models import ScanResult


def write_json_report(scan_result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(scan_result.to_dict(), handle, indent=2)
