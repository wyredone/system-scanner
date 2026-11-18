"""Local review state and deliberately minimal shareable reports."""
import json
import tempfile
from pathlib import Path

import analysis as A


def read_settings():
    try:
        data = json.loads((A.SCANS_DIR / "review-settings.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(settings):
    A.SCANS_DIR.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=A.SCANS_DIR) as folder:
        pending = Path(folder) / "settings.json"
        pending.write_text(json.dumps(settings), encoding="utf-8")
        pending.replace(A.SCANS_DIR / "review-settings.json")


def fingerprint(finding):
    return json.dumps([finding.key, A.comparison_state(finding)], default=str)


def redacted_report(findings):
    # Allowlist static fields; entry names and free text can contain private data.
    allowed = {"Task", "Service", "Startup", "Process", "Coverage", "RemoteSession",
               "RemoteAccess", "Security", "Driver", "WMI"}
    return "\n".join(
        f"Entry {number:03} | {finding.severity} | "
        f"{finding.category if finding.category in allowed else 'Other'}"
        f" | {'New or changed' if finding.is_new else 'Current'}"
        for number, finding in enumerate(findings, 1)
    )
