"""Backup and restore supported Windows Registry Run entries."""
import json
from uuid import uuid4

import analysis as A

PREFIX = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
KEYS = {f"{prefix}\\{suffix}".casefold() for suffix in ("Run", "RunOnce")}


def registry_location(location, name):
    import winreg
    hive, separator, key = location.partition(":\\")
    if not separator or key.casefold() not in KEYS or not name:
        raise ValueError("Only standard Registry Run and RunOnce entries are supported.")
    if hive.upper() not in {"HKCU", "HKLM"}:
        raise ValueError("Unsupported Registry hive.")
    return winreg, getattr(winreg, {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}[hive.upper()]), key


def remove_run_entry(location, name, scanned_command):
    reg, hive, key = registry_location(location, name)
    with reg.OpenKey(hive, key, access=reg.KEY_QUERY_VALUE | reg.KEY_SET_VALUE) as handle:
        value, kind = reg.QueryValueEx(handle, name)
        if kind not in (reg.REG_SZ, reg.REG_EXPAND_SZ) or value != scanned_command:
            raise ValueError("The saved command differs from the live value. Scan again before changing it.")
        folder = A.SCANS_DIR / "startup-backups"
        folder.mkdir(parents=True, exist_ok=True)
        backup = folder / f"{uuid4().hex}.json"
        with backup.open("x", encoding="utf-8") as stream:
            json.dump(dict(location=location, name=name, value=value, kind=kind), stream)
        reg.DeleteValue(handle, name)
    return backup


def restore_run_entry(payload):
    reg, hive, key = registry_location(payload["location"], payload["name"])
    value, kind = payload["value"], payload["kind"]
    if not isinstance(value, str) or kind not in (reg.REG_SZ, reg.REG_EXPAND_SZ):
        raise ValueError("Unsupported Registry value type.")
    with reg.CreateKeyEx(hive, key, access=reg.KEY_QUERY_VALUE | reg.KEY_SET_VALUE) as handle:
        try:
            reg.QueryValueEx(handle, payload["name"])
        except FileNotFoundError:
            reg.SetValueEx(handle, payload["name"], 0, kind, value)
        else:
            raise ValueError("A startup entry already exists at this location.")
