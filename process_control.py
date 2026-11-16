"""Stop a single verified Windows process using a stable process handle."""
import ctypes
import ntpath
import os
from ctypes import wintypes

PROTECTED_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe", "mbamservice.exe",
}


def stop_process(pid: int, path: str, start_ticks: int) -> str:
    if pid <= 4 or pid in {os.getpid(), os.getppid()}:
        return "Protected"
    if not path or not start_ticks:
        return "Process identity unavailable"
    if not ntpath.isabs(path):
        return "Process identity unavailable"

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    handle_type = wintypes.HANDLE
    pointer = ctypes.POINTER
    filetime = wintypes.FILETIME
    signatures = {
        "OpenProcess": (handle_type, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
        "CloseHandle": (wintypes.BOOL, [handle_type]),
        "GetProcessTimes": (wintypes.BOOL, [handle_type] + [pointer(filetime)] * 4),
        "QueryFullProcessImageNameW": (
            wintypes.BOOL, [handle_type, wintypes.DWORD, wintypes.LPWSTR, pointer(wintypes.DWORD)]
        ),
        "IsProcessCritical": (wintypes.BOOL, [handle_type, pointer(wintypes.BOOL)]),
        "TerminateProcess": (wintypes.BOOL, [handle_type, wintypes.UINT]),
        "WaitForSingleObject": (wintypes.DWORD, [handle_type, wintypes.DWORD]),
    }
    for name, (restype, argtypes) in signatures.items():
        function = getattr(api, name)
        function.restype = restype
        function.argtypes = argtypes

    # Synchronize, query limited information, and terminate.
    handle = api.OpenProcess(0x100000 | 0x1000 | 0x0001, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        return {5: "Access denied", 87: "Already exited"}.get(error, f"Open failed ({error})")
    try:
        if api.WaitForSingleObject(handle, 0) == 0:
            return "Already exited"
        created, exited, kernel, user = (filetime() for _ in range(4))
        image = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(image))
        if not api.GetProcessTimes(handle, created, exited, kernel, user):
            return "Process identity unavailable"
        if not api.QueryFullProcessImageNameW(handle, 0, image, length):
            return "Process identity unavailable"
        actual_ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
        normalize = lambda value: ntpath.normcase(ntpath.normpath(value))
        # CIM timestamps are only precise to a microsecond.
        if actual_ticks // 10 != start_ticks // 10 or normalize(image.value) != normalize(path):
            return "Process changed"
        critical = wintypes.BOOL()
        if not api.IsProcessCritical(handle, critical) or critical.value:
            return "Protected"
        windows = normalize(os.environ.get("SystemRoot", r"C:\Windows")).rstrip("\\") + "\\"
        actual_path = normalize(image.value)
        if actual_path.startswith(windows) or ntpath.basename(actual_path) in PROTECTED_NAMES:
            return "Protected"
        if not api.TerminateProcess(handle, 1):
            error = ctypes.get_last_error()
            if api.WaitForSingleObject(handle, 0) == 0:
                return "Already exited"
            return "Access denied" if error == 5 else f"Stop failed ({error})"
        if api.WaitForSingleObject(handle, 3000) == 0:
            return "Stopped"
        return "Stop requested, exit unverified"
    finally:
        api.CloseHandle(handle)
