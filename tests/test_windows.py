import ctypes
from ctypes import wintypes
import subprocess
import os
import sys
import unittest
from unittest.mock import patch

from process_control import stop_process


@unittest.skipUnless(os.name == "nt", "Windows integration")
class WindowsTests(unittest.TestCase):
    def test_stop_disposable_child(self):
        with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]) as child:
            try:
                fields = [wintypes.FILETIME() for _ in range(4)]
                ok = ctypes.windll.kernel32.GetProcessTimes(
                    wintypes.HANDLE(int(child._handle)), *(ctypes.byref(f) for f in fields))
                self.assertTrue(ok)
                ticks = (fields[0].dwHighDateTime << 32) | fields[0].dwLowDateTime
                self.assertEqual(stop_process(child.pid, sys.executable, ticks - 100), "Process changed")
                self.assertIsNone(child.poll())
                self.assertEqual(stop_process(child.pid, sys.executable, ticks), "Stopped")
                self.assertEqual(child.wait(5), 1)
            finally:
                if child.poll() is None:
                    child.kill()

    def test_saved_scan_disables_stop(self):
        from system_scanner import App
        with patch.object(App, "start_scan"):
            app = App()
            try:
                app.load_process_rows({"Items": [{"Category": "Process", "Name": "Example",
                    "Path": sys.executable, "Details": {"PID": 123, "StartTicks": "100"}}]}, False)
                app.process_tree.selection_set("0")
                app.show_process()
                self.assertTrue(app.stop_btn.instate(["disabled"]))
            finally:
                app.destroy()

    def test_task_lifecycle(self):
        import hashlib
        import json
        import uuid
        from analysis import ENGINE

        name = "SystemScanner-Test-" + uuid.uuid4().hex
        path = "\\"
        base = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]

        def powershell(script):
            return subprocess.run(base + ["-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                                          "$ErrorActionPreference='Stop'; " + script],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=45)

        def xml():
            return powershell(f"[Console]::Write((Export-ScheduledTask -TaskPath '\\' -TaskName '{name}'))").stdout.decode(
                "utf-8")

        def change(action, definition="", digest=None):
            request = dict(action=action, path=path, name=name, xml=definition,
                           digest=digest or hashlib.sha256(definition.encode("utf-8")).hexdigest())
            return subprocess.run(base + ["-File", str(ENGINE.with_name("task-action.ps1"))],
                                  input=json.dumps(request), encoding="utf-8", capture_output=True, timeout=45)

        powershell(f"$a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'; "
                   f"Register-ScheduledTask -TaskName '{name}' -Action $a | Out-Null")
        try:
            result = change("disable", xml(), digest="stale")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("definition changed", result.stderr)
            for action in ("disable", "enable", "delete"):
                definition = xml()
                result = change(action, definition)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = change("restore", definition)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("<Actions", xml())
        finally:
            powershell(f"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue")
