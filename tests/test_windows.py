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
