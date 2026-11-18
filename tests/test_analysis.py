import unittest
from analysis import Finding, analyze_item, mark_new


class ScannerTests(unittest.TestCase):
    def test_signed_launcher_arguments(self):
        item = dict(Category="Task", Name="Example", Command="powershell -WindowStyle Hidden",
                    Exists=True, Sig="Valid", Signer="Microsoft", Path=r"C:\Windows\powershell.exe")
        self.assertEqual(analyze_item(item).severity, "Medium")

    def test_changed_hash(self):
        item = dict(Category="Task", Name="Example", SHA256="old")
        current = Finding("Info", "Task", "Example", sha256="new")
        self.assertEqual(mark_new([current], {"Items": [item]}), 1)
        self.assertIn("Changed since baseline", current.reasons)

    def test_payload_signature(self):
        item = dict(Category="Task", Name="Example", Details={
            "PayloadPath": "sample.dll", "PayloadSignature": "HashMismatch"})
        self.assertEqual(analyze_item(item).severity, "High")
