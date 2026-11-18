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

    def test_changed_command_and_absent(self):
        from analysis import compare_findings
        prior = {"Meta": {"Admin": True}, "Items": [{"Category": "Task", "Name": "Job", "Command": "old"},
                           {"Category": "Task", "Name": "Former"}]}
        row = Finding("Info", "Task", "Job", command="new")
        changes, absent = compare_findings([row], prior)
        self.assertEqual(changes[id(row)][0], "Changed")
        self.assertEqual(changes[id(row)][1].command, "old")
        self.assertEqual([item.name for item in absent], ["Former"])

    def test_retry_preserves_unrelated_sections(self):
        from analysis import merge_retry, retry_sections
        prior = {"Meta": {"Coverage": {"Network activity": "Partial", "Drivers": "Complete"}},
                 "Items": [{"Section": "Drivers"}, {"Section": "Running processes"}]}
        fresh = {"Meta": {"Coverage": {"Network activity": "Complete"}},
                 "Items": [{"Section": "Running processes", "Name": "Current"}], "Network": []}
        sections = retry_sections(prior)
        self.assertIn("Services", sections)
        merged = merge_retry(prior, fresh, sections)
        self.assertEqual(merged["Items"], [prior["Items"][0], fresh["Items"][0]])
        self.assertEqual(merged["Meta"]["Coverage"]["Drivers"], "Complete")

    def test_priority_flags(self):
        finding = Finding("High", "Task", "Demo", reasons=["File was modified after it was signed",
            "Command line uses scripting", "Command line uses scripting"])
        self.assertEqual(finding.flags, ["Signature mismatch", "Script behavior"])
        self.assertEqual(finding.priority, 94)
        self.assertEqual(Finding("Medium", "Coverage", "Tasks").priority, 0)
