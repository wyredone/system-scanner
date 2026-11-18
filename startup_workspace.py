"""Snapshot comparison and explicit Scheduled Tasks actions."""
import json
import os
from pathlib import Path
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from uuid import uuid4
import webbrowser

import analysis as A
from review_tools import save_settings

CATEGORIES = {"RunKey", "StartupFolder", "Task"}


def startup_entries(data):
    return [A.analyze_item(row) for row in data.get("Items", []) if row.get("Category") in CATEGORIES]


class StartupWorkspace:
    def __init__(self, app):
        self.app = app
        self.frame = ttk.Frame(app.tabs, padding=12)
        app.tabs.add(self.frame, text="Startup & Tasks")
        self.current = None
        self.live = False
        self.active = False
        self.rows = []
        selectors = ttk.Frame(self.frame)
        selectors.pack(fill="x")
        self.pickers = []
        for label in ("Before", "After"):
            ttk.Label(selectors, text=label).pack(side="left", padx=5)
            picker = ttk.Combobox(selectors, width=20)
            picker.pack(side="left")
            picker.bind("<<ComboboxSelected>>", lambda _: self.compare())
            self.pickers.append(picker)
        self.button(selectors, "Compare", self.compare)
        self.button(selectors, "Save snapshot", self.snapshot)
        self.help(selectors, "startup-snapshots", "Compare two saved scans or use Current as the after snapshot. Snapshots are read-only.")

        self.filter = tk.StringVar(value="All entries")
        choices = ttk.Combobox(self.frame, state="readonly", textvariable=self.filter, width=20,
                               values=("All entries", "Added", "Changed", "Absent", "Blocked"))
        choices.pack(anchor="w", pady=(6, 0))
        choices.bind("<<ComboboxSelected>>", lambda _: self.compare())
        body = ttk.PanedWindow(self.frame, orient="vertical")
        body.pack(fill="both", expand=True, pady=8)
        self.table = ttk.Treeview(body, columns=("change", "kind", "entry"), show="headings", selectmode="browse")
        for col in ("change", "kind", "entry"):
            self.table.heading(col, text=col.title())
        self.table.column("change", width=125, stretch=False)
        self.table.column("kind", width=125, stretch=False)
        self.table.bind("<<TreeviewSelect>>", lambda _: self.detail())
        body.add(self.table, weight=3)
        evidence = ttk.PanedWindow(body, orient="horizontal")
        self.details = []
        for title in ("Before", "After"):
            frame = ttk.Frame(evidence)
            ttk.Label(frame, text=title).pack(anchor="w")
            box = tk.Text(frame, height=10, wrap="word", state="disabled")
            box.pack(fill="both", expand=True)
            self.details.append(box)
            evidence.add(frame, weight=1)
        body.add(evidence, weight=2)
        actions = ttk.Frame(self.frame)
        actions.pack(fill="x")
        for label, callback in [
            ("Explain", self.explain), ("Hash lookup", self.lookup),
            ("Disable", lambda: self.task_action("disable")), ("Enable", lambda: self.task_action("enable")),
            ("Delete", lambda: self.task_action("delete")), ("Restore task", self.restore),
            ("Block / Unblock", self.block),
        ]:
            self.button(actions, label, callback)
        self.help(actions, "startup-actions", "Windows changes require a fresh live task selection and confirmation. Blocking tracks an entry on future scans.")

    def button(self, parent, label, callback):
        ttk.Button(parent, text=label, command=callback).pack(side="left", padx=3)

    def help(self, bar, anchor, text):
        def show():
            if messagebox.askyesno("Help", text + "\n\nOpen the manual?", parent=self.app):
                webbrowser.open((A.APP_DIR / "user-guide.html").as_uri() + "#" + anchor)
        self.button(bar, "?", show)

    def load(self, data, live):
        self.current, self.live = data, live
        values = ["Current", *map(str, sorted((p for p in A.SCANS_DIR.glob("*.json") if p.name != "review-settings.json" and not p.name.startswith("settings-before-import-")), reverse=True))]
        for picker in self.pickers:
            picker.configure(values=values)
        if not self.pickers[1].get():
            self.pickers[1].set("Current")
        self.compare()

    def snapshot(self):
        if self.current is None:
            return
        path = filedialog.asksaveasfilename(parent=self.app, initialfile="startup-baseline.json", defaultextension=".json")
        if path:
            try:
                # Stage next to the destination so snapshots never appear partially written.
                destination = Path(path)
                pending = destination.with_name(f".{uuid4().hex}.tmp")
                try:
                    pending.write_text(json.dumps(self.current), encoding="utf-8")
                    pending.replace(destination)
                finally:
                    pending.unlink(missing_ok=True)
            except OSError as exc:
                messagebox.showerror("Snapshot failed", str(exc), parent=self.app)
            else:
                self.pickers[0].set(path)
                self.compare()

    def compare(self):
        if self.current is None:
            return
        before, after = (picker.get() for picker in self.pickers)
        try:
            base = self.current if before == "Current" else A.load_scan(Path(before)) if before else None
            target = self.current if after == "Current" else A.load_scan(Path(after))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Could not compare snapshots", str(exc), parent=self.app)
            return
        if base and base["Meta"].get("Computer") != target["Meta"].get("Computer"):
            messagebox.showwarning("Different computers", "Compare snapshots from the same computer.", parent=self.app)
            return
        current = startup_entries(target)
        changes, absent = A.compare_findings(current, {"Meta": base["Meta"], "Items": [
            row for row in base["Items"] if row.get("Category") in CATEGORIES]}) if base else ({}, [])
        blocked = self.app.settings.get("blocks", {})
        self.rows = []
        self.table.delete(*self.table.get_children())
        choice = self.filter.get()
        for row in current:
            state, prior = changes.get(id(row), ("Current", None))
            tracked = self.identity(row) in blocked
            if choice != "All entries" and choice != state and not (choice == "Blocked" and tracked):
                continue
            if tracked:
                state += " · Blocked" if row.details.get("State") == "Disabled" else " · Block alert"
            self.rows.append((prior or (row if state.startswith("Unchanged") else None), row))
            self.table.insert("", "end", values=(state, row.category, row.name))
        for row in absent:
            if row.category in CATEGORIES and (choice in ("All entries", "Absent")
                    or (choice == "Blocked" and self.identity(row) in blocked)):
                self.rows.append((row, None))
                self.table.insert("", "end", values=("Absent", row.category, row.name))
        self.detail()

    def current_row(self):
        selected = self.table.selection()
        return self.rows[self.table.index(selected[0])] if selected else (None, None)

    def detail(self):
        for box, item in zip(self.details, self.current_row()):
            box.configure(state="normal")
            box.delete("1.0", "end")
            if item:
                box.insert("1.0", item.as_text())
            box.configure(state="disabled")

    def identity(self, row):
        location = row.details.get("Key") or row.details.get("Shortcut") or ""
        return json.dumps([row.category, str(location).casefold(), row.name.casefold()])

    def explain(self):
        prior, after = self.current_row()
        self.app.on_explain(after or prior)

    def lookup(self):
        prior, after = self.current_row()
        row = after or prior
        if row and len(row.sha256) == 64 and all(c in "0123456789abcdefABCDEF" for c in row.sha256):
            webbrowser.open("https://www.virustotal.com/gui/file/" + row.sha256)

    def block(self):
        _, row = self.current_row()
        if not row or not self.can_edit():
            return
        rules = self.app.settings.setdefault("blocks", {})
        key = self.identity(row)
        if key in rules:
            del rules[key]
            self.app.persist_settings()
            self.compare()
        elif row.category == "Task" and row.details.get("State") != "Disabled":
            self.task_action("disable", block=True)
        elif messagebox.askyesno("Track block rule", "Flag this entry when it appears in subsequent scans?", parent=self.app):
            rules[key] = row.name
            self.app.persist_settings()
            self.compare()

    def can_edit(self):
        return (self.live and not self.app.busy and not self.active
                and self.pickers[1].get() == "Current")

    def task_action(self, action, block=False):
        _, row = self.current_row()
        if not self.can_edit() or not row or row.category != "Task" or not row.details.get("TaskDigest"):
            messagebox.showinfo("Live task required", "Select a scheduled task from a fresh live scan.", parent=self.app)
            return
        fields = row.details
        payload = dict(action=action, path=fields["TaskPath"], name=fields["TaskName"], digest=fields["TaskDigest"])
        if not messagebox.askyesno("Confirm task change", f"{action.title()} {row.name}?\n\n{row.command}", parent=self.app):
            return
        if action == "delete":
            payload["xml"] = fields["TaskXml"]
            try:
                backups = A.SCANS_DIR / "task-backups"
                backups.mkdir(parents=True, exist_ok=True)
                (backups / f"{uuid4().hex}.json").write_text(json.dumps(payload), encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Backup failed", str(exc), parent=self.app)
                return
        self.run_task(payload, row if block else None)

    def restore(self):
        if self.app.busy or self.active:
            return
        try:
            path = filedialog.askopenfilename(parent=self.app, initialdir=A.SCANS_DIR / "task-backups",
                                               filetypes=[("Task backups", "*.json")])
            if not path:
                return
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            payload = {key: data[key] for key in ("path", "name", "xml")}
            if not all(isinstance(value, str) and value for value in payload.values()):
                raise ValueError("Invalid task backup")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            messagebox.showerror("Invalid backup", str(exc), parent=self.app)
            return
        if messagebox.askyesno("Restore scheduled task", f"Register {payload['path']}{payload['name']} from this backup? Restored tasks can run automatically.",
                               parent=self.app):
            self.run_task(dict(payload, action="restore"))

    def run_task(self, payload, blocked_row=None):
        self.active = self.app.busy = True

        def complete(error):
            self.active = self.app.busy = False
            if error:
                messagebox.showerror("Task action failed", error, parent=self.app)
                return
            if blocked_row:
                self.app.settings.setdefault("blocks", {})[self.identity(blocked_row)] = blocked_row.name
                self.app.persist_settings()
            self.app.start_scan()

        def worker():
            try:
                subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                "-File", str(A.ENGINE.with_name("task-action.ps1"))],
                               input=json.dumps(payload), encoding="utf-8", capture_output=True,
                               check=True, timeout=45, creationflags=0x08000000)
            except subprocess.CalledProcessError as exc:
                error = exc.stderr.strip() or str(exc)
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                error = str(exc)
            else:
                error = ""
            self.app.after(0, complete, error)

        threading.Thread(target=worker, daemon=True).start()

    def settings_backup(self):
        window = tk.Toplevel(self.app)
        window.title("Settings Backup & Restore")
        panel = ttk.Frame(window, padding=14)
        panel.pack(fill="both", expand=True)
        self.button(panel, "Export settings", self.export_settings)
        self.button(panel, "Import settings", self.import_settings)
        self.help(panel, "settings-backup", "Transfers the local model choice, review notes, and block watches. Imports never modify Windows tasks.")

    def export_settings(self):
        path = filedialog.asksaveasfilename(parent=self.app, initialfile="scanner-settings.json", defaultextension=".json")
        if not path:
            return
        data = {key: self.app.settings[key] for key in ("model", "notes", "blocks") if key in self.app.settings}
        try:
            Path(path).write_text(json.dumps({"version": 1, "settings": data}, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.app)

    def import_settings(self):
        path = filedialog.askopenfilename(parent=self.app, filetypes=[("Settings backup", "*.json")])
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if data["version"] != 1 or not isinstance(data["settings"], dict):
                raise ValueError("Unsupported settings version")
            candidate = data["settings"]
            if set(candidate) - {"model", "notes", "blocks"}:
                raise ValueError("Unknown setting")
            model = candidate.get("model", "")
            if not isinstance(model, str) or "cloud" in model.casefold():
                raise ValueError("Expected a local model name")
            for key in ("notes", "blocks"):
                rows = candidate.get(key, {})
                if not isinstance(rows, dict) or any(not isinstance(v, str) for v in rows.values()):
                    raise ValueError(f"Invalid {key}")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            messagebox.showerror("Invalid settings backup", str(exc), parent=self.app)
            return
        window = tk.Toplevel(self.app)
        window.title("Preview settings import")
        panel = ttk.Frame(window, padding=14)
        panel.pack(fill="both", expand=True)
        text = [f"Ollama model: {model or 'No model in backup'}"]
        for key in ("notes", "blocks"):
            incoming = candidate.get(key, {})
            previous = self.app.settings.get(key, {})
            text.append(f"{key.title()}: {len(incoming.keys() - previous.keys())} added, "
                        f"{sum(k in previous and previous[k] != v for k, v in incoming.items())} replaced")
        text.append("Importing block watches does not apply Windows actions.")
        ttk.Label(panel, text="\n".join(text), justify="left").pack(pady=8)

        def apply(merge):
            existing = self.app.settings
            result = {**existing, **candidate} if merge else dict(candidate)
            for key in ("notes", "blocks"):
                if merge:
                    result[key] = {**existing.get(key, {}), **candidate.get(key, {})}
            try:
                A.SCANS_DIR.mkdir(exist_ok=True)
                backup = A.SCANS_DIR / f"settings-before-import-{uuid4().hex}.backup.json"
                backup.write_text(json.dumps({"version": 1, "settings": existing}), encoding="utf-8")
                save_settings(result)
            except OSError as exc:
                messagebox.showerror("Import failed", str(exc), parent=window)
                return
            self.app.settings = result
            if result.get("model"):
                os.environ["SCANNER_OLLAMA_MODEL"] = result["model"]
            else:
                os.environ.pop("SCANNER_OLLAMA_MODEL", None)
            self.compare()
            self.app.refresh()
            window.destroy()

        self.button(panel, "Merge", lambda: apply(True))
        self.button(panel, "Replace", lambda: apply(False))
        self.button(panel, "Cancel", window.destroy)
