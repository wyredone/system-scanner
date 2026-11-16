"""System Scanner - GUI.

Scans Windows services, drivers, startup entries, scheduled tasks, hijack points,
WMI persistence, antivirus status and remote-access history, and flags anything
that looks like malware or unwanted remote access. READ-ONLY: it never changes,
stops, deletes or uploads anything.

Start with "Scan Computer.bat" (normal) or "Scan Computer (Admin).bat" (complete scan).
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import analysis as A

SEV_COLORS = {"High": "#f8c9c4", "Medium": "#fde7b0", "Low": "#dbe9f7", "Info": "#ffffff"}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        alt = exe[:-10] + "pythonw.exe"
        if os.path.exists(alt):
            exe = alt
    script = str(Path(__file__).resolve())
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f'"{script}"', str(A.APP_DIR), 1)
    return rc > 32


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("System Scanner" + ("  (Administrator)" if is_admin() else ""))
        self.geometry("1280x800")
        self.minsize(900, 560)
        self.findings: list[A.Finding] = []
        self.meta: dict = {}
        self.scan_file: Path | None = None
        self.visible: list[A.Finding] = []
        self._build()
        self.after(200, self.start_scan)

    # ------------------------------------------------------------ layout
    def _build(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22)

        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        self.scan_btn = ttk.Button(top, text="Scan now", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.admin_btn = ttk.Button(top, text="Restart as Administrator", command=self.on_admin)
        self.admin_btn.pack(side="left", padx=(6, 0))
        if is_admin():
            self.admin_btn.state(["disabled"])
        ttk.Button(top, text="Open saved scan...", command=self.on_open).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Export report (HTML)", command=self.on_export_html).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Export CSV", command=self.on_export_csv).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Scans folder", command=lambda: os.startfile(A.SCANS_DIR)).pack(side="left", padx=(6, 0))
        self.progress = ttk.Progressbar(top, mode="indeterminate", length=160)
        self.progress.pack(side="right")
        self.status = tk.StringVar(value="Ready")
        ttk.Label(top, textvariable=self.status, width=40, anchor="e").pack(side="right", padx=8)

        self.summary = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.summary, padding=(10, 0), font=("Segoe UI", 10, "bold")).pack(fill="x")

        filt = ttk.Frame(self, padding=(8, 4))
        filt.pack(fill="x")
        ttk.Label(filt, text="Show:").pack(side="left")
        self.sev_vars = {}
        for s in A.SEVERITIES:
            v = tk.BooleanVar(value=s != "Info")
            self.sev_vars[s] = v
            ttk.Checkbutton(filt, text=s, variable=v, command=self.refresh).pack(side="left", padx=3)
        ttk.Label(filt, text="   Category:").pack(side="left")
        self.cat_var = tk.StringVar(value="All")
        self.cat_box = ttk.Combobox(filt, textvariable=self.cat_var, state="readonly", width=16, values=["All"])
        self.cat_box.pack(side="left")
        self.cat_box.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(filt, text="   Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh())
        ttk.Entry(filt, textvariable=self.search_var, width=28).pack(side="left")
        self.hide_ms = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text="Hide Microsoft-signed", variable=self.hide_ms, command=self.refresh).pack(side="left", padx=8)
        self.only_new = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text="Only NEW since last scan", variable=self.only_new, command=self.refresh).pack(side="left")

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        tree_frame = ttk.Frame(pane)
        cols = ("sev", "new", "cat", "name", "signer", "why")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for c, label, w, stretch in (("sev", "Severity", 75, False), ("new", "New", 45, False),
                                      ("cat", "Category", 105, False), ("name", "Name", 340, True),
                                      ("signer", "Signed by", 200, False), ("why", "Why flagged", 460, True)):
            self.tree.heading(c, text=label, command=lambda c=c: self.sort_by(c))
            self.tree.column(c, width=w, stretch=stretch, anchor="w")
        for s, col in SEV_COLORS.items():
            self.tree.tag_configure(s, background=col)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda e: self.on_open_location())
        pane.add(tree_frame, weight=3)

        det = ttk.Frame(pane)
        btns = ttk.Frame(det)
        btns.pack(fill="x", pady=(0, 4))
        ttk.Button(btns, text="Check hash on VirusTotal", command=self.on_virustotal).pack(side="left")
        ttk.Button(btns, text="Open file location", command=self.on_open_location).pack(side="left", padx=6)
        ttk.Button(btns, text="Copy SHA256", command=self.on_copy_hash).pack(side="left")
        ttk.Button(btns, text="Copy details", command=self.on_copy_details).pack(side="left", padx=6)
        ttk.Label(btns, text="Read-only: nothing is changed. 'High' = worth investigating, not proof of malware.",
                  foreground="#666").pack(side="right")
        self.detail = tk.Text(det, height=12, wrap="word", font=("Consolas", 10), relief="solid", borderwidth=1)
        self.detail.pack(fill="both", expand=True)
        self.detail.configure(state="disabled")
        pane.add(det, weight=1)

        self.sort_col, self.sort_rev = "sev", False

    # ------------------------------------------------------------ scanning
    def start_scan(self) -> None:
        self.scan_btn.state(["disabled"])
        self.progress.start(12)
        self.status.set("Starting scan...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        try:
            path = A.run_scan(lambda m: self.after(0, self.status.set, f"Scanning: {m}"))
            self.after(0, self.load_file, path)
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._scan_failed, str(exc))

    def _scan_failed(self, msg: str) -> None:
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        self.status.set("Scan failed")
        messagebox.showerror("Scan failed", msg)

    def load_file(self, path: Path) -> None:
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        try:
            data = A.load_scan(path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Could not read scan", str(exc))
            return
        self.scan_file = Path(path)
        self.meta = data.get("Meta") or {}
        self.findings = A.analyze(data)
        prev = None
        if self.scan_file.parent.resolve() == A.SCANS_DIR.resolve():
            prev = A.previous_scan(self.scan_file)
        n_new = A.mark_new(self.findings, A.load_scan(prev) if prev else None)
        cats = sorted({f.category for f in self.findings})
        self.cat_box.configure(values=["All"] + cats)
        counts = {s: sum(1 for f in self.findings if f.severity == s) for s in A.SEVERITIES}
        new_txt = (f"   |   {n_new} new since {prev.stem.rsplit('_', 2)[1]}-{prev.stem.rsplit('_', 1)[1][:4]}"
                   if prev else "   |   first scan of this PC (next scan will show what changed)")
        self.summary.set(
            f"{self.meta.get('Computer', '?')}   |   scanned {self.meta.get('ScanTime', '')}   |   "
            f"{'Administrator' if self.meta.get('Admin') else 'NOT admin (partial)'}   |   "
            f"High {counts['High']}   Medium {counts['Medium']}   Low {counts['Low']}   Info {counts['Info']}"
            + new_txt)
        self.status.set(f"Loaded {self.scan_file.name}")
        self.refresh()

    # ------------------------------------------------------------ table
    def refresh(self) -> None:
        q = self.search_var.get().strip().lower()
        cat = self.cat_var.get()
        rows = []
        for f in self.findings:
            if not self.sev_vars[f.severity].get():
                continue
            if cat != "All" and f.category != cat:
                continue
            if self.hide_ms.get() and f.microsoft_signed:
                continue
            if self.only_new.get() and not f.is_new:
                continue
            if q and q not in f"{f.name} {f.command} {f.path} {f.signer} {f.company} {' '.join(f.reasons)}".lower():
                continue
            rows.append(f)
        keyf = {
            "sev": lambda f: (A.SEV_RANK[f.severity], f.category, f.name.lower()),
            "new": lambda f: (not f.is_new, A.SEV_RANK[f.severity]),
            "cat": lambda f: (f.category, A.SEV_RANK[f.severity]),
            "name": lambda f: f.name.lower(),
            "signer": lambda f: f.signer.lower(),
            "why": lambda f: " ".join(f.reasons).lower(),
        }[self.sort_col]
        rows.sort(key=keyf, reverse=self.sort_rev)
        self.visible = rows
        self.tree.delete(*self.tree.get_children())
        for i, f in enumerate(rows):
            self.tree.insert("", "end", iid=str(i), tags=(f.severity,),
                             values=(f.severity, "NEW" if f.is_new else "", f.category, f.name,
                                     f.signer or (f.sig if f.sig not in ("Valid", "") else ""),
                                     " | ".join(f.reasons)))
        self._show_detail(None)

    def sort_by(self, col: str) -> None:
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        self.refresh()

    def selected(self) -> A.Finding | None:
        sel = self.tree.selection()
        return self.visible[int(sel[0])] if sel else None

    def on_select(self, _event=None) -> None:
        self._show_detail(self.selected())

    def _show_detail(self, f: A.Finding | None) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", f.as_text() if f else
                           f"{len(self.visible)} of {len(self.findings)} entries shown. Click a row for details.")
        self.detail.configure(state="disabled")

    # ------------------------------------------------------------ actions
    def on_admin(self) -> None:
        if relaunch_as_admin():
            self.destroy()

    def on_open(self) -> None:
        p = filedialog.askopenfilename(initialdir=A.SCANS_DIR, filetypes=[("Scan files", "*.json")])
        if p:
            self.load_file(Path(p))

    def _default_name(self, ext: str) -> str:
        return (self.scan_file.stem if self.scan_file else "scan") + ext

    def on_export_html(self) -> None:
        if not self.findings:
            return
        p = filedialog.asksaveasfilename(initialdir=A.SCANS_DIR, initialfile=self._default_name(".html"),
                                         defaultextension=".html", filetypes=[("HTML", "*.html")])
        if p:
            A.export_html(self.findings, self.meta, Path(p))
            webbrowser.open(Path(p).as_uri())

    def on_export_csv(self) -> None:
        if not self.findings:
            return
        p = filedialog.asksaveasfilename(initialdir=A.SCANS_DIR, initialfile=self._default_name(".csv"),
                                         defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if p:
            A.export_csv(self.findings, Path(p))
            self.status.set(f"Saved {Path(p).name}")

    def on_virustotal(self) -> None:
        f = self.selected()
        if f and f.sha256:
            # Opens a hash lookup in your browser. The file itself is never uploaded.
            webbrowser.open(f"https://www.virustotal.com/gui/file/{f.sha256}")
        else:
            self.status.set("No file hash for this entry")

    def on_open_location(self) -> None:
        f = self.selected()
        if f and f.path and os.path.exists(f.path):
            subprocess.Popen(["explorer.exe", "/select,", f.path])
        elif f:
            self.status.set("File not found on disk")

    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status.set("Copied to clipboard")

    def on_copy_hash(self) -> None:
        f = self.selected()
        if f and f.sha256:
            self._copy(f.sha256)

    def on_copy_details(self) -> None:
        f = self.selected()
        if f:
            self._copy(f.as_text())


def main() -> None:
    if "--elevate" in sys.argv and not is_admin():
        if relaunch_as_admin():
            return
        # User declined the UAC prompt: carry on with a normal scan.
    App().mainloop()


if __name__ == "__main__":
    main()
