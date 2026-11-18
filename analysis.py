"""System Scanner - analysis rules, scan runner, baseline comparison and reports.

Everything here only reads data. Nothing is changed, stopped, deleted or uploaded.

Command line use (no GUI):
    python analysis.py            run a new scan and print the High/Medium findings
    python analysis.py scan.json  analyze an existing scan file
"""
from __future__ import annotations

import csv
import html
import json
import ntpath
import os
import re
import subprocess
import tempfile
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
ENGINE = APP_DIR / "engine" / "collect.ps1"
SCANS_DIR = APP_DIR / "scans"

SEVERITIES = ["High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RECENT_REMOTE_DAYS = 14

# ---------------------------------------------------------------- patterns
USER_WRITABLE = re.compile(
    r"\\(appdata|temp|tmp|programdata|users\\public|downloads|\$recycle\.bin|perflogs|windows\\temp)\\",
    re.I)
WINDOWS_DIR = re.compile(r"^[a-z]:\\windows\\", re.I)
SUSPICIOUS_CMD = re.compile(
    r"(-enc(odedcommand)?\s|-e\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?\b|frombase64string|"
    r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|mshta|"
    r"regsvr32\b.*(/i:|scrobj)|rundll32\b.*\\(appdata|temp|programdata|users)\\|rundll32\b.*javascript:|"
    r"certutil\b.*-(urlcache|decode)|bitsadmin\b.*/transfer|wscript|cscript|\.vbs\b|\.vbe\b|\.jse?\b|\.hta\b|"
    r"\.wsf\b|https?://|cmd(\.exe)?\s+/c\s+.*(powershell|curl|echo)|\bcurl\b.*\|)",
    re.I)
SYSTEM_BINARY_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe", "services.exe", "smss.exe",
    "spoolsv.exe", "taskhostw.exe", "rundll32.exe", "conhost.exe", "dllhost.exe", "wininit.exe",
    "lsm.exe", "taskmgr.exe", "ctfmon.exe", "searchindexer.exe", "runtimebroker.exe",
}
MASQUERADE = re.compile(r"svch0st|scvhost|svhost|svchosts|lsas\.|lsasss|csrsss|expl0rer|explore\.exe|winlog0n|"
                        r"rundl132|spoo1sv|taskh0st", re.I)
REMOTE_TOOLS = re.compile(
    r"anydesk|teamviewer|ultraviewer|ultraview|rustdesk|screenconnect|connectwise|splashtop|logmein|"
    r"gotoassist|goto opener|supremo|aeroadmin|ammyy|remote utilities|rutserv|rfusclient|netsupport|"
    r"client32\.exe|dwservice|dwagent|zoho assist|zohomeeting|bomgar|beyondtrust|atera|tightvnc|"
    r"ultravnc|realvnc|winvnc|vncserver|tvnserver|parsec|chrome remote desktop|remoting_host|remotepc|"
    r"meshagent|action1|level\.io|simplehelp|syncro|kaseya|ninjarmm", re.I)


@dataclass
class Finding:
    severity: str
    category: str
    name: str
    command: str = ""
    path: str = ""
    signer: str = ""
    sig: str = ""
    created: str = ""
    sha256: str = ""
    company: str = ""
    reasons: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    is_new: bool = False

    @property
    def key(self) -> str:
        return "|".join(x.lower() for x in (self.category, self.name, self.path or "", self.command or ""))

    @property
    def microsoft_signed(self) -> bool:
        return self.sig == "Valid" and "microsoft" in (self.signer or "").lower()

    def as_text(self) -> str:
        lines = [
            f"Severity:  {self.severity}" + ("   (NEW since last scan)" if self.is_new else ""),
            f"Category:  {self.category}",
            f"Name:      {self.name}",
            f"Command:   {self.command}",
            f"File:      {self.path}",
            f"Signature: {self.sig or 'n/a'}" + (f"  -  {self.signer}" if self.signer else ""),
            f"Company:   {self.company}",
            f"Created:   {self.created}",
            f"SHA256:    {self.sha256}",
        ]
        if self.details:
            lines.append("Details:   " + "; ".join(f"{k}={v}" for k, v in self.details.items() if v not in ("", None)))
        lines.append("")
        lines.append("Why flagged:" if self.reasons else "Why flagged: nothing suspicious found")
        lines += [f"  - {r}" for r in self.reasons]
        return "\n".join(lines)


def _bump(sev: str, to: str) -> str:
    return to if SEV_RANK[to] < SEV_RANK[sev] else sev


def _demote(sev: str) -> str:
    return SEVERITIES[min(SEV_RANK[sev] + 1, len(SEVERITIES) - 1)]


# ---------------------------------------------------------------- rules
def analyze_item(it: dict) -> Finding:
    cat = it.get("Category", "")
    path = it.get("Path") or ""
    cmd = it.get("Command") or ""
    sig = it.get("Sig") or ""
    exists = bool(it.get("Exists"))
    details = it.get("Details") or {}
    f = Finding(severity="Info", category=cat, name=it.get("Name", ""), command=cmd, path=path,
                signer=it.get("Signer") or "", sig=sig, created=it.get("Created") or "",
                sha256=it.get("SHA256") or "", company=it.get("Company") or "", details=details)
    sev = "Info"
    reasons = f.reasons
    signed_ok = sig == "Valid"
    in_user_dir = bool(USER_WRITABLE.search(path))
    base = ntpath.basename(path).lower()
    text = f"{f.name} {cmd} {path} {f.company}"

    if base in SYSTEM_BINARY_NAMES and path and not WINDOWS_DIR.match(path):
        sev = _bump(sev, "High"); reasons.append(f"Uses a Windows system file name ({base}) outside C:\\Windows")
    if MASQUERADE.search(text):
        sev = _bump(sev, "High"); reasons.append("Name imitates a Windows system process")
    if SUSPICIOUS_CMD.search(cmd):
        sev = _bump(sev, "High" if (not signed_ok or in_user_dir) else "Medium")
        reasons.append("Command line uses scripting, encoding, hidden windows or downloads (common malware tricks)")
    if details.get("PayloadPath"):
        payload_sig = details.get("PayloadSignature")
        if payload_sig != "Valid":
            severity = "High" if payload_sig == "HashMismatch" else "Medium"
            sev = _bump(sev, severity)
            reasons.append(f"Referenced script or DLL signature status: {payload_sig or 'unknown'}")
    if cat in ("IFEO", "AppCertDll"):
        sev = _bump(sev, "Medium" if signed_ok else "High")
        reasons.append("Hijacks how another program starts (Image File Execution Options / AppCert DLL)")
    if exists and sig == "HashMismatch":
        sev = _bump(sev, "High"); reasons.append("File was modified after it was signed (signature hash mismatch)")
    if exists and not signed_ok and in_user_dir:
        sev = _bump(sev, "High"); reasons.append("Unsigned program running from a user-writable folder")
    elif exists and not signed_ok and WINDOWS_DIR.match(path) and "microsoft" in f.company.lower():
        sev = _bump(sev, "Low")
        reasons.append("Windows file whose catalog signature could not be confirmed (usually a harmless "
                       "Windows quirk; check the hash on VirusTotal if unsure)")
    elif exists and not signed_ok:
        sev = _bump(sev, "Medium")
        reasons.append(f"Not signed by a trusted publisher (signature status: {sig})")
    elif exists and in_user_dir:
        sev = _bump(sev, "Low"); reasons.append("Runs from a user-writable folder (signed, so probably fine)")

    if REMOTE_TOOLS.search(text):
        sev = _bump(sev, "Medium")
        reasons.append("Remote-access tool: gives someone full control of this PC. Make sure you installed it")

    if not exists and path:
        if cat == "Service" and details.get("StartMode") == "Auto":
            sev = _bump(sev, "Medium"); reasons.append("Auto-start service whose program file is missing")
        else:
            sev = _bump(sev, "Low"); reasons.append("Points to a file that no longer exists (leftover entry)")
    if cat == "Service" and not path and details.get("Note"):
        reasons.append(details["Note"])

    if cat == "Task" and details.get("Hidden") and not f.name.lower().startswith("\\microsoft\\"):
        sev = _bump(sev, "Medium"); reasons.append("Hidden scheduled task from a non-Microsoft folder")

    if (cat == "Service" and cmd and not cmd.startswith('"') and " " in cmd.split(".exe")[0]
            and not WINDOWS_DIR.match(cmd) and "\\windowsapps\\" not in cmd.lower()
            and "localsystem" in str(details.get("Account", "")).lower()):
        sev = _bump(sev, "Low")
        reasons.append("Unquoted service path with spaces (a privilege-escalation weakness, not malware)")

    disabled = (cat == "Task" and str(details.get("State", "")).lower() == "disabled") or \
               (cat in ("Service", "Driver") and str(details.get("StartMode", "")).lower() == "disabled")
    if disabled and sev != "Info":
        sev = _demote(sev); reasons.append("Currently disabled, so it does not run")

    f.severity = sev
    return f


def _parse_when(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            pass
    return None


def analyze_global(data: dict) -> list[Finding]:
    out: list[Finding] = []
    meta = data.get("Meta") or {}

    for section, status in (meta.get("Coverage") or {}).items():
        partial = str(status).startswith("Partial")
        out.append(Finding("Medium" if partial else "Info", "Coverage", section, reasons=[status]))

    # Antivirus
    av = data.get("Antivirus") or []
    if isinstance(av, dict):
        av = [av]
    enabled = [a for a in av if a.get("Enabled")]
    for a in av:
        f = Finding("Info", "Security", f"Antivirus: {a.get('Name')}",
                    details={"Enabled": a.get("Enabled"), "UpToDate": a.get("UpToDate"), "State": a.get("State")})
        if a.get("Enabled") and not a.get("UpToDate"):
            f.severity = "Medium"; f.reasons.append("Antivirus is on but its definitions are out of date")
        if not a.get("Enabled") and a.get("Name", "").lower().startswith("windows defender") and enabled:
            f.reasons.append(f"Defender is off because another antivirus is active ({enabled[0].get('Name')}); that is normal")
        out.append(f)
    if av and not enabled:
        out.append(Finding("High", "Security", "No antivirus is turned on",
                           reasons=["Windows Security reports no enabled antivirus product"]))

    # Winlogon
    hj = data.get("Hijack") or {}
    shell = (hj.get("WinlogonShell") or "").strip().lower()
    if shell and shell not in ("explorer.exe", "c:\\windows\\explorer.exe"):
        out.append(Finding("High", "Winlogon", "Shell", command=hj.get("WinlogonShell"),
                           reasons=["Windows logon shell is not explorer.exe (classic persistence trick)"]))
    ui = (hj.get("WinlogonUserinit") or "").strip().lower().rstrip(",")
    if ui and ui not in ("c:\\windows\\system32\\userinit.exe", "userinit.exe"):
        out.append(Finding("High", "Winlogon", "Userinit", command=hj.get("WinlogonUserinit"),
                           reasons=["Userinit runs extra programs at every logon"]))
    if hj.get("WinlogonTaskman"):
        out.append(Finding("Medium", "Winlogon", "Taskman", command=hj.get("WinlogonTaskman"),
                           reasons=["Task Manager has been replaced"]))
    if hj.get("UserWinlogonShell"):
        out.append(Finding("High", "Winlogon", "User Shell", command=hj.get("UserWinlogonShell"),
                           reasons=["Per-user logon shell override"]))
    appinit = hj.get("AppInit") or []
    if isinstance(appinit, dict):
        appinit = [appinit]
    for a in appinit:
        if a.get("Enabled"):
            out.append(Finding("High", "AppInit", a.get("Dlls", ""), path=a.get("Dlls", ""), details={"Key": a.get("Key")},
                               reasons=["AppInit DLLs are loaded into almost every program"]))
        else:
            out.append(Finding("Info", "AppInit", a.get("Dlls", ""), path=a.get("Dlls", ""), details={"Key": a.get("Key")},
                               reasons=["AppInit DLL is listed but loading is switched off, so it does nothing"]))

    # WMI
    wmi = data.get("Wmi") or []
    if isinstance(wmi, dict):
        wmi = [wmi]
    for w in wmi:
        t = w.get("Type")
        f = Finding("Info", "WMI", f"{t}: {w.get('Name')}", command=w.get("Payload") or "")
        if t in ("CommandLineConsumer", "ActiveScriptConsumer"):
            f.severity = "High"
            f.reasons.append("WMI event that runs a command or script - a favourite hiding place for fileless malware")
        out.append(f)

    # Remote sessions
    sessions = data.get("RemoteSessions") or []
    if isinstance(sessions, dict):
        sessions = [sessions]
    groups: dict[tuple, list] = {}
    for s in sessions:
        if s.get("Direction") != "Incoming":
            continue
        groups.setdefault((s.get("Tool"), s.get("RemoteId"), s.get("RemoteName") or ""), []).append(s)
    try:
        scan_time = datetime.strptime(meta.get("ScanTime", ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        scan_time = datetime.now()
    for (tool, rid, rname), ss in groups.items():
        whens = sorted(w for w in (_parse_when(s.get("When")) for s in ss) if w)
        last = whens[-1] if whens else None
        f = Finding("Info", "RemoteSession", f"{tool} incoming from {rid}" + (f" ({rname})" if rname else ""),
                    details={"Sessions": len(ss), "First": whens[0].strftime("%Y-%m-%d %H:%M") if whens else "",
                             "Last": last.strftime("%Y-%m-%d %H:%M") if last else "",
                             "Methods": ", ".join(sorted({s.get("Method", "") for s in ss}))})
        if last and scan_time - last <= timedelta(days=RECENT_REMOTE_DAYS):
            f.severity = "Medium"
            f.reasons.append(f"Someone connected to this PC in the last {RECENT_REMOTE_DAYS} days. Confirm it was you or someone you trust")
        else:
            f.reasons.append("Older remote session")
        out.append(f)
    if data.get("AnyDeskUnattended"):
        out.append(Finding("Medium", "RemoteAccess", "AnyDesk unattended access is enabled",
                           reasons=["Anyone with the AnyDesk password can connect without someone accepting. "
                                    "Use a strong password and AnyDesk's Access Control List"]))

    if not meta.get("Admin"):
        out.append(Finding("Info", "Scan", "Scan ran without Administrator rights",
                           reasons=["Some service paths and SYSTEM-level details could not be read. "
                                    "Use 'Scan Computer (Admin).bat' for a complete scan"]))
    return out


def process_findings(data: dict) -> list[Finding]:
    items = data.get("Items") or []
    if isinstance(items, dict):
        items = [items]
    links = {}
    for item in items:
        if item.get("Category") != "Process" and item.get("Path"):
            key = ntpath.normcase(ntpath.normpath(item["Path"]))
            links.setdefault(key, []).append(f"{item['Category']}: {item['Name']}")
    results = []
    for item in items:
        if item.get("Category") != "Process":
            continue
        finding = analyze_item(item)
        if finding.path:
            key = ntpath.normcase(ntpath.normpath(finding.path))
            matches = links.get(key, [])
            if matches:
                finding.details = {**finding.details, "Matching scan entries": " | ".join(matches)}
        results.append(finding)
    return sorted(results, key=lambda f: (SEV_RANK[f.severity], f.name.lower()))


def analyze(data: dict) -> list[Finding]:
    items = data.get("Items") or []
    if isinstance(items, dict):
        items = [items]
    findings = [analyze_item(it) for it in items if it.get("Category") != "Process"] + analyze_global(data)
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category, f.name.lower()))
    return findings


# ---------------------------------------------------------------- scanning / storage
def run_scan(progress=None) -> Path:
    """Run the PowerShell collector. Returns the path of the saved raw scan JSON."""
    SCANS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S%f")
    out = SCANS_DIR / f"{os.environ.get('COMPUTERNAME', 'PC')}_{stamp}.json"
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    with tempfile.TemporaryDirectory(dir=SCANS_DIR) as staging:
        pending = Path(staging) / "scan.json"
        proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ENGINE), "-OutFile", str(pending)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            creationflags=flags)
        tail = []
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("PROGRESS|"):
                if progress:
                    progress(line.split("|", 1)[1])
            elif line:
                tail.append(line)
        proc.wait()
        if proc.returncode != 0 or not pending.exists():
            raise RuntimeError("Scan failed:\n" + "\n".join(tail[-20:]))
        load_scan(pending)
        pending.replace(out)
    return out


def load_scan(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("Meta"), dict):
        raise ValueError("Missing scanner metadata")
    items = data.get("Items")
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError("Invalid scanner inventory")
    return data


def previous_scan(current: Path) -> Path | None:
    """Most recent earlier scan of the same computer."""
    computer = current.name.rsplit("_", 2)[0]
    older = sorted(p for p in SCANS_DIR.glob(f"{computer}_*.json") if p.name < current.name and p.name.rsplit("_", 2)[0] == computer)
    return older[-1] if older else None


def comparison_state(f: Finding) -> tuple:
    fields = ("StartMode", "State", "Sessions", "Last", "Enabled", "UpToDate", "PayloadSHA256", "PayloadSignature")
    return (f.sha256, f.sig, f.signer, *(f.details.get(k) for k in fields))


def mark_new(findings: list[Finding], baseline: dict | None) -> int:
    if not baseline:
        return 0
    old = {}
    for prior in analyze(baseline):
        old.setdefault(prior.key, set()).add(comparison_state(prior))
    n = 0
    for f in findings:
        if comparison_state(f) not in old.get(f.key, set()):
            if f.key in old:
                f.reasons.append("Changed since baseline")
            f.is_new = True
            n += 1
    return n


# ---------------------------------------------------------------- export
def export_csv(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Severity", "New", "Category", "Name", "Command", "File", "Signature", "Signer",
                    "Company", "Created", "SHA256", "Reasons", "Details"])
        for f in findings:
            values = [f.severity, "yes" if f.is_new else "", f.category, f.name, f.command, f.path, f.sig,
                        f.signer, f.company, f.created, f.sha256, " | ".join(f.reasons),
                        "; ".join(f"{k}={v}" for k, v in f.details.items())]
            w.writerow(["'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value for value in values])


def export_html(findings: list[Finding], meta: dict, path: Path, min_severity: str = "Low") -> None:
    e = html.escape
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    shown = [f for f in findings if SEV_RANK[f.severity] <= SEV_RANK[min_severity]]
    rows = []
    for f in shown:
        vt = (f'<a href="https://www.virustotal.com/gui/file/{e(f.sha256)}" target="_blank">VirusTotal</a>'
              if f.sha256 else "")
        rows.append(
            f'<tr class="{f.severity.lower()}"><td><b>{e(f.severity)}</b>{" <span class=new>NEW</span>" if f.is_new else ""}</td>'
            f"<td>{e(f.category)}</td><td>{e(f.name)}<div class=cmd>{e(f.command)}</div></td>"
            f"<td>{e(f.sig)}<br>{e(f.signer)}</td><td>{'<br>'.join(e(r) for r in f.reasons)}</td><td>{vt}</td></tr>")
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>System Scan - {e(meta.get('Computer',''))}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#fafafa;color:#222}}
table{{border-collapse:collapse;width:100%;background:#fff}} td,th{{border:1px solid #ddd;padding:6px 8px;vertical-align:top;font-size:13px}}
th{{background:#333;color:#fff;text-align:left}} .cmd{{color:#666;font-family:Consolas,monospace;font-size:11px;word-break:break-all}}
tr.high td:first-child{{background:#f8c9c4}} tr.medium td:first-child{{background:#fde7b0}} tr.low td:first-child{{background:#dbe9f7}}
.new{{background:#7b2cbf;color:#fff;border-radius:3px;padding:0 4px;font-size:11px}} .pill{{display:inline-block;margin-right:12px}}
</style></head><body>
<h1>System Scan Report</h1>
<p><b>Computer:</b> {e(str(meta.get('Computer','')))} &nbsp; <b>User:</b> {e(str(meta.get('User','')))} &nbsp;
<b>Admin scan:</b> {e(str(meta.get('Admin','')))} &nbsp; <b>When:</b> {e(str(meta.get('ScanTime','')))} &nbsp; <b>OS:</b> {e(str(meta.get('OS','')))}</p>
<p>{''.join(f'<span class=pill><b>{s}:</b> {counts[s]}</span>' for s in SEVERITIES)}</p>
<p>Showing {e(min_severity)} and above. This scan only reads the system; "High" means worth investigating, not proof of malware.</p>
<table><tr><th>Severity</th><th>Category</th><th>Name / command</th><th>Signature</th><th>Why flagged</th><th>Check</th></tr>
{''.join(rows)}</table></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


# ---------------------------------------------------------------- CLI
def main(argv: list[str]) -> int:
    if len(argv) > 1:
        scan = Path(argv[1])
    else:
        scan = run_scan(lambda m: print("  ...", m, flush=True))
    data = load_scan(scan)
    findings = analyze(data)
    prev = previous_scan(scan) if scan.parent.resolve() == SCANS_DIR.resolve() else None
    n_new = mark_new(findings, load_scan(prev) if prev else None)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    print(f"\nScan file: {scan}")
    print("Counts:", counts, f"| new since last scan: {n_new}" if prev else "| no earlier scan to compare")
    for f in findings:
        if f.severity in ("High", "Medium"):
            print(f"\n[{f.severity}]{' NEW' if f.is_new else ''} {f.category}: {f.name}")
            for r in f.reasons:
                print("    -", r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
