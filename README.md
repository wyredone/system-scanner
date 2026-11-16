# System Scanner

Scans a Windows PC for malware persistence and unwanted remote access. **Read-only**:
scans only collect data. Process termination is a separate, confirmed action.

## Run it

| Launcher | What it does |
|---|---|
| `Scan Computer.bat` | Normal scan, no admin prompt. Some SYSTEM-level details are hidden. |
| `Scan Computer (Admin).bat` | Complete scan. Windows asks for Administrator permission. |

The window scans automatically when it opens (about 1 minute).

To scan another PC, copy this whole folder to it. It needs Python 3 (python.org, standard
install; no extra packages).

## What it checks

- Services (including the real DLL behind `svchost` services) and non-Microsoft drivers
- Registry Run/RunOnce keys, Startup folders
- Scheduled tasks (programs and COM handlers)
- Hijack points: Winlogon Shell/Userinit, AppInit DLLs, Image File Execution Options,
  SilentProcessExit, AppCertDlls
- WMI event subscriptions (fileless malware)
- Antivirus status (Windows Security Center, Defender)
- Remote-access tools (AnyDesk, TeamViewer, UltraViewer, RustDesk, ScreenConnect, ...),
  AnyDesk unattended access, and AnyDesk/TeamViewer incoming-session history

Every program file gets a signature check, publisher, creation date and SHA-256.

## Help and local AI

Open **User Guide** in the app or read [user-guide.html](user-guide.html). Click
**?** beside a group of controls for help. Select a finding or process and click
**Explain This Finding** to request an advisory summary from local Ollama.
The default model is `llama3.1:8b`. The guide covers installation and model selection.

## Running Processes

Scan the local PC, open **Running Processes**, and select a row to see the executable,
signature, hash, and related scan entries. **Stop Selected Process** force-stops one
process after confirmation. Save any work in that process first. Use the admin
launcher if the normal scan lacks access. Saved scans are view-only.

The stop action verifies the process path and creation time and blocks protected
targets. Results are written locally to `scans/process-actions.jsonl`. A service
or scheduled task can restart a stopped process.

## Reading the results

- **High**: worth investigating now (unsigned program in a user folder, encoded/hidden
  script commands, system-file-name impostors, logon hijacks, WMI command consumers,
  no antivirus).
- **Medium**: confirm you recognise it (unsigned software, remote-access tools, recent
  incoming remote sessions).
- **Low**: usually harmless (leftover entries, signed apps in user folders).
- **Info**: everything else, hidden by default.

High is a reason to look, not proof of malware. Select a row and use
**Check hash on VirusTotal**. That looks up the hash only; the file is never uploaded.

## Comparing scans

Each scan is saved in `scans\COMPUTERNAME_date_time.json`. The next scan of the same PC
marks anything that appeared since then as **NEW**. Tick "Only NEW since last scan" to
see just the changes, which is the quickest way to spot something that installed itself.

**Export report (HTML)** makes a shareable report; **Export CSV** gives everything for Excel.

## Files

- `system_scanner.py`: GUI (tkinter)
- `analysis.py`: rules, baseline comparison, exports. Also a CLI: `py -3 analysis.py`
- `engine\collect.ps1`: the PowerShell collector
