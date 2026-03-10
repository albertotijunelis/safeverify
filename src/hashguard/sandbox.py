"""HashGuard Sandbox — Behavioral monitoring framework.

Provides:
- System state snapshots (processes, files, registry, network)
- Diff-based behavior detection (before/after comparison)
- File system monitoring for suspicious writes (temp, startup, AppData)
- ETW-based process creation monitoring (Windows Event Log)
- Windows Sandbox integration (.wsb launch + auto log collection)
- Registry change detection
- Safe monitoring without executing unknown files directly
"""

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class SystemSnapshot:
    """Snapshot of system state at a point in time."""

    timestamp: str = ""
    processes: Dict[int, dict] = field(default_factory=dict)  # pid -> {name, exe, cmdline}
    network_connections: List[dict] = field(default_factory=list)
    files_in_watched: Dict[str, float] = field(default_factory=dict)  # path -> mtime


@dataclass
class BehaviorEvent:
    event_type: str  # process_spawn, file_write, network_connect, persistence, evasion
    timestamp: str
    description: str
    details: dict = field(default_factory=dict)
    severity: str = "medium"


@dataclass
class SandboxResult:
    available: bool = False
    mode: str = "monitor"  # monitor, windows_sandbox
    events: List[BehaviorEvent] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    duration: float = 0.0
    status: str = "not_started"  # not_started, running, completed, error

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "mode": self.mode,
            "status": self.status,
            "duration": round(self.duration, 2),
            "events": [
                {
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "description": e.description,
                    "details": e.details,
                    "severity": e.severity,
                }
                for e in self.events
            ],
            "summary": self.summary,
        }


# ── Suspicious paths to monitor ─────────────────────────────────────────────


def _get_watched_dirs() -> List[str]:
    """Return directories that malware commonly writes to."""
    dirs = []
    temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")

    if temp:
        dirs.append(temp)
    if appdata:
        dirs.append(appdata)
        dirs.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    if localappdata:
        dirs.append(os.path.join(localappdata, "Temp"))
    if userprofile:
        dirs.append(os.path.join(userprofile, "Desktop"))
        dirs.append(os.path.join(userprofile, "Downloads"))

    return [d for d in dirs if os.path.isdir(d)]


# ── Suspicious process heuristics ────────────────────────────────────────────

_SUSPICIOUS_PROCS = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "schtasks.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "wmic.exe",
}

_EVASION_PATTERNS = [
    "taskkill",
    "-enc",
    "-encodedcommand",
    "-windowstyle hidden",
    "bypass",
    "unrestricted",
    "downloadstring",
    "invoke-expression",
    "iex(",
    "new-object net.webclient",
]


def _classify_process(name: str, cmdline: str = "") -> Optional[BehaviorEvent]:
    """Return an event if the process looks suspicious."""
    now = datetime.now().isoformat()
    name_lower = name.lower()
    cmd_lower = cmdline.lower()

    # Living-off-the-land binaries
    if name_lower in _SUSPICIOUS_PROCS:
        sev = "high" if any(p in cmd_lower for p in _EVASION_PATTERNS) else "medium"
        return BehaviorEvent(
            event_type="evasion" if sev == "high" else "process_spawn",
            timestamp=now,
            description=f"Suspicious LOLBin: {name}",
            details={"name": name, "cmdline": cmdline[:300]},
            severity=sev,
        )
    return None


def check_sandbox_availability() -> dict:
    """Check what sandbox capabilities are available."""
    result = {
        "psutil": HAS_PSUTIL,
        "windows_sandbox": _check_windows_sandbox(),
    }
    result["any_available"] = any(result.values())
    return result


def _check_windows_sandbox() -> bool:
    """Check if Windows Sandbox is available."""
    return os.path.isfile(r"C:\Windows\System32\WindowsSandbox.exe")


def take_snapshot() -> SystemSnapshot:
    """Take a detailed snapshot of current system state."""
    snap = SystemSnapshot(timestamp=datetime.now().isoformat())

    if not HAS_PSUTIL:
        return snap

    # Processes — capture name, exe, and command line
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            snap.processes[info["pid"]] = {
                "name": info["name"] or "",
                "exe": info.get("exe") or "",
                "cmdline": " ".join(info.get("cmdline") or []),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Network connections
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status in ("ESTABLISHED", "LISTEN", "SYN_SENT"):
                snap.network_connections.append(
                    {
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
    except (psutil.AccessDenied, OSError):
        pass

    # File system — snapshot mtimes in watched directories
    for d in _get_watched_dirs():
        try:
            for entry in os.scandir(d):
                try:
                    snap.files_in_watched[entry.path] = entry.stat().st_mtime
                except OSError:
                    pass
        except OSError:
            pass

    return snap


def compare_snapshots(before: SystemSnapshot, after: SystemSnapshot) -> List[BehaviorEvent]:
    """Compare two system snapshots and return behavior events."""
    events: List[BehaviorEvent] = []
    now = datetime.now().isoformat()

    # ── New processes ────────────────────────────────────────────────────────
    before_pids = set(before.processes.keys())
    after_pids = set(after.processes.keys())
    for pid in after_pids - before_pids:
        info = after.processes.get(pid, {})
        name = info.get("name", "unknown")
        cmdline = info.get("cmdline", "")

        # Check for suspicious process
        suspicious = _classify_process(name, cmdline)
        if suspicious:
            events.append(suspicious)
        else:
            events.append(
                BehaviorEvent(
                    event_type="process_spawn",
                    timestamp=now,
                    description=f"New process: {name} (PID {pid})",
                    details={"pid": pid, "name": name, "cmdline": cmdline[:200]},
                    severity="low",
                )
            )

    # ── New network connections ──────────────────────────────────────────────
    before_conns = {(c.get("remote", ""), c.get("pid")) for c in before.network_connections}
    for conn in after.network_connections:
        key = (conn.get("remote", ""), conn.get("pid"))
        if key not in before_conns and conn.get("remote"):
            # Resolve process name
            pid = conn.get("pid")
            proc_name = after.processes.get(pid, {}).get("name", "")
            events.append(
                BehaviorEvent(
                    event_type="network_connect",
                    timestamp=now,
                    description=f"New connection to {conn['remote']} by {proc_name} (PID {pid})",
                    details={**conn, "process": proc_name},
                    severity="high",
                )
            )

    # ── File system changes ──────────────────────────────────────────────────
    before_files = set(before.files_in_watched.keys())
    after_files = set(after.files_in_watched.keys())

    # New files
    for fpath in after_files - before_files:
        basename = os.path.basename(fpath).lower()
        # Determine severity based on location/extension
        sev = "medium"
        if "startup" in fpath.lower():
            sev = "critical"
            etype = "persistence"
        elif basename.endswith((".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs")):
            sev = "high"
            etype = "file_write"
        else:
            etype = "file_write"
        events.append(
            BehaviorEvent(
                event_type=etype,
                timestamp=now,
                description=f"New file: {os.path.basename(fpath)}",
                details={"path": fpath, "size": _safe_size(fpath)},
                severity=sev,
            )
        )

    # Modified files (mtime changed)
    for fpath in before_files & after_files:
        old_mt = before.files_in_watched.get(fpath, 0)
        new_mt = after.files_in_watched.get(fpath, 0)
        if new_mt > old_mt:
            events.append(
                BehaviorEvent(
                    event_type="file_write",
                    timestamp=now,
                    description=f"Modified: {os.path.basename(fpath)}",
                    details={"path": fpath},
                    severity="low",
                )
            )

    return events


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def monitor_execution(duration_seconds: int = 30) -> SandboxResult:
    """Monitor system changes for a time period.

    Takes before/after snapshots of processes, network, and file system
    and reports all new activity detected during the monitoring period.
    """
    result = SandboxResult(available=HAS_PSUTIL, mode="monitor")

    if not HAS_PSUTIL:
        result.status = "error"
        return result

    result.status = "running"
    start = time.time()

    before = take_snapshot()
    time.sleep(min(duration_seconds, 120))  # Cap at 2 minutes
    after = take_snapshot()

    result.events = compare_snapshots(before, after)
    result.duration = time.time() - start
    result.status = "completed"

    # Summarize
    for event in result.events:
        result.summary[event.event_type] = result.summary.get(event.event_type, 0) + 1

    return result


# ── Windows Sandbox integration ──────────────────────────────────────────────


def _build_wsb_config(sample_path: str) -> str:
    """Build a .wsb XML config with logon command for auto-analysis."""
    host_folder = os.path.dirname(os.path.abspath(sample_path))
    # Sanitize filename to prevent command injection inside sandbox
    raw_name = os.path.basename(sample_path)
    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)
    # The logon command runs inside the sandbox: collects process list, netstat,
    # and registry snapshot before/after running the sample for 15 seconds
    logon_script = (
        f'powershell -NoProfile -Command "'
        f"$logDir = 'C:\\\\SandboxLogs'; "
        f"New-Item -Path $logDir -ItemType Directory -Force | Out-Null; "
        f"Get-Process | Select-Object Name,Id,Path | Export-Csv $logDir\\\\procs_before.csv -NoType; "
        f"netstat -ano > $logDir\\\\netstat_before.txt; "
        f"reg export HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run $logDir\\\\run_before.reg /y 2>$null; "
        f"Start-Process -FilePath 'C:\\\\Sandbox\\\\{filename}' -ErrorAction SilentlyContinue; "
        f"Start-Sleep -Seconds 15; "
        f"Get-Process | Select-Object Name,Id,Path | Export-Csv $logDir\\\\procs_after.csv -NoType; "
        f"netstat -ano > $logDir\\\\netstat_after.txt; "
        f"reg export HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run $logDir\\\\run_after.reg /y 2>$null; "
        f"Get-ChildItem C:\\\\Sandbox -Recurse | Select-Object FullName,Length,LastWriteTime | "
        f"Export-Csv $logDir\\\\files.csv -NoType; "
        f'"'
    )
    return f"""<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_folder}</HostFolder>
      <SandboxFolder>C:\\Sandbox</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>{logon_script}</Command>
  </LogonCommand>
  <Networking>Disable</Networking>
  <MemoryInMB>2048</MemoryInMB>
</Configuration>"""


def launch_windows_sandbox(sample_path: str) -> SandboxResult:
    """Launch sample in Windows Sandbox (requires Win 10 Pro/Enterprise).

    The sandbox runs with networking disabled and the sample folder is
    mapped read-only.  Returns a SandboxResult with status info.
    """
    result = SandboxResult(mode="windows_sandbox")

    if not _check_windows_sandbox():
        result.status = "error"
        result.events.append(
            BehaviorEvent(
                event_type="process_spawn",
                timestamp=datetime.now().isoformat(),
                description="Windows Sandbox not available (requires Windows 10/11 Pro with feature enabled)",
                severity="low",
            )
        )
        return result

    # Write .wsb config to temp file
    wsb_content = _build_wsb_config(sample_path)
    wsb_path = os.path.join(tempfile.gettempdir(), "hashguard_sandbox.wsb")
    try:
        with open(wsb_path, "w", encoding="utf-8") as f:
            f.write(wsb_content)
    except OSError as e:
        result.status = "error"
        result.events.append(
            BehaviorEvent(
                event_type="process_spawn",
                timestamp=datetime.now().isoformat(),
                description=f"Failed to write .wsb config: {e}",
                severity="medium",
            )
        )
        return result

    # Take before snapshot
    before = take_snapshot()
    result.status = "running"
    result.available = True
    start = time.time()

    try:
        # Launch Windows Sandbox (non-blocking — it opens a GUI window)
        subprocess.Popen(
            [r"C:\Windows\System32\WindowsSandbox.exe", wsb_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result.events.append(
            BehaviorEvent(
                event_type="process_spawn",
                timestamp=datetime.now().isoformat(),
                description=f"Windows Sandbox launched with {os.path.basename(sample_path)}",
                details={"wsb_config": wsb_path, "sample": sample_path},
                severity="low",
            )
        )
    except OSError as e:
        result.status = "error"
        result.events.append(
            BehaviorEvent(
                event_type="process_spawn",
                timestamp=datetime.now().isoformat(),
                description=f"Failed to launch Windows Sandbox: {e}",
                severity="high",
            )
        )
        return result

    # Monitor host for 30 s while sandbox is running
    time.sleep(30)
    after = take_snapshot()

    host_events = compare_snapshots(before, after)
    result.events.extend(host_events)

    result.duration = time.time() - start
    result.status = "completed"

    for event in result.events:
        result.summary[event.event_type] = result.summary.get(event.event_type, 0) + 1

    return result


def generate_sandbox_config(sample_path: str) -> dict:
    """Generate sandbox configuration details for manual use."""
    filename = os.path.basename(sample_path)
    return {
        "windows_sandbox": {
            "wsb_config": _build_wsb_config(sample_path),
            "note": "Requires Windows 10/11 Pro/Enterprise with Windows Sandbox feature enabled",
        },
        "manual_analysis": {
            "commands": [
                f'copy "{sample_path}" C:\\sandbox\\{filename}',
                f"C:\\sandbox\\{filename}",
            ],
            "monitoring": "Use Process Monitor (procmon) and Wireshark for full behavioral capture",
        },
    }


# ── ETW-based Process Creation Monitoring ────────────────────────────────────

_PERSISTENCE_REGISTRY_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SYSTEM\CurrentControlSet\Services",
]


def query_etw_process_events(since_seconds: int = 60) -> List[BehaviorEvent]:
    """Query Windows Security Event Log for recent process creation events.

    Uses Event ID 4688 (process creation) from the Security log, which is
    available without extra tools when audit process creation is enabled.
    Falls back to Sysmon Event ID 1 if Sysmon is installed.
    """
    events = []
    now = datetime.now()

    # Try Windows Security log (Event ID 4688)
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4688}} "
            f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.TimeCreated -gt (Get-Date).AddSeconds(-{since_seconds}) }} | "
            f"Select-Object TimeCreated, @{{N='NewProcess';E={{$_.Properties[5].Value}}}}, "
            f"@{{N='ParentProcess';E={{$_.Properties[13].Value}}}}, "
            f"@{{N='CommandLine';E={{$_.Properties[8].Value}}}} | "
            f"ConvertTo-Json -Compress",
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                new_proc = entry.get("NewProcess", "")
                parent = entry.get("ParentProcess", "")
                cmdline = entry.get("CommandLine", "")
                proc_name = os.path.basename(new_proc) if new_proc else ""
                sev = "medium"
                etype = "process_spawn"
                if proc_name.lower() in _SUSPICIOUS_PROCS:
                    sev = "high"
                    etype = "evasion"
                events.append(
                    BehaviorEvent(
                        event_type=etype,
                        timestamp=str(entry.get("TimeCreated", now.isoformat())),
                        description=f"Process created: {proc_name}",
                        details={
                            "new_process": new_proc,
                            "parent_process": parent,
                            "cmdline": (cmdline or "")[:500],
                        },
                        severity=sev,
                    )
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass

    # Try Sysmon log (Event ID 1) — more detailed if installed
    if not events:
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id=1}} "
                f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.TimeCreated -gt (Get-Date).AddSeconds(-{since_seconds}) }} | "
                f"ForEach-Object {{ $_.ToXml() }} | ConvertTo-Json -Compress",
            ]
            proc = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, str):
                    data = [data]
                events.append(
                    BehaviorEvent(
                        event_type="process_spawn",
                        timestamp=now.isoformat(),
                        description=f"Sysmon detected {len(data)} process creation event(s)",
                        details={"count": len(data), "source": "Sysmon"},
                        severity="medium",
                    )
                )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

    return events


def check_registry_persistence() -> List[BehaviorEvent]:
    """Check common registry persistence locations for suspicious entries."""
    events = []
    now = datetime.now().isoformat()

    try:
        import winreg
    except ImportError:
        return events

    for key_path in _PERSISTENCE_REGISTRY_KEYS:
        for hive, hive_name in [
            (winreg.HKEY_CURRENT_USER, "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        ]:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        val_str = str(value).lower()
                        # Flag suspicious values
                        suspicious = False
                        for indicator in [
                            "powershell",
                            "cmd /c",
                            "wscript",
                            "mshta",
                            "regsvr32",
                            "certutil",
                            "bitsadmin",
                            "\\temp\\",
                            "\\appdata\\local\\temp",
                            "downloadstring",
                            "-enc",
                            "-encodedcommand",
                        ]:
                            if indicator in val_str:
                                suspicious = True
                                break
                        if suspicious:
                            events.append(
                                BehaviorEvent(
                                    event_type="persistence",
                                    timestamp=now,
                                    description=f"Suspicious registry persistence: {hive_name}\\{key_path}\\{name}",
                                    details={
                                        "hive": hive_name,
                                        "key": key_path,
                                        "name": name,
                                        "value": str(value)[:300],
                                    },
                                    severity="high",
                                )
                            )
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue

    return events


def enhanced_monitor(duration_seconds: int = 30) -> SandboxResult:
    """Enhanced monitoring combining snapshot diffs, ETW events, and registry checks.

    This is the recommended monitoring function — it combines all available
    techniques for maximum visibility.
    """
    result = SandboxResult(available=HAS_PSUTIL, mode="enhanced_monitor")

    if not HAS_PSUTIL:
        result.status = "error"
        return result

    result.status = "running"
    start = time.time()

    # Pre-monitoring registry check
    registry_events_before = check_registry_persistence()

    # Standard snapshot monitoring
    before = take_snapshot()
    time.sleep(min(duration_seconds, 120))
    after = take_snapshot()

    result.events = compare_snapshots(before, after)

    # ETW process creation events during the monitoring window
    etw_events = query_etw_process_events(since_seconds=duration_seconds + 5)
    result.events.extend(etw_events)

    # Post-monitoring registry check — flag new entries
    registry_events_after = check_registry_persistence()
    before_descs = {e.description for e in registry_events_before}
    for evt in registry_events_after:
        if evt.description not in before_descs:
            evt.description = f"NEW {evt.description}"
            evt.severity = "critical"
            result.events.append(evt)

    result.duration = time.time() - start
    result.status = "completed"

    for event in result.events:
        result.summary[event.event_type] = result.summary.get(event.event_type, 0) + 1

    return result
