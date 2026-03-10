/*
    HashGuard - Persistence and Lateral Movement YARA Rules
    Detects techniques for maintaining access and spreading through networks.
*/

rule Persistence_Registry_Run_Keys
{
    meta:
        description = "Detects Registry Run key persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1547.001"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($run*) and 1 of ($api*)
}

rule Persistence_Scheduled_Task
{
    meta:
        description = "Detects scheduled task creation for persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1053.005"
    strings:
        $st1 = "schtasks" ascii nocase
        $st2 = "/create" ascii nocase
        $st3 = "ITaskScheduler" ascii
        $st4 = "Schedule.Service" ascii
        $st5 = "\\Microsoft\\Windows\\Task Scheduler" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Persistence_WMI_Event
{
    meta:
        description = "Detects WMI event subscription persistence"
        severity = "critical"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1546.003"
    strings:
        $w1 = "__EventFilter" ascii
        $w2 = "__EventConsumer" ascii
        $w3 = "__FilterToConsumerBinding" ascii
        $w4 = "CommandLineEventConsumer" ascii
        $w5 = "ActiveScriptEventConsumer" ascii
        $w6 = "Win32_ProcessStartTrace" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Persistence_Service_Creation
{
    meta:
        description = "Detects Windows service installation for persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1543.003"
    strings:
        $s1 = "CreateServiceA" ascii
        $s2 = "CreateServiceW" ascii
        $s3 = "ChangeServiceConfig" ascii
        $s4 = "StartService" ascii
        $s5 = "sc create" ascii nocase
        $s6 = "sc config" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Persistence_COM_Hijack
{
    meta:
        description = "Detects COM object hijacking for persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1546.015"
    strings:
        $c1 = "\\Software\\Classes\\CLSID\\" ascii nocase
        $c2 = "\\InprocServer32" ascii nocase
        $c3 = "\\TreatAs" ascii nocase
        $c4 = "CoCreateInstance" ascii
        $c5 = "DllGetClassObject" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Persistence_Bootkit_MBR
{
    meta:
        description = "Detects MBR/bootkit modification attempts"
        severity = "critical"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1542.003"
    strings:
        $m1 = "\\\\.\\PhysicalDrive0" ascii
        $m2 = "\\\\.\\PhysicalDrive" ascii
        $m3 = "DeviceIoControl" ascii
        $m4 = "IOCTL_DISK_SET_DRIVE_LAYOUT" ascii
        $m5 = { 55 AA }
    condition:
        uint16(0) == 0x5A4D and 2 of ($m1, $m2, $m3, $m4) and $m5
}

rule Persistence_Image_File_Execution
{
    meta:
        description = "Detects Image File Execution Options debugger persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1546.012"
    strings:
        $ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii nocase
        $dbg = "Debugger" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $ifeo and $dbg
}

rule Persistence_AppInit_DLLs
{
    meta:
        description = "Detects AppInit_DLLs persistence"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1546.010"
    strings:
        $s1 = "AppInit_DLLs" ascii nocase
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii nocase
        $s3 = "LoadAppInit_DLLs" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule LateralMovement_PsExec_Pattern
{
    meta:
        description = "Detects PsExec-like remote execution patterns"
        severity = "critical"
        author = "HashGuard"
        category = "lateral_movement"
        mitre = "T1569.002"
    strings:
        $p1 = "\\ADMIN$\\" ascii
        $p2 = "\\IPC$" ascii
        $p3 = "PSEXESVC" ascii
        $p4 = "\\pipe\\svcctl" ascii
        $a1 = "OpenSCManager" ascii
        $a2 = "CreateServiceA" ascii
        $a3 = "StartService" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($p*) or (1 of ($p*) and 2 of ($a*)))
}

rule LateralMovement_WMI_Remote
{
    meta:
        description = "Detects WMI-based remote execution"
        severity = "high"
        author = "HashGuard"
        category = "lateral_movement"
        mitre = "T1047"
    strings:
        $w1 = "Win32_Process" ascii
        $w2 = "Win32_Service" ascii
        $w3 = "IWbemServices" ascii
        $w4 = "ExecMethod" ascii
        $w5 = "Create" ascii
        $w6 = "wmic" ascii nocase
        $w7 = "/node:" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule LateralMovement_RDP_Hijacking
{
    meta:
        description = "Detects RDP session hijacking attempts"
        severity = "critical"
        author = "HashGuard"
        category = "lateral_movement"
        mitre = "T1563.002"
    strings:
        $r1 = "tscon.exe" ascii nocase
        $r2 = "mstsc.exe" ascii nocase
        $r3 = "WTSConnectSession" ascii
        $r4 = "WTSDisconnectSession" ascii
        $r5 = "WTSEnumerateSessions" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule LateralMovement_DCSync
{
    meta:
        description = "Detects DCSync replication attack patterns"
        severity = "critical"
        author = "HashGuard"
        category = "lateral_movement"
        mitre = "T1003.006"
    strings:
        $dc1 = "DRSGetNCChanges" ascii
        $dc2 = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" ascii nocase
        $dc3 = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" ascii nocase
        $dc4 = "DsGetDomainController" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule LateralMovement_Pass_The_Hash
{
    meta:
        description = "Detects Pass-the-Hash attack patterns"
        severity = "critical"
        author = "HashGuard"
        category = "lateral_movement"
        mitre = "T1550.002"
    strings:
        $p1 = "sekurlsa" ascii nocase
        $p2 = "LsaLogonUser" ascii
        $p3 = "NTLMSSP" ascii
        $p4 = "LogonUserA" ascii
        $p5 = "ImpersonateLoggedOnUser" ascii
        $p6 = "NtlmHash" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Persistence_DLL_Search_Order
{
    meta:
        description = "Detects potential DLL search order hijacking"
        severity = "medium"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1574.001"
    strings:
        $s1 = "SetDllDirectory" ascii
        $s2 = "AddDllDirectory" ascii
        $s3 = "LoadLibraryEx" ascii
        $s4 = "LOAD_WITH_ALTERED_SEARCH_PATH" ascii
        $s5 = "\\System32\\" ascii nocase
        $s6 = "\\SysWOW64\\" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or $s2) and $s3 and 1 of ($s4, $s5, $s6)
}

rule Persistence_Startup_Folder
{
    meta:
        description = "Detects startup folder persistence writes"
        severity = "high"
        author = "HashGuard"
        category = "persistence"
        mitre = "T1547.001"
    strings:
        $s1 = "\\Start Menu\\Programs\\Startup" ascii nocase
        $s2 = "CSIDL_STARTUP" ascii
        $s3 = "FOLDERID_Startup" ascii
        $s4 = "SHGetFolderPath" ascii
        $s5 = "SHGetKnownFolderPath" ascii
        $w = "WriteFile" ascii
        $c = "CopyFile" ascii
    condition:
        uint16(0) == 0x5A4D and (1 of ($s1, $s2, $s3)) and ($s4 or $s5) and ($w or $c)
}
