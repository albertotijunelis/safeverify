/*
    HashGuard - Trojan / RAT / Backdoor YARA Rules
*/

rule Trojan_Reverse_Shell
{
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
    strings:
        $s1 = "cmd.exe /c" ascii nocase
        $s2 = "/bin/sh" ascii
        $s3 = "/bin/bash" ascii
        $n1 = "WSAStartup" ascii
        $n2 = "connect" ascii
        $n3 = "CreateProcess" ascii
        $n4 = "socket" ascii
        $p1 = "reverse" ascii nocase
        $p2 = "shell" ascii nocase
        $p3 = "bind" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($s*) and 2 of ($n*) and 1 of ($p*)
}

rule Trojan_Clipboard_Hijacker
{
    meta:
        description = "Detects clipboard monitoring / hijacking"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $a1 = "GetClipboardData" ascii
        $a2 = "SetClipboardData" ascii
        $a3 = "OpenClipboard" ascii
        $a4 = "AddClipboardFormatListener" ascii
        $c1 = "1BvB" ascii
        $c2 = "bc1q" ascii
        $c3 = "0x" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*) and 1 of ($c*)
}

rule Trojan_Screen_Capture
{
    meta:
        description = "Detects screen capture capabilities"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $a1 = "BitBlt" ascii
        $a2 = "GetDesktopWindow" ascii
        $a3 = "GetDC" ascii
        $a4 = "CreateCompatibleBitmap" ascii
        $a5 = "GetDIBits" ascii
        $s1 = "screenshot" ascii nocase
        $s2 = "screen capture" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of ($a*) and 1 of ($s*)
}

rule Trojan_Data_Exfiltration
{
    meta:
        description = "Detects data collection and exfiltration patterns"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $d1 = "passwords" ascii nocase
        $d2 = "credentials" ascii nocase
        $d3 = "cookies" ascii nocase
        $d4 = "wallet.dat" ascii nocase
        $d5 = "Login Data" ascii
        $n1 = "HttpSendRequest" ascii
        $n2 = "InternetOpen" ascii
        $n3 = "FtpPutFile" ascii
        $n4 = "smtp" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($d*) and 1 of ($n*)
}

rule Trojan_Downloader_Generic
{
    meta:
        description = "Detects generic trojan downloader patterns"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "WinHttpOpen" ascii
        $dl4 = "InternetOpenUrl" ascii
        $exec1 = "WinExec" ascii
        $exec2 = "ShellExecuteA" ascii
        $exec3 = "CreateProcessA" ascii
        $tmp = "GetTempPath" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($dl*) and 1 of ($exec*) and $tmp
}

rule Trojan_Dropper_Resource
{
    meta:
        description = "Detects trojan dropping payload from PE resources"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $r1 = "FindResourceA" ascii
        $r2 = "FindResourceW" ascii
        $r3 = "LoadResource" ascii
        $r4 = "LockResource" ascii
        $r5 = "SizeofResource" ascii
        $w = "WriteFile" ascii
        $e = "CreateProcess" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of ($r*) and $w and $e
}

rule Trojan_Registry_Manipulation
{
    meta:
        description = "Detects trojan-style registry manipulation"
        severity = "medium"
        author = "HashGuard"
        category = "trojans"
    strings:
        $reg1 = "RegSetValueExA" ascii
        $reg2 = "RegSetValueExW" ascii
        $reg3 = "RegCreateKeyExA" ascii
        $run = "\\CurrentVersion\\Run" ascii nocase
        $ie = "\\Internet Settings" ascii nocase
        $proxy = "ProxyEnable" ascii
        $disable = "DisableTaskMgr" ascii
        $uac = "EnableLUA" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($reg*) and (($run and 1 of ($reg*)) or $disable or $uac or ($ie and $proxy))
}

rule Trojan_Process_Injection_Classic
{
    meta:
        description = "Detects classic CreateRemoteThread injection"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
    strings:
        $o = "OpenProcess" ascii
        $v = "VirtualAllocEx" ascii
        $w = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $nt = "NtCreateThreadEx" ascii
    condition:
        uint16(0) == 0x5A4D and $o and $v and $w and ($c or $nt)
}

rule Trojan_Firewall_Manipulation
{
    meta:
        description = "Detects firewall rule manipulation"
        severity = "high"
        author = "HashGuard"
        category = "trojans"
    strings:
        $fw1 = "netsh advfirewall" ascii nocase
        $fw2 = "netsh firewall" ascii nocase
        $fw3 = "add rule" ascii nocase
        $fw4 = "delete rule" ascii nocase
        $fw5 = "set rule" ascii nocase
        $fw6 = "INetFwPolicy2" ascii
    condition:
        1 of ($fw1, $fw2, $fw6) and 1 of ($fw3, $fw4, $fw5)
}

rule Trojan_Disable_Security
{
    meta:
        description = "Detects attempts to disable security software"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
    strings:
        $wd1 = "DisableAntiSpyware" ascii nocase
        $wd2 = "DisableRealtimeMonitoring" ascii nocase
        $wd3 = "Windows Defender" ascii nocase
        $wd4 = "Set-MpPreference" ascii nocase
        $wd5 = "-DisableRealtimeMonitoring" ascii
        $kill1 = "taskkill" ascii nocase
        $kill2 = "/im " ascii nocase
        $av1 = "avp.exe" ascii nocase
        $av2 = "MsMpEng.exe" ascii nocase
        $av3 = "avgnt.exe" ascii nocase
    condition:
        2 of ($wd*) or ($kill1 and $kill2 and 1 of ($av*))
}

rule Trojan_UAC_Bypass
{
    meta:
        description = "Detects UAC bypass techniques"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1548.002"
    strings:
        $uac1 = "fodhelper" ascii nocase
        $uac2 = "eventvwr" ascii nocase
        $uac3 = "computerdefaults" ascii nocase
        $uac4 = "sdclt" ascii nocase
        $uac5 = "slui" ascii nocase
        $reg = "ms-settings\\shell" ascii nocase
        $reg2 = "\\shell\\open\\command" ascii nocase
        $hi = "DelegateExecute" ascii
    condition:
        uint16(0) == 0x5A4D and (1 of ($uac*) and ($reg or $reg2)) or ($hi and 1 of ($uac*))
}

rule Trojan_Credential_Dumping_LSASS
{
    meta:
        description = "Detects LSASS credential dumping (Mimikatz-like)"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1003.001"
    strings:
        $l1 = "lsass.exe" ascii nocase
        $l2 = "lsass" ascii nocase
        $api1 = "MiniDumpWriteDump" ascii
        $api2 = "OpenProcess" ascii
        $api3 = "NtReadVirtualMemory" ascii
        $priv = "SeDebugPrivilege" ascii
        $mimi = "mimikatz" ascii nocase
        $mimi2 = "sekurlsa" ascii nocase
        $mimi3 = "kerberos" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($l1 and $api1) or ($l2 and $priv and ($api2 or $api3)) or (2 of ($mimi*)))
}
