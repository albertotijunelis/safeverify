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

rule Trojan_AsyncRAT
{
    meta:
        description = "Detects AsyncRAT remote access trojan"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1219"
    strings:
        $async1 = "AsyncRAT" ascii nocase
        $async2 = "AsyncClient" ascii nocase
        $async3 = "Async_RAT" ascii nocase
        $cfg1 = "Ports" ascii
        $cfg2 = "Hosts" ascii
        $cfg3 = "Install" ascii
        $cfg4 = "MTX" ascii
        $cfg5 = "Pastebin" ascii
        $net1 = "SslStream" ascii
        $net2 = "TcpClient" ascii
        $aes = "Aes256" ascii nocase
        $anti = "AntiAnalysis" ascii
        $key1 = "keylogger" ascii nocase
        $rec = "DesktopRecorder" ascii
    condition:
        (1 of ($async*) and 1 of ($net*)) or
        (3 of ($cfg*) and 1 of ($net*) and $aes) or
        ($anti and 1 of ($key1, $rec) and 1 of ($net*))
}

rule Trojan_QuasarRAT
{
    meta:
        description = "Detects QuasarRAT remote access trojan"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1219"
    strings:
        $q1 = "Quasar" ascii nocase
        $q2 = "QuasarRAT" ascii nocase
        $q3 = "xClient" ascii
        $cfg1 = "SubDirectory" ascii
        $cfg2 = "InstallName" ascii
        $cfg3 = "Mutex" ascii
        $cfg4 = "StartupKey" ascii
        $cmd1 = "DoShellExecute" ascii
        $cmd2 = "DoDownloadAndExecute" ascii
        $cmd3 = "DoVisitWebsite" ascii
        $cmd4 = "DoUploadFile" ascii
        $net1 = "X509Certificate2" ascii
        $net2 = "AES" ascii
    condition:
        uint16(0) == 0x5A4D and ((1 of ($q*) and 2 of ($cfg*)) or
        (3 of ($cmd*)) or
        ($q3 and $net1 and $net2))
}

rule Trojan_DarkGate
{
    meta:
        description = "Detects DarkGate loader/RAT indicators"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1059"
    strings:
        $dg1 = "DarkGate" ascii nocase
        $dg2 = "darkgate" ascii nocase
        $au = "AutoIt" ascii nocase
        $au2 = ".au3" ascii nocase
        $hta = "mshta" ascii nocase
        $ps = "powershell" ascii nocase
        $vbs = "wscript" ascii nocase
        $dl1 = "certutil" ascii nocase
        $dl2 = "bitsadmin" ascii nocase
        $crypto1 = "CryptStringToBinary" ascii
        $cfg1 = "=yes" ascii nocase
        $cfg2 = "=no" ascii nocase
        $mine = "crypto" ascii nocase
        $hvnc = "hVNC" ascii nocase
    condition:
        (1 of ($dg*) and ($au or $au2)) or
        ($hta and $ps and 1 of ($dl*) and ($au or $au2)) or
        (($hvnc or $mine) and ($au or $au2) and 1 of ($cfg*))
}

rule Trojan_Pikabot
{
    meta:
        description = "Detects Pikabot loader indicators"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1055"
    strings:
        $pika1 = "pikabot" ascii nocase
        $dll1 = "DllRegisterServer" ascii
        $inj1 = "NtCreateSection" ascii
        $inj2 = "NtMapViewOfSection" ascii
        $inj3 = "NtQueueApcThread" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "GetTickCount" ascii
        $anti3 = "NtQueryInformationProcess" ascii
        $c2_1 = "Content-Type: application" ascii
        $c2_2 = "POST" ascii
        $junk = { 90 90 90 90 90 90 90 90 }
    condition:
        uint16(0) == 0x5A4D and (($pika1 and $dll1) or
        (2 of ($inj*) and 2 of ($anti*) and $c2_2) or
        ($dll1 and 2 of ($inj*) and $junk))
}

rule Trojan_SilverRAT
{
    meta:
        description = "Detects Silver RAT indicators"
        severity = "critical"
        author = "HashGuard"
        category = "trojans"
        mitre = "T1219"
    strings:
        $sr1 = "SilverRAT" ascii nocase
        $sr2 = "S1lv3r" ascii nocase
        $net1 = "TcpClient" ascii
        $net2 = "SslStream" ascii
        $feat1 = "Keylogger" ascii
        $feat2 = "RansomWare" ascii
        $feat3 = "HVNC" ascii
        $feat4 = "ReverseProxy" ascii
        $feat5 = "PasswordRecovery" ascii
        $cfg1 = "BuilderSettings" ascii
        $prot = "Protobuf" ascii
    condition:
        (1 of ($sr*) and 1 of ($net*)) or
        (3 of ($feat*) and 1 of ($net*)) or
        ($cfg1 and 2 of ($feat*))
}
