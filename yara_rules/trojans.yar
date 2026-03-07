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
