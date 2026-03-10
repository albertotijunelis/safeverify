/*
    HashGuard - Default YARA Rules
    These rules detect common suspicious patterns in executables.
*/

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects encoded PowerShell commands"
        severity = "medium"
        author = "HashGuard"
    strings:
        $a1 = "powershell -enc" ascii nocase
        $a2 = "powershell -e " ascii nocase
        $a3 = "powershell -encodedcommand" ascii nocase
        $a4 = "powershell.exe -nop -w hidden" ascii nocase
    condition:
        any of ($a*)
}

rule Suspicious_Process_Injection
{
    meta:
        description = "Detects patterns associated with process injection"
        severity = "high"
        author = "HashGuard"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of ($api*)
}

rule Suspicious_Anti_Debug
{
    meta:
        description = "Detects anti-debugging techniques"
        severity = "medium"
        author = "HashGuard"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess" ascii
        $a4 = "OutputDebugStringA" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of ($a*)
}

rule Suspicious_Crypto_Ransomware
{
    meta:
        description = "Detects patterns associated with ransomware"
        severity = "critical"
        author = "HashGuard"
    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "bitcoin" ascii nocase
        $r3 = "pay the ransom" ascii nocase
        $r4 = ".onion" ascii nocase
        $c1 = "CryptEncrypt" ascii
        $c2 = "CryptGenKey" ascii
        $c3 = "BCryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($r*) or (1 of ($r*) and 1 of ($c*)))
}

rule Suspicious_Keylogger
{
    meta:
        description = "Detects potential keylogger behaviour"
        severity = "high"
        author = "HashGuard"
    strings:
        $a1 = "GetAsyncKeyState" ascii
        $a2 = "SetWindowsHookEx" ascii
        $a3 = "GetKeyboardState" ascii
        $a4 = "keylog" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}
