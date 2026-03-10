/*
    HashGuard - Evasion and Anti-Analysis YARA Rules
    Detects anti-debugging, anti-VM, anti-sandbox, AMSI bypass, and obfuscation techniques.
*/

rule Evasion_Anti_Debug_Timing
{
    meta:
        description = "Detects timing-based anti-debugging (RDTSC, QueryPerformanceCounter)"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1497.001"
    strings:
        $rdtsc = { 0F 31 }
        $qpc = "QueryPerformanceCounter" ascii
        $gtc = "GetTickCount" ascii
        $gtc64 = "GetTickCount64" ascii
        $sleep = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and (($rdtsc and $sleep) or (2 of ($qpc, $gtc, $gtc64) and $sleep))
}

rule Evasion_Anti_Debug_NtQuery
{
    meta:
        description = "Detects NtQueryInformationProcess-based anti-debug"
        severity = "high"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1497.001"
    strings:
        $nq = "NtQueryInformationProcess" ascii
        $nqs = "NtQuerySystemInformation" ascii
        $flag = "ProcessDebugPort" ascii
        $flag2 = "ProcessDebugObjectHandle" ascii
        $flag3 = "ProcessDebugFlags" ascii
    condition:
        uint16(0) == 0x5A4D and ($nq or $nqs) and 1 of ($flag*)
}

rule Evasion_Anti_VM_Registry
{
    meta:
        description = "Detects VM detection via registry queries"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1497.001"
    strings:
        $vm1 = "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest" ascii nocase
        $vm2 = "SYSTEM\\CurrentControlSet\\Services\\vmci" ascii nocase
        $vm3 = "SYSTEM\\CurrentControlSet\\Services\\vmhgfs" ascii nocase
        $vm4 = "SOFTWARE\\VMware, Inc." ascii nocase
        $vm5 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii nocase
        $vm6 = "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD" ascii nocase
        $vm7 = "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE" ascii nocase
        $hv1 = "HARDWARE\\ACPI\\DSDT\\VBOX" ascii nocase
        $hv2 = "HARDWARE\\ACPI\\FADT\\VBOX" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Evasion_Anti_VM_Hardware
{
    meta:
        description = "Detects VM detection via hardware fingerprinting"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1497.001"
    strings:
        $hw1 = "VMwareVMware" ascii
        $hw2 = "VBoxVideo" ascii
        $hw3 = "vmware" ascii nocase
        $hw4 = "virtualbox" ascii nocase
        $hw5 = "qemu" ascii nocase
        $hw6 = "xen" ascii nocase
        $hw7 = "Virtual HD" ascii
        $hw8 = "VBOX HARDDISK" ascii nocase
        $cpuid = { 0F A2 }
        $mac1 = "00:0C:29" ascii
        $mac2 = "00:50:56" ascii
        $mac3 = "08:00:27" ascii
    condition:
        uint16(0) == 0x5A4D and (5 of ($hw*) or ($cpuid and 3 of ($hw*)) or (2 of ($mac*) and 1 of ($hw*)))
}

rule Evasion_Anti_Sandbox_Environment
{
    meta:
        description = "Detects sandbox evasion via environment checks"
        severity = "high"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1497.001"
    strings:
        $sb1 = "SbieDll.dll" ascii nocase
        $sb2 = "SxIn.dll" ascii nocase
        $sb3 = "snxhk.dll" ascii nocase
        $sb4 = "cmdvrt32.dll" ascii nocase
        $sb5 = "pstorec.dll" ascii nocase
        $sb6 = "dbghelp.dll" ascii nocase
        $proc1 = "wireshark.exe" ascii nocase
        $proc2 = "procmon.exe" ascii nocase
        $proc3 = "ollydbg.exe" ascii nocase
        $proc4 = "x64dbg.exe" ascii nocase
        $proc5 = "idaq.exe" ascii nocase
        $proc6 = "fiddler.exe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Evasion_Anti_Sandbox_Username
{
    meta:
        description = "Detects sandbox detection via known usernames/hostnames"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
    strings:
        $u1 = "sandbox" ascii nocase
        $u2 = "malware" ascii nocase
        $u3 = "virus" ascii nocase
        $u4 = "sample" ascii nocase
        $u5 = "test" ascii nocase
        $u6 = "john" ascii nocase
        $u7 = "CurrentUser" ascii
        $api = "GetUserName" ascii
    condition:
        uint16(0) == 0x5A4D and $api and 3 of ($u*)
}

rule Evasion_AMSI_Bypass
{
    meta:
        description = "Detects AMSI (Antimalware Scan Interface) bypass"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1562.001"
    strings:
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "amsi.dll" ascii nocase
        $amsi3 = "AmsiInitialize" ascii
        $amsi4 = "AmsiOpenSession" ascii
        $patch1 = { B8 57 00 07 80 C3 }
        $patch2 = "AmsiScanBuffer" ascii
        $vp = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($amsi*) and ($vp or $patch1 or $patch2)
}

rule Evasion_ETW_Patching
{
    meta:
        description = "Detects ETW (Event Tracing for Windows) patching/evasion"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1562.006"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "ntdll.dll" ascii nocase
        $patch = "VirtualProtect" ascii
        $ret = { C2 14 00 }
    condition:
        uint16(0) == 0x5A4D and 1 of ($etw*) and $patch and $ret
}

rule Evasion_Process_Hollowing
{
    meta:
        description = "Detects process hollowing technique"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1055.012"
    strings:
        $a1 = "NtUnmapViewOfSection" ascii
        $a2 = "ZwUnmapViewOfSection" ascii
        $a3 = "NtMapViewOfSection" ascii
        $b1 = "VirtualAllocEx" ascii
        $b2 = "WriteProcessMemory" ascii
        $b3 = "SetThreadContext" ascii
        $b4 = "ResumeThread" ascii
        $c = "CREATE_SUSPENDED" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 2 of ($b*) and $c
}

rule Evasion_Direct_Syscall
{
    meta:
        description = "Detects direct syscall invocation to bypass hooks"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1106"
    strings:
        $syscall32 = { B8 ?? ?? 00 00 BA ?? ?? ?? ?? FF D2 }
        $syscall64 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        $sysenter = { 0F 34 }
        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtWriteVirtualMemory" ascii
        $nt3 = "NtCreateThreadEx" ascii
        $nt4 = "NtProtectVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and (1 of ($syscall*) or $sysenter) and 2 of ($nt*)
}

rule Evasion_Unhooking
{
    meta:
        description = "Detects library unhooking to bypass security products"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1562.001"
    strings:
        $ntdll = "ntdll.dll" ascii nocase
        $read = "ReadFile" ascii
        $get = "GetModuleHandle" ascii
        $map = "MapViewOfFile" ascii
        $vp = "VirtualProtect" ascii
        $text = ".text" ascii
    condition:
        uint16(0) == 0x5A4D and $ntdll and $vp and ($read or $map) and ($get or $text)
}

rule Evasion_Sleep_Obfuscation
{
    meta:
        description = "Detects sleep-based sandbox evasion or Ekko-style sleep encryption"
        severity = "high"
        author = "HashGuard"
        category = "evasion"
    strings:
        $sleep1 = "Sleep" ascii
        $sleep2 = "NtDelayExecution" ascii
        $wait = "WaitForSingleObject" ascii
        $timer = "CreateTimerQueueTimer" ascii
        $apc = "NtQueueApcThread" ascii
        $vp = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and ($timer or $apc) and $vp and ($sleep1 or $sleep2 or $wait)
}

rule Evasion_String_Encryption
{
    meta:
        description = "Detects heavily string-encrypted binaries (XOR/RC4 decryption loops)"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
    strings:
        $xor1 = { 30 ?? 4? [0-2] 3B ?? 7? }
        $xor2 = { 32 ?? 4? [0-2] 3B ?? 7? }
        $rc4 = { 80 ?? ?? 00 01 00 00 [0-8] 0F B6 }
    condition:
        uint16(0) == 0x5A4D and (#xor1 > 5 or #xor2 > 5 or #rc4 > 3)
}

rule Evasion_Process_Injection_APC
{
    meta:
        description = "Detects APC injection technique"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1055.004"
    strings:
        $a1 = "QueueUserAPC" ascii
        $a2 = "NtQueueApcThread" ascii
        $b1 = "VirtualAllocEx" ascii
        $b2 = "WriteProcessMemory" ascii
        $c1 = "OpenThread" ascii
        $c2 = "SuspendThread" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}

rule Evasion_Reflective_DLL_Loading
{
    meta:
        description = "Detects reflective DLL injection"
        severity = "critical"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1620"
    strings:
        $r1 = "ReflectiveLoader" ascii
        $r2 = { 4D 5A [0-256] 50 45 00 00 }
        $a1 = "VirtualAlloc" ascii
        $a2 = "GetProcAddress" ascii
        $a3 = "LoadLibrary" ascii
        $a4 = "NtFlushInstructionCache" ascii
    condition:
        uint16(0) == 0x5A4D and ($r1 or ($r2 and 4 of ($a*)))
}

rule Evasion_Timestomping
{
    meta:
        description = "Detects file timestamp manipulation"
        severity = "medium"
        author = "HashGuard"
        category = "evasion"
        mitre = "T1070.006"
    strings:
        $s1 = "SetFileTime" ascii
        $s2 = "NtSetInformationFile" ascii
        $s3 = "FileBasicInformation" ascii
        $s4 = "GetFileTime" ascii
    condition:
        uint16(0) == 0x5A4D and $s1 and $s2 and ($s3 or $s4)
}
