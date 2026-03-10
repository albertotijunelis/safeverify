/*
    HashGuard - Malicious Script Detection YARA Rules
*/

rule Script_VBA_Macro_Dropper
{
    meta:
        description = "Detects VBA macro with dropper capabilities"
        severity = "high"
        author = "HashGuard"
        category = "scripts"
    strings:
        $v1 = "AutoOpen" ascii nocase
        $v2 = "Document_Open" ascii nocase
        $v3 = "Workbook_Open" ascii nocase
        $d1 = "Shell" ascii
        $d2 = "WScript" ascii
        $d3 = "CreateObject" ascii
        $d4 = "URLDownloadToFile" ascii
        $d5 = "Environ" ascii
    condition:
        1 of ($v*) and 2 of ($d*)
}

rule Script_Batch_Payload
{
    meta:
        description = "Detects suspicious batch file payloads"
        severity = "medium"
        author = "HashGuard"
        category = "scripts"
    strings:
        $b1 = "@echo off" ascii nocase
        $d1 = "certutil" ascii nocase
        $d2 = "bitsadmin" ascii nocase
        $d3 = "curl" ascii nocase
        $p1 = "del /f" ascii nocase
        $p2 = "attrib +h" ascii nocase
        $p3 = "reg add" ascii nocase
        $p4 = "schtasks /create" ascii nocase
    condition:
        $b1 and 1 of ($d*) and 1 of ($p*) and filesize < 50KB
}

rule Script_JavaScript_Dropper
{
    meta:
        description = "Detects JavaScript-based droppers"
        severity = "high"
        author = "HashGuard"
        category = "scripts"
    strings:
        $w1 = "WScript.Shell" ascii nocase
        $w2 = "ActiveXObject" ascii nocase
        $w3 = "Scripting.FileSystemObject" ascii nocase
        $a1 = "eval(" ascii
        $a2 = "new Function(" ascii
        $a3 = "fromCharCode" ascii
        $d1 = "savetofile" ascii nocase
        $d2 = ".Run" ascii
        $d3 = ".Exec" ascii
    condition:
        1 of ($w*) and (1 of ($a*) or 1 of ($d*)) and filesize < 500KB
}

rule Script_HTA_Payload
{
    meta:
        description = "Detects malicious HTA (HTML Application) files"
        severity = "high"
        author = "HashGuard"
        category = "scripts"
    strings:
        $h1 = "<HTA:APPLICATION" ascii nocase
        $h2 = "<script" ascii nocase
        $s1 = "Shell.Application" ascii nocase
        $s2 = "WScript.Shell" ascii nocase
        $c1 = "powershell" ascii nocase
        $c2 = "cmd /c" ascii nocase
    condition:
        $h1 and $h2 and (1 of ($s*) or 1 of ($c*))
}

/* ── Shell Script Malware ────────────────────────────────────────────── */

rule Script_Shell_Dropper
{
    meta:
        description = "Detects shell scripts that download and execute payloads"
        severity = "high"
        author = "HashGuard"
        category = "scripts"
    strings:
        $sh1 = "#!/bin/sh" ascii
        $sh2 = "#!/bin/bash" ascii
        $dl1 = "wget " ascii
        $dl2 = "curl " ascii
        $dl3 = "tftp " ascii
        $exec1 = "chmod 777" ascii
        $exec2 = "chmod +x" ascii
        $exec3 = "chmod 755" ascii
        $path1 = "/tmp/" ascii
        $path2 = "/var/tmp/" ascii
        $path3 = "/dev/shm/" ascii
    condition:
        (1 of ($sh*) or uint32(0) == 0x2F62696E) and
        1 of ($dl*) and 1 of ($exec*) and 1 of ($path*) and
        filesize < 100KB
}

rule Script_Shell_Mirai_Loader
{
    meta:
        description = "Detects Mirai-style architecture dropper scripts"
        severity = "critical"
        author = "HashGuard"
        category = "scripts"
    strings:
        $sh1 = "#!/bin/sh" ascii
        $sh2 = "#!/bin/bash" ascii
        $dl1 = "wget " ascii
        $dl2 = "curl " ascii
        $arch1 = "mips" ascii nocase
        $arch2 = "arm" ascii nocase
        $arch3 = "x86" ascii nocase
        $arch4 = "i686" ascii nocase
        $arch5 = "powerpc" ascii nocase
        $arch6 = "sparc" ascii nocase
        $arch7 = "m68k" ascii nocase
        $arch8 = "mipsel" ascii nocase
        $arch9 = "aarch64" ascii nocase
        $exec1 = "chmod " ascii
        $path1 = "/tmp/" ascii
    condition:
        1 of ($sh*) and 1 of ($dl*) and 3 of ($arch*) and $exec1 and $path1 and filesize < 50KB
}

rule Script_Reverse_Shell
{
    meta:
        description = "Detects reverse shell one-liners in scripts"
        severity = "critical"
        author = "HashGuard"
        category = "scripts"
    strings:
        $r1 = "/dev/tcp/" ascii
        $r2 = "nc -e" ascii
        $r3 = "ncat -e" ascii
        $r4 = "bash -i >& /dev/tcp/" ascii
        $r5 = "mkfifo /tmp/" ascii
        $r6 = "python -c 'import socket" ascii
        $r7 = "python3 -c 'import socket" ascii
        $r8 = "socat exec:" ascii nocase
    condition:
        1 of ($r*) and filesize < 100KB
}

rule Script_Cleanup_Traces
{
    meta:
        description = "Detects scripts that clean up forensic traces"
        severity = "high"
        author = "HashGuard"
        category = "scripts"
    strings:
        $c1 = "history -c" ascii
        $c2 = "rm -rf /var/log" ascii
        $c3 = "unset HISTFILE" ascii
        $c4 = "echo > /var/log" ascii
        $c5 = "rm -f ~/.bash_history" ascii
        $c6 = "/dev/null" ascii
        $k1 = "iptables -F" ascii
        $k2 = "kill -9" ascii
    condition:
        2 of ($c*) or (1 of ($c*) and 1 of ($k*))
}
