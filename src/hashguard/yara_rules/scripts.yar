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
