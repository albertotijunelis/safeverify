/*
    HashGuard - Suspicious Document / Macro / Embedded Object YARA Rules
    Detects malicious documents, embedded payloads, and dropper documents.
*/

rule Document_OLE_Embedded_Executable
{
    meta:
        description = "Detects OLE document with embedded PE executable"
        severity = "critical"
        author = "HashGuard"
        category = "documents"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $mz = { 4D 5A 90 00 }
        $pe = "This program cannot be run in DOS mode" ascii
    condition:
        $ole at 0 and ($mz or $pe)
}

rule Document_OLE_Macro_AutoExec
{
    meta:
        description = "Detects OLE document with auto-executing macro"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "AutoExec" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $auto4 = "Workbook_Open" ascii nocase
        $auto5 = "Auto_Open" ascii nocase
        $auto6 = "DocumentBeforeClose" ascii nocase
    condition:
        $ole at 0 and any of ($auto*)
}

rule Document_Macro_Dropper
{
    meta:
        description = "Detects VBA macro with file dropping capabilities"
        severity = "critical"
        author = "HashGuard"
        category = "documents"
    strings:
        $vba1 = "Attribute VB_" ascii
        $drop1 = "Shell" ascii
        $drop2 = "WScript.Shell" ascii
        $drop3 = "CreateObject" ascii
        $drop4 = "Environ" ascii
        $drop5 = "URLDownloadToFile" ascii
        $drop6 = "powershell" ascii nocase
        $drop7 = "cmd /c" ascii nocase
        $drop8 = "Open.*For.*Binary" ascii nocase
        $drop9 = "ADODB.Stream" ascii
    condition:
        $vba1 and 3 of ($drop*)
}

rule Document_Macro_Obfuscated
{
    meta:
        description = "Detects heavily obfuscated VBA macro code"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $vba = "Attribute VB_" ascii
        $chr1 = "Chr(" ascii
        $chr2 = "ChrW(" ascii
        $str = "StrReverse" ascii
        $rep = "Replace(" ascii
        $mid = "Mid(" ascii
        $concat = "& Chr(" ascii
    condition:
        $vba and (#chr1 > 15 or #chr2 > 15 or (#concat > 10 and ($str or $rep or $mid)))
}

rule Document_DDE_Attack
{
    meta:
        description = "Detects DDE (Dynamic Data Exchange) command execution"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $dde1 = "DDE" ascii
        $dde2 = "DDEAUTO" ascii
        $cmd1 = "cmd" ascii nocase
        $cmd2 = "powershell" ascii nocase
        $cmd3 = "mshta" ascii nocase
        $formula = "=cmd" ascii nocase
        $formula2 = "=MSEXCEL" ascii nocase
    condition:
        ($dde1 and $dde2 and 1 of ($cmd*)) or 1 of ($formula*)
}

rule Document_Template_Injection
{
    meta:
        description = "Detects remote template injection"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $xml = "<?xml" ascii nocase
        $rel = "relationships" ascii nocase
        $tmpl1 = "attachedTemplate" ascii nocase
        $tmpl2 = "oleObject" ascii nocase
        $tmpl3 = "frame" ascii nocase
        $http = "http" ascii
        $dotm = ".dotm" ascii nocase
    condition:
        $xml and $rel and 1 of ($tmpl*) and $http and $dotm
}

rule Document_PDF_JavaScript
{
    meta:
        description = "Detects PDF with embedded JavaScript"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $pdf = "%PDF" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS " ascii
        $js3 = "/OpenAction" ascii
        $js4 = "/AA " ascii
        $launch = "/Launch" ascii
    condition:
        $pdf at 0 and (2 of ($js*) or $launch)
}

rule Document_PDF_Exploit
{
    meta:
        description = "Detects exploit attempts in PDF files"
        severity = "critical"
        author = "HashGuard"
        category = "documents"
    strings:
        $pdf = "%PDF" ascii
        $heap = { 25 75 30 30 }
        $nop = { 90 90 90 90 90 90 90 90 }
        $shell = { E8 [4] 5? }
        $uri = "/URI" ascii
        $embed = "/EmbeddedFile" ascii
    condition:
        $pdf at 0 and (($heap and $nop) or ($shell and $uri) or ($heap and $embed))
}

rule Document_RTF_Exploit
{
    meta:
        description = "Detects RTF document with exploit elements"
        severity = "critical"
        author = "HashGuard"
        category = "documents"
    strings:
        $rtf = "{\\rtf" ascii
        $obj1 = "\\object" ascii
        $obj2 = "\\objocx" ascii
        $obj3 = "\\objemb" ascii
        $ole1 = "d0cf11e0" ascii nocase
        $ole2 = "0105000002" ascii nocase
        $eq = "0002CE020000000000C000000000000046" ascii nocase
    condition:
        $rtf at 0 and 1 of ($obj*) and (1 of ($ole*) or $eq)
}

rule Document_OneNote_Embedded_File
{
    meta:
        description = "Detects OneNote file with embedded executable/script"
        severity = "critical"
        author = "HashGuard"
        category = "documents"
    strings:
        $one_magic = { E4 52 5C 7B 8C D8 A7 4D }
        $mz = { 4D 5A }
        $ps = "powershell" ascii nocase
        $bat = "@echo off" ascii nocase
        $vbs = "WScript" ascii
        $hta = "<HTA:" ascii nocase
    condition:
        $one_magic at 0 and ($mz or $ps or $bat or $vbs or $hta)
}

rule Document_ISO_IMG_Dropper
{
    meta:
        description = "Detects ISO/IMG files used as malware delivery vehicles"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $iso = "CD001" ascii
        $mz = { 4D 5A 90 00 }
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $bat = "@echo off" ascii nocase
        $vbs = "WScript.Shell" ascii
    condition:
        $iso and ($mz or $lnk or $bat or $vbs)
}

rule Document_LNK_Malicious
{
    meta:
        description = "Detects malicious LNK shortcut files"
        severity = "high"
        author = "HashGuard"
        category = "documents"
    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }
        $ps1 = "powershell" ascii nocase
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "mshta" ascii nocase
        $cmd3 = "wscript" ascii nocase
        $cmd4 = "cscript" ascii nocase
        $dl = "http" ascii
    condition:
        $lnk_header at 0 and 1 of ($ps1, $cmd1, $cmd2, $cmd3, $cmd4) and $dl
}
