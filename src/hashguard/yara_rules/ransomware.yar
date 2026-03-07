/*
    HashGuard - Ransomware-Specific YARA Rules
*/

rule Ransomware_Note_Patterns
{
    meta:
        description = "Detects common ransomware note text patterns"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $n1 = "your files have been encrypted" ascii nocase
        $n2 = "your important files" ascii nocase
        $n3 = "decrypt your files" ascii nocase
        $n4 = "restore your files" ascii nocase
        $n5 = "all your files" ascii nocase
        $p1 = "bitcoin" ascii nocase
        $p2 = "monero" ascii nocase
        $p3 = "cryptocurrency" ascii nocase
        $p4 = "wallet" ascii nocase
        $t1 = ".onion" ascii
        $t2 = "tor browser" ascii nocase
    condition:
        2 of ($n*) and (1 of ($p*) or 1 of ($t*))
}

rule Ransomware_File_Extension_Changes
{
    meta:
        description = "Detects code that bulk-renames files with ransomware extensions"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $r1 = ".locked" ascii nocase
        $r2 = ".encrypted" ascii nocase
        $r3 = ".crypto" ascii nocase
        $r4 = ".crypt" ascii nocase
        $r5 = ".pay2key" ascii nocase
        $r6 = ".WNCRY" ascii
        $r7 = ".locky" ascii nocase
        $a1 = "MoveFileEx" ascii
        $a2 = "MoveFileW" ascii
        $a3 = "rename" ascii
        $a4 = "CryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($r*) and 1 of ($a*)
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Detects Volume Shadow Copy deletion (common ransomware action)"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $v1 = "vssadmin" ascii nocase
        $v2 = "delete shadows" ascii nocase
        $v3 = "wmic shadowcopy delete" ascii nocase
        $v4 = "bcdedit" ascii nocase
        $v5 = "recoveryenabled no" ascii nocase
        $w1 = "wbadmin delete" ascii nocase
    condition:
        2 of them
}
