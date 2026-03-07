/*
    HashGuard - Packer / Protector Detection YARA Rules
*/

rule Packer_UPX
{
    meta:
        description = "Detects UPX packed executables"
        severity = "low"
        author = "HashGuard"
        category = "packers"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $sig = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($upx*) or $sig)
}

rule Packer_MPRESS
{
    meta:
        description = "Detects MPRESS packed executables"
        severity = "low"
        author = "HashGuard"
        category = "packers"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_ASPack
{
    meta:
        description = "Detects ASPack packed executables"
        severity = "medium"
        author = "HashGuard"
        category = "packers"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_Themida_VMProtect
{
    meta:
        description = "Detects Themida or VMProtect protected executables"
        severity = "medium"
        author = "HashGuard"
        category = "packers"
    strings:
        $t1 = ".themida" ascii
        $v1 = ".vmp0" ascii
        $v2 = ".vmp1" ascii
        $v3 = ".vmp2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_Enigma
{
    meta:
        description = "Detects Enigma Protector"
        severity = "medium"
        author = "HashGuard"
        category = "packers"
    strings:
        $e1 = ".enigma1" ascii
        $e2 = ".enigma2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_PECompact
{
    meta:
        description = "Detects PECompact packed executables"
        severity = "low"
        author = "HashGuard"
        category = "packers"
    strings:
        $s1 = "PEC2" ascii
        $s2 = "PECompact2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
