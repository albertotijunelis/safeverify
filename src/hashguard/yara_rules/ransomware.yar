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

rule Ransomware_LockBit_Indicators
{
    meta:
        description = "Detects LockBit ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $lb1 = "lockbit" ascii nocase
        $lb2 = ".lockbit" ascii nocase
        $lb3 = "Restore-My-Files.txt" ascii nocase
        $lb4 = "LockBit_Ransomware" ascii nocase
        $lb5 = "lockbit3" ascii nocase
        $mutex = "Global\\{" ascii
        $aes = "CryptEncrypt" ascii
    condition:
        2 of ($lb*) or (1 of ($lb*) and $mutex and $aes)
}

rule Ransomware_Conti_Indicators
{
    meta:
        description = "Detects Conti ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $c1 = "CONTI" ascii
        $c2 = "readme.txt" ascii nocase
        $c3 = ".CONTI" ascii
        $api1 = "IoCompletionPort" ascii
        $spread = "\\ADMIN$" ascii
        $enc = "ChaCha" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($c*) or (1 of ($c*) and $enc) or ($spread and $enc and $api1))
}

rule Ransomware_BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $bc1 = "RECOVER-" ascii
        $bc2 = "alphv" ascii nocase
        $bc3 = "blackcat" ascii nocase
        $bc4 = "--access-token" ascii
        $rust1 = "std::rt::lang_start" ascii
        $rust2 = "aes256gcm" ascii nocase
        $json = "config.json" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($bc*) or ($rust1 and $rust2 and ($bc4 or $json)))
}

rule Ransomware_Hive_Indicators
{
    meta:
        description = "Detects Hive ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $h1 = ".hive" ascii nocase
        $h2 = "HOW_TO_DECRYPT" ascii nocase
        $h3 = "hive ransomware" ascii nocase
        $go = "main.main" ascii
        $enc = "encryptFile" ascii
    condition:
        2 of ($h*) or (1 of ($h*) and $go and $enc)
}

rule Ransomware_REvil_Sodinokibi
{
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $r1 = "sodinokibi" ascii nocase
        $r2 = "REvil" ascii
        $r3 = "-nolan" ascii
        $r4 = "expand 32-byte k" ascii
        $cfg = "{\"pk\":" ascii
        $ext_skip = "ntldr" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($r*) or ($cfg and $r4) or ($r3 and $r4 and $ext_skip))
}

rule Ransomware_WannaCry_Indicators
{
    meta:
        description = "Detects WannaCry ransomware"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $wc1 = "WanaCrypt0r" ascii nocase
        $wc2 = ".WNCRY" ascii
        $wc3 = "@WanaDecryptor@" ascii
        $wc4 = "tasksche.exe" ascii
        $wc5 = "mssecsvc.exe" ascii
        $kill = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    condition:
        2 of them
}

rule Ransomware_Dharma_CrySiS
{
    meta:
        description = "Detects Dharma/CrySiS ransomware"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $d1 = "dharma" ascii nocase
        $d2 = ".dharma" ascii nocase
        $d3 = "crysis" ascii nocase
        $d4 = ".id-" ascii
        $d5 = ".[" ascii
        $d6 = "].bip" ascii nocase
        $email = /\[[\w.]+@[\w.]+\]/ ascii
    condition:
        3 of ($d*) or ($d4 and $d5 and $email)
}

rule Ransomware_Encryption_Library
{
    meta:
        description = "Detects ransomware-grade encryption library usage"
        severity = "high"
        author = "HashGuard"
        category = "ransomware"
    strings:
        $aes = "AES-256" ascii nocase
        $rsa = "RSA" ascii nocase
        $chacha = "ChaCha20" ascii nocase
        $salsa = "Salsa20" ascii nocase
        $curve = "Curve25519" ascii nocase
        $enc = "CryptEncrypt" ascii
        $gen = "CryptGenKey" ascii
        $import = "CryptImportKey" ascii
        $enum = "FindFirstFile" ascii
        $write = "WriteFile" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($aes, $rsa, $chacha, $salsa, $curve) and ($enc or $gen or $import) and $enum and $write
}

rule Ransomware_Akira
{
    meta:
        description = "Detects Akira ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $ak1 = "akira" ascii nocase
        $ak2 = ".akira" ascii nocase
        $ak3 = "akira_readme.txt" ascii nocase
        $note1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4cez" ascii
        $note2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76iez" ascii
        $rust = "std::rt::lang_start" ascii
        $chacha = "chacha" ascii nocase
        $enum_f = "FindFirstFileW" ascii
        $enum_d = "FindNextFileW" ascii
        $shadow = "vssadmin delete shadows" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($ak*) or
        (1 of ($note*) and ($chacha or $rust)) or
        (1 of ($ak*) and $shadow and $enum_f))
}

rule Ransomware_Royal
{
    meta:
        description = "Detects Royal ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $ry1 = ".royal" ascii nocase
        $ry2 = "README.TXT" ascii
        $ry3 = "royal" ascii nocase
        $note = "unique case#" ascii nocase
        $onion = ".onion" ascii
        $aes = "AES" ascii
        $rsa = "RSA" ascii
        $partial = "SetFilePointerEx" ascii
        $enum1 = "FindFirstFileW" ascii
        $net1 = "\\ADMIN$" ascii
        $net2 = "\\IPC$" ascii
        $del = "vssadmin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((2 of ($ry*) and ($onion or $del)) or
        ($ry1 and $partial and ($aes or $rsa)) or
        (1 of ($ry*) and 1 of ($net*) and $del))
}

rule Ransomware_Play
{
    meta:
        description = "Detects Play ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $pl1 = ".play" ascii nocase
        $pl2 = "ReadMe.txt" ascii
        $pl3 = "PLAY" ascii
        $note = "email" ascii nocase
        $aes = "CryptEncrypt" ascii
        $rsa = "CryptImportPublicKeyInfo" ascii
        $enum1 = "FindFirstFileW" ascii
        $enum2 = "GetLogicalDriveStrings" ascii
        $admin = "\\ADMIN$" ascii
        $shad = "wmic shadowcopy delete" ascii nocase
        $psexec = "PsExec" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($pl1 and $pl3 and $aes) or
        ($pl1 and $shad and $enum1) or
        (2 of ($pl*) and ($admin or $psexec)))
}

rule Ransomware_BlackBasta
{
    meta:
        description = "Detects Black Basta ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $bb1 = "basta" ascii nocase
        $bb2 = ".basta" ascii nocase
        $bb3 = "readme.txt" ascii nocase
        $bb4 = "instructions_read_me" ascii nocase
        $chacha = "chacha20" ascii nocase
        $rsa = "RSA-4096" ascii nocase
        $onion = ".onion" ascii
        $del1 = "vssadmin delete shadows" ascii nocase
        $del2 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $icon = ".ico" ascii
        $enum = "FindFirstFile" ascii
        $svc = "sc stop" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((2 of ($bb*) and ($chacha or $rsa)) or
        (1 of ($bb*) and $del1 and $del2) or
        (1 of ($bb*) and $onion and $svc and $enum))
}

rule Ransomware_Rhysida
{
    meta:
        description = "Detects Rhysida ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $rh1 = "Rhysida" ascii nocase
        $rh2 = ".rhysida" ascii nocase
        $rh3 = "CriticalBreachDetected" ascii nocase
        $note1 = "CriticalBreachDetected.pdf" ascii nocase
        $note2 = "You will have to pay" ascii nocase
        $chacha = "ChaCha20" ascii nocase
        $rsa = "RSA" ascii nocase
        $pdf = "%PDF" ascii
        $enum = "FindFirstFileW" ascii
        $shad = "vssadmin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((2 of ($rh*)) or
        (1 of ($note*) and ($chacha or $rsa)) or
        (1 of ($rh*) and $shad and $enum))
}

rule Ransomware_Medusa_Locker
{
    meta:
        description = "Detects MedusaLocker ransomware indicators"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $ml1 = "MedusaLocker" ascii nocase
        $ml2 = "medusa" ascii nocase
        $note1 = "How_to_back_files" ascii nocase
        $note2 = "!!readme!!" ascii nocase
        $aes = "AES-256" ascii nocase
        $rsa = "RSA-2048" ascii nocase
        $svc1 = "sc stop" ascii nocase
        $svc2 = "net stop" ascii nocase
        $del = "vssadmin delete shadows" ascii nocase
        $persist = "\\CurrentVersion\\Run" ascii nocase
        $enum = "FindFirstFile" ascii
    condition:
        uint16(0) == 0x5A4D and ((1 of ($ml*) and 1 of ($note*)) or
        (1 of ($ml*) and ($aes or $rsa) and $del) or
        (1 of ($note*) and $persist and $enum and ($aes or $rsa)))
}
