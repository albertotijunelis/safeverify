/*
    HashGuard - Wiper and Destructive Malware YARA Rules
    Detects wiper malware, data destruction, and sabotage tools.
*/

rule Wiper_MBR_Overwrite
{
    meta:
        description = "Detects MBR wiper patterns"
        severity = "critical"
        author = "HashGuard"
        category = "wipers"
    strings:
        $d1 = "\\\\.\\PhysicalDrive" ascii
        $d2 = "CreateFile" ascii
        $d3 = "WriteFile" ascii
        $d4 = "DeviceIoControl" ascii
        $zero = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and $d1 and ($d2 or $d3 or $d4) and $zero
}

rule Wiper_Disk_Destruction
{
    meta:
        description = "Detects disk destruction patterns"
        severity = "critical"
        author = "HashGuard"
        category = "wipers"
    strings:
        $d1 = "\\\\.\\PhysicalDrive0" ascii
        $d2 = "\\\\.\\PhysicalDrive1" ascii
        $d3 = "\\\\.\\C:" ascii
        $w1 = "WriteFile" ascii
        $w2 = "NtFsControlFile" ascii
        $format = "format" ascii nocase
        $vol = "\\Volume" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($d*) and ($w1 or $w2 or $format) and $vol
}

rule Wiper_File_Shredding
{
    meta:
        description = "Detects file shredding/secure delete patterns"
        severity = "high"
        author = "HashGuard"
        category = "wipers"
    strings:
        $find1 = "FindFirstFile" ascii
        $find2 = "FindNextFile" ascii
        $del1 = "DeleteFileA" ascii
        $del2 = "DeleteFileW" ascii
        $write = "WriteFile" ascii
        $rand = "CryptGenRandom" ascii
        $ext1 = ".doc" ascii nocase
        $ext2 = ".xls" ascii nocase
        $ext3 = ".pdf" ascii nocase
        $ext4 = ".jpg" ascii nocase
        $ext5 = ".sql" ascii nocase
        $ext6 = ".mdb" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($find1 or $find2) and ($del1 or $del2) and $write and ($rand or 3 of ($ext*))
}

rule Wiper_HermeticWiper_Pattern
{
    meta:
        description = "Detects HermeticWiper-like destructive patterns"
        severity = "critical"
        author = "HashGuard"
        category = "wipers"
    strings:
        $se = "SeBackupPrivilege" ascii
        $se2 = "SeLoadDriverPrivilege" ascii
        $drv = "\\drivers\\" ascii nocase
        $phys = "\\\\.\\PhysicalDrive" ascii
        $ntfs = "$MFT" ascii
        $ntfs2 = "$Bitmap" ascii
    condition:
        uint16(0) == 0x5A4D and ($se or $se2) and ($drv or $phys) and ($ntfs or $ntfs2)
}

rule Wiper_Shadow_Destroy
{
    meta:
        description = "Detects comprehensive backup/recovery destruction"
        severity = "critical"
        author = "HashGuard"
        category = "wipers"
    strings:
        $v1 = "vssadmin delete shadows" ascii nocase
        $v2 = "vssadmin resize shadowstorage" ascii nocase
        $v3 = "wmic shadowcopy delete" ascii nocase
        $v4 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $v5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $v6 = "wbadmin delete catalog" ascii nocase
        $v7 = "wbadmin delete systemstatebackup" ascii nocase
        $v8 = "del /s /q %SYSTEMDRIVE%\\$Recycle.bin" ascii nocase
    condition:
        3 of them
}

rule Wiper_CaddyWiper_Pattern
{
    meta:
        description = "Detects CaddyWiper-like disk wiping"
        severity = "critical"
        author = "HashGuard"
        category = "wipers"
    strings:
        $se = "SeTakeOwnershipPrivilege" ascii
        $drive = "C:\\Users" ascii
        $zero_fill = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $phys = "\\\\.\\PhysicalDrive" ascii
    condition:
        uint16(0) == 0x5A4D and $se and ($drive or $phys) and $zero_fill
}

/*
    HashGuard - Worm / Self-Propagation YARA Rules
*/

rule Worm_USB_Spread
{
    meta:
        description = "Detects USB worm propagation patterns"
        severity = "high"
        author = "HashGuard"
        category = "worms"
    strings:
        $d1 = "GetDriveType" ascii
        $d2 = "DRIVE_REMOVABLE" ascii
        $d3 = "GetLogicalDrives" ascii
        $copy = "CopyFile" ascii
        $auto = "autorun.inf" ascii nocase
        $lnk = ".lnk" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($d*) and ($auto or ($copy and $lnk))
}

rule Worm_Network_Spread
{
    meta:
        description = "Detects network worm propagation patterns"
        severity = "high"
        author = "HashGuard"
        category = "worms"
    strings:
        $scan1 = "connect" ascii
        $scan2 = "send" ascii
        $scan3 = "recv" ascii
        $port1 = { 01 BD }
        $port2 = "445" ascii
        $port3 = "139" ascii
        $smb = "SMBv" ascii
        $enum = "NetShareEnum" ascii
        $enum2 = "WNetEnumResource" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($scan*) and (1 of ($port*) or $smb or $enum or $enum2)
}

rule Worm_Email_Spread
{
    meta:
        description = "Detects email worm spreading patterns"
        severity = "high"
        author = "HashGuard"
        category = "worms"
    strings:
        $m1 = "MAIL FROM:" ascii nocase
        $m2 = "RCPT TO:" ascii nocase
        $m3 = "SMTP" ascii
        $m4 = "MAPISendMail" ascii
        $addr = "address book" ascii nocase
        $addr2 = "contacts" ascii nocase
        $att = "Content-Disposition: attachment" ascii nocase
    condition:
        2 of ($m*) and (1 of ($addr*) or $att)
}

/*
    HashGuard - RAT (Remote Access Trojan) Specific Rules
*/

rule RAT_Generic_Capabilities
{
    meta:
        description = "Detects generic RAT capabilities"
        severity = "critical"
        author = "HashGuard"
        category = "rats"
    strings:
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "ShellExecute" ascii
        $cam = "capCreateCaptureWindow" ascii
        $mic = "waveInOpen" ascii
        $proc = "CreateProcess" ascii
        $file = "FindFirstFile" ascii
        $reg = "RegSetValueEx" ascii
        $dl = "URLDownloadToFile" ascii
        $net = "WSAStartup" ascii
    condition:
        uint16(0) == 0x5A4D and 5 of them
}

rule RAT_njRAT_Indicators
{
    meta:
        description = "Detects njRAT indicators"
        severity = "critical"
        author = "HashGuard"
        category = "rats"
    strings:
        $n1 = "njRAT" ascii nocase
        $n2 = "njq8" ascii
        $n3 = "im523" ascii
        $n4 = "|'|'|" ascii
        $n5 = "netsh firewall" ascii nocase
        $n6 = "cmd.exe /c ping" ascii nocase
    condition:
        3 of them
}

rule RAT_DarkComet
{
    meta:
        description = "Detects DarkComet RAT patterns"
        severity = "critical"
        author = "HashGuard"
        category = "rats"
    strings:
        $dc1 = "DarkComet" ascii nocase
        $dc2 = "DC_MUTEX-" ascii
        $dc3 = "#BOT#ALIVE#" ascii
        $dc4 = "#KCMDDC" ascii
        $dc5 = "YOURPASSWORD" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule RAT_Quasar
{
    meta:
        description = "Detects Quasar RAT patterns"
        severity = "critical"
        author = "HashGuard"
        category = "rats"
    strings:
        $q1 = "Quasar.Common" ascii
        $q2 = "Quasar.Client" ascii
        $q3 = "GetKeyloggerLogs" ascii
        $q4 = "DoUploadAndExecute" ascii
        $q5 = "DoShellExecute" ascii
        $q6 = "DoDownloadFile" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule RAT_Remcos
{
    meta:
        description = "Detects Remcos RAT indicators"
        severity = "critical"
        author = "HashGuard"
        category = "rats"
    strings:
        $r1 = "Remcos" ascii nocase
        $r2 = "Breaking-Security.Net" ascii nocase
        $r3 = "licence" ascii
        $r4 = "keylogger" ascii nocase
        $r5 = /remcos_[a-z]/ ascii nocase
        $mutex = "remcos_mutex" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
