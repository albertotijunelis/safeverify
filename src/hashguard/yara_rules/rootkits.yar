/*
    HashGuard - Rootkit and Bootkit YARA Rules
    Detects kernel-level rootkits, bootkits, and driver-level threats.
*/

rule Rootkit_Driver_Loading
{
    meta:
        description = "Detects kernel driver loading for rootkit installation"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
        mitre = "T1014"
    strings:
        $s1 = "NtLoadDriver" ascii
        $s2 = "ZwLoadDriver" ascii
        $s3 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ascii nocase
        $s4 = "\\Driver\\" ascii
        $s5 = "DriverObject" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Rootkit_SSDT_Hook
{
    meta:
        description = "Detects SSDT (System Service Descriptor Table) hooking"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $s1 = "KeServiceDescriptorTable" ascii
        $s2 = "ZwQuerySystemInformation" ascii
        $s3 = "NtCreateFile" ascii
        $s4 = "MmGetSystemRoutineAddress" ascii
        $s5 = "SSDT" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Rootkit_IDT_Hook
{
    meta:
        description = "Detects IDT hooking / interrupt manipulation"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $idt1 = { 0F 01 0D }
        $idt2 = "IDTR" ascii
        $idt3 = "HalDispatchTable" ascii
        $hook = "MmMapIoSpace" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Rootkit_Process_Hiding
{
    meta:
        description = "Detects DKOM-based process hiding"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $s1 = "PsGetCurrentProcess" ascii
        $s2 = "ActiveProcessLinks" ascii
        $s3 = "EPROCESS" ascii
        $s4 = "PsLookupProcessByProcessId" ascii
        $s5 = "RemoveEntryList" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Rootkit_File_Hiding
{
    meta:
        description = "Detects filesystem filter-based file hiding"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $fs1 = "IoCreateDevice" ascii
        $fs2 = "IoAttachDevice" ascii
        $fs3 = "FltRegisterFilter" ascii
        $fs4 = "FltStartFiltering" ascii
        $fs5 = "IRP_MJ_DIRECTORY_CONTROL" ascii
        $fs6 = "IRP_MJ_CREATE" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Rootkit_Network_Hiding
{
    meta:
        description = "Detects network activity hiding via NDIS/TDI hooks"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $n1 = "NdisRegisterProtocol" ascii
        $n2 = "TdiMapUserRequest" ascii
        $n3 = "\\Device\\Tcp" ascii
        $n4 = "\\Device\\Udp" ascii
        $n5 = "NdisMRegisterMiniport" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Bootkit_MBR_Infector
{
    meta:
        description = "Detects MBR bootkit infection patterns"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $mbr1 = "\\\\.\\PhysicalDrive0" ascii
        $mbr2 = "CreateFileA" ascii
        $mbr3 = "WriteFile" ascii
        $mbr4 = "DeviceIoControl" ascii
        $sec = { 55 AA }
        $boot = "NTLDR" ascii
        $boot2 = "bootmgr" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $mbr1 and ($mbr2 or $mbr3 or $mbr4) and ($sec or $boot or $boot2)
}

rule Bootkit_UEFI
{
    meta:
        description = "Detects UEFI bootkit indicators"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $uefi1 = "\\EFI\\Boot\\" ascii nocase
        $uefi2 = "\\EFI\\Microsoft\\Boot\\" ascii nocase
        $uefi3 = "bootx64.efi" ascii nocase
        $uefi4 = "bootmgfw.efi" ascii nocase
        $var = "EFI_GLOBAL_VARIABLE" ascii
        $rt = "GetVariable" ascii
        $esp = "EFI System Partition" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Rootkit_Callback_Registration
{
    meta:
        description = "Detects kernel callback registration (common in rootkits)"
        severity = "high"
        author = "HashGuard"
        category = "rootkits"
    strings:
        $cb1 = "PsSetCreateProcessNotifyRoutine" ascii
        $cb2 = "PsSetCreateThreadNotifyRoutine" ascii
        $cb3 = "PsSetLoadImageNotifyRoutine" ascii
        $cb4 = "CmRegisterCallback" ascii
        $cb5 = "ObRegisterCallbacks" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Driver_Vulnerable_Exploitation
{
    meta:
        description = "Detects BYOVD (Bring Your Own Vulnerable Driver) patterns"
        severity = "critical"
        author = "HashGuard"
        category = "rootkits"
        mitre = "T1068"
    strings:
        $s1 = "\\SystemRoot\\System32\\drivers\\" ascii nocase
        $s2 = "NtLoadDriver" ascii
        $s3 = ".sys" ascii nocase
        $v1 = "RTCore64" ascii
        $v2 = "DBUtil_2_3" ascii
        $v3 = "gdrv" ascii
        $v4 = "AsIO" ascii
        $v5 = "Capcom.sys" ascii
        $v6 = "procexp" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or $s2) and ($s3 and 1 of ($v*))
}
