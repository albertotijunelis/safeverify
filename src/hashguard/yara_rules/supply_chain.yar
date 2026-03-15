/*
    HashGuard - Supply Chain & Emerging Threat YARA Rules
    Detects supply-chain attack vectors, dependency confusion, trojanized
    packages, AI-assisted malware patterns, and modern loader frameworks.
*/

rule SupplyChain_PyPI_Malicious_Setup
{
    meta:
        description = "Detects malicious setup.py patterns in Python packages"
        severity = "critical"
        author = "HashGuard"
        category = "supply_chain"
        mitre = "T1195.002"
    strings:
        $s1 = "setup(" ascii
        $s2 = "cmdclass" ascii
        $s3 = "install" ascii
        $exec1 = "subprocess.Popen" ascii
        $exec2 = "os.system" ascii
        $exec3 = "exec(base64" ascii nocase
        $exec4 = "__import__('os').popen" ascii
        $net1 = "requests.get(" ascii
        $net2 = "urllib.request.urlopen" ascii
        $net3 = "socket.connect" ascii
    condition:
        $s1 and $s2 and $s3 and (1 of ($exec*) or 1 of ($net*))
}

rule SupplyChain_NPM_PostInstall_Exec
{
    meta:
        description = "Detects suspicious npm postinstall script execution"
        severity = "high"
        author = "HashGuard"
        category = "supply_chain"
        mitre = "T1195.002"
    strings:
        $pkg = "\"scripts\"" ascii
        $post1 = "\"postinstall\"" ascii
        $post2 = "\"preinstall\"" ascii
        $exec1 = "child_process" ascii
        $exec2 = "exec(" ascii
        $exec3 = "execSync(" ascii
        $net1 = "http.get(" ascii
        $net2 = "https.get(" ascii
        $net3 = "fetch(" ascii
        $sus1 = "Buffer.from(" ascii
        $sus2 = "eval(" ascii
    condition:
        $pkg and (1 of ($post*)) and (1 of ($exec*) or 1 of ($net*) or 1 of ($sus*))
}

rule SupplyChain_Dependency_Confusion
{
    meta:
        description = "Detects indicators of dependency confusion / typosquatting attacks"
        severity = "high"
        author = "HashGuard"
        category = "supply_chain"
        mitre = "T1195.002"
    strings:
        $pip1 = "pip install" ascii nocase
        $pip2 = "pip3 install" ascii nocase
        $npm1 = "npm install" ascii nocase
        $dns1 = ".burpcollaborator.net" ascii nocase
        $dns2 = ".interact.sh" ascii nocase
        $dns3 = ".oast.fun" ascii nocase
        $dns4 = ".canarytokens.com" ascii nocase
        $exfil1 = "dns.resolve" ascii
        $exfil2 = "subprocess.check_output" ascii
        $exfil3 = "os.uname" ascii
        $exfil4 = "platform.node" ascii
    condition:
        (1 of ($pip*) or 1 of ($npm*)) and (1 of ($dns*) or 2 of ($exfil*))
}

rule SupplyChain_Trojanized_Installer
{
    meta:
        description = "Detects trojanized software installers with embedded payloads"
        severity = "critical"
        author = "HashGuard"
        category = "supply_chain"
        mitre = "T1195.002"
    strings:
        $sig1 = "Inno Setup" ascii
        $sig2 = "Nullsoft" ascii
        $sig3 = "InstallShield" ascii
        $drop1 = "\\Temp\\" ascii nocase
        $drop2 = "\\AppData\\Local\\Temp" ascii nocase
        $exec1 = "ShellExecuteW" ascii
        $exec2 = "CreateProcessW" ascii
        $net1 = "InternetOpenUrlW" ascii
        $net2 = "URLDownloadToFileW" ascii
        $hid1 = "SW_HIDE" ascii
        $hid2 = "CreateProcessA" ascii
        $persist = "\\Run\\" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($sig*) and 1 of ($drop*) and
        (1 of ($net*) or ($persist and 1 of ($exec*)) or 1 of ($hid*))
}

rule Loader_BatLoader
{
    meta:
        description = "Detects BatLoader initial access framework indicators"
        severity = "critical"
        author = "HashGuard"
        category = "loaders"
        mitre = "T1059.003"
    strings:
        $bat1 = "powershell" ascii nocase
        $bat2 = "Start-BitsTransfer" ascii nocase
        $bat3 = "mshta" ascii nocase
        $bat4 = "certutil" ascii nocase
        $bat5 = "bitsadmin" ascii nocase
        $dl1 = "/transfer" ascii nocase
        $dl2 = "-urlcache" ascii nocase
        $dl3 = "-decodehex" ascii nocase
        $exe1 = "regsvr32" ascii nocase
        $exe2 = "rundll32" ascii nocase
        $exe3 = "msiexec" ascii nocase
    condition:
        2 of ($bat*) and (1 of ($dl*) or 1 of ($exe*))
}

rule Loader_GuLoader_Shellcode
{
    meta:
        description = "Detects GuLoader/CloudEyE shellcode-based loader patterns"
        severity = "critical"
        author = "HashGuard"
        category = "loaders"
        mitre = "T1027.002"
    strings:
        $vb1 = "VirtualAlloc" ascii
        $vb2 = "NtProtectVirtualMemory" ascii
        $vb3 = "EnumWindows" ascii
        $anti1 = "cpuid" ascii
        $anti2 = "rdtsc" ascii
        $shell1 = { E8 00 00 00 00 5? }
        $shell2 = { 64 A1 30 00 00 00 }
        $cloud1 = "drive.google.com" ascii nocase
        $cloud2 = "onedrive.live.com" ascii nocase
        $cloud3 = "discord" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($vb*) and (1 of ($anti*) or 1 of ($shell*)) and 1 of ($cloud*)
}

rule Loader_IcedID_GZip
{
    meta:
        description = "Detects IcedID/BokBot GZip loader and license.dat pattern"
        severity = "critical"
        author = "HashGuard"
        category = "loaders"
        mitre = "T1140"
    strings:
        $lic = "license.dat" ascii nocase
        $gzip = { 1F 8B 08 }
        $dll = "DllRegisterServer" ascii
        $run1 = "rundll32.exe" ascii nocase
        $run2 = "regsvr32.exe" ascii nocase
        $ua = "Mozilla/" ascii
        $cert = "C=XX" ascii
    condition:
        uint16(0) == 0x5A4D and $gzip and ($lic or $dll) and (1 of ($run*) or $ua)
}

rule Loader_BATCLOAK_Obfuscation
{
    meta:
        description = "Detects BatCloak-style heavily obfuscated batch loaders"
        severity = "high"
        author = "HashGuard"
        category = "loaders"
        mitre = "T1027"
    strings:
        $set1 = /set\s+"\w{1,3}=[^"]{1,5}"/ nocase
        $set2 = /set\s+"\w{1,3}=[^"]{1,5}"/ nocase
        $concat = /%\w{1,3}%%\w{1,3}%%\w{1,3}%/ nocase
        $call = "call" ascii nocase
        $pow = "pow" ascii nocase
        $ersh = "ersh" ascii nocase
        $ell = "ell" ascii nocase
    condition:
        (#set1 + #set2) > 20 and #concat > 5 and $call and ($pow and $ersh and $ell)
}

rule AI_Generated_Malware_Patterns
{
    meta:
        description = "Detects patterns common in AI/LLM-generated malware code"
        severity = "medium"
        author = "HashGuard"
        category = "emerging"
    strings:
        $comm1 = "# This script" ascii
        $comm2 = "# Step 1:" ascii
        $comm3 = "# Step 2:" ascii
        $comm4 = "# Note:" ascii
        $import1 = "import socket" ascii
        $import2 = "import subprocess" ascii
        $import3 = "import os" ascii
        $func1 = "def main():" ascii
        $func2 = "def exfiltrate" ascii nocase
        $func3 = "def encrypt_file" ascii nocase
        $func4 = "def keylogger" ascii nocase
        $func5 = "def reverse_shell" ascii nocase
        $func6 = "def spread" ascii nocase
    condition:
        3 of ($comm*) and 2 of ($import*) and 2 of ($func*)
}

rule Stealer_Modern_InfectionChain
{
    meta:
        description = "Detects modern infostealer delivery chain (Discord/Telegram exfil)"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1567.001"
    strings:
        $hook1 = "discord.com/api/webhooks" ascii nocase
        $hook2 = "discordapp.com/api/webhooks" ascii nocase
        $tg1 = "api.telegram.org/bot" ascii nocase
        $tg2 = "/sendDocument" ascii nocase
        $tg3 = "/sendMessage" ascii nocase
        $browser1 = "\\Login Data" ascii nocase
        $browser2 = "\\Cookies" ascii nocase
        $browser3 = "\\Web Data" ascii nocase
        $zip1 = "zipfile" ascii
        $zip2 = "ZipFile" ascii
        $zip3 = "shutil.make_archive" ascii
    condition:
        (1 of ($hook*) or ($tg1 and 1 of ($tg2, $tg3))) and 2 of ($browser*) and 1 of ($zip*)
}

rule Ransomware_Intermittent_Encryption
{
    meta:
        description = "Detects intermittent/partial file encryption used by modern ransomware"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $seek1 = "SetFilePointerEx" ascii
        $seek2 = "fseek" ascii
        $seek3 = "lseek" ascii
        $read1 = "ReadFile" ascii
        $write1 = "WriteFile" ascii
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "BCryptEncrypt" ascii
        $crypt3 = "chacha20" ascii nocase
        $crypt4 = "salsa20" ascii nocase
        $skip1 = "skip" ascii nocase
        $skip2 = "chunk" ascii nocase
        $skip3 = "block_size" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($seek*) and ($read1 or $write1) and
        1 of ($crypt*) and 1 of ($skip*)
}

rule Ransomware_ESXi_Targeting
{
    meta:
        description = "Detects ransomware targeting VMware ESXi environments"
        severity = "critical"
        author = "HashGuard"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $esxi1 = "esxcli" ascii nocase
        $esxi2 = "/vmfs/volumes" ascii
        $esxi3 = ".vmdk" ascii nocase
        $esxi4 = ".vmx" ascii nocase
        $esxi5 = "vim-cmd" ascii
        $kill1 = "vm process kill" ascii nocase
        $kill2 = "esxcli vm process" ascii nocase
        $enc1 = "openssl" ascii
        $enc2 = "sosemanuk" ascii nocase
        $enc3 = "encrypt" ascii nocase
    condition:
        3 of ($esxi*) and (1 of ($kill*) or 1 of ($enc*))
}
