/*
    HashGuard - Miners and Adware YARA Rules
    Detects cryptocurrency miners, adware, PUPs, and coinminers.
*/

rule Miner_XMRig
{
    meta:
        description = "Detects XMRig cryptocurrency miner"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $xmr1 = "xmrig" ascii nocase
        $xmr2 = "stratum+tcp://" ascii
        $xmr3 = "stratum+ssl://" ascii
        $xmr4 = "pool.minexmr.com" ascii
        $xmr5 = "donate-level" ascii
        $xmr6 = "--coin=" ascii
        $xmr7 = "randomx" ascii nocase
        $xmr8 = "cryptonight" ascii nocase
    condition:
        3 of them
}

rule Miner_Generic_Stratum
{
    meta:
        description = "Detects generic stratum mining protocol usage"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "mining.subscribe" ascii
        $s4 = "mining.authorize" ascii
        $s5 = "mining.submit" ascii
        $s6 = "mining.notify" ascii
    condition:
        2 of them
}

rule Miner_Mining_Pools
{
    meta:
        description = "Detects connections to known mining pools"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $pool1 = "pool.hashvault.pro" ascii
        $pool2 = "pool.supportxmr.com" ascii
        $pool3 = "xmr-us-east1.nanopool.org" ascii
        $pool4 = "mine.xmrpool.net" ascii
        $pool5 = "pool.minexmr.com" ascii
        $pool6 = "xmr.pool.minergate.com" ascii
        $pool7 = "moneroocean.stream" ascii
        $pool8 = "gulf.moneroocean.stream" ascii
        $pool9 = "pool.hashvault.pro" ascii
        $pool10 = "2miners.com" ascii
        $pool11 = "dwarfpool.com" ascii
        $pool12 = "ethereum.miningpoolhub.com" ascii
        $pool13 = "monerohash.com" ascii
        $pool14 = "herominers.com" ascii
    condition:
        any of them
}

rule Miner_Crypto_Algorithms
{
    meta:
        description = "Detects cryptocurrency mining algorithm implementations"
        severity = "medium"
        author = "HashGuard"
        category = "miners"
    strings:
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
        $algo4 = "kawpow" ascii nocase
        $algo5 = "equihash" ascii nocase
        $algo6 = "argon2" ascii nocase
        $hash1 = "cn/r" ascii
        $hash2 = "rx/0" ascii
        $hash3 = "cn-heavy" ascii
        $gpu = "OpenCL" ascii
        $gpu2 = "CUDA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($algo*) or (1 of ($hash*) and ($gpu or $gpu2))
}

rule Miner_Browser_Coinhive
{
    meta:
        description = "Detects browser-based miners (Coinhive and variants)"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $ch1 = "coinhive.min.js" ascii nocase
        $ch2 = "CoinHive.Anonymous" ascii
        $ch3 = "coin-hive.com" ascii nocase
        $ch4 = "authedmine.com" ascii nocase
        $ch5 = "jsecoin.com" ascii nocase
        $ch6 = "webassembly" ascii nocase
        $ch7 = "CryptoNight" ascii
    condition:
        2 of them
}

rule Miner_Hidden_Mining
{
    meta:
        description = "Detects hidden/stealth mining behavior"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $hide1 = "tasklist" ascii nocase
        $hide2 = "taskkill" ascii nocase
        $hide3 = "SetWindowPos" ascii
        $hide4 = "ShowWindow" ascii
        $hide5 = "SW_HIDE" ascii
        $cpu1 = "GetSystemInfo" ascii
        $cpu2 = "NumberOfProcessors" ascii
        $cpu3 = "SetProcessAffinityMask" ascii
        $mine = "stratum" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($hide*) and 1 of ($cpu*) and $mine
}

rule PUP_Adware_Browser_Extension
{
    meta:
        description = "Detects adware/PUP browser extension installation"
        severity = "medium"
        author = "HashGuard"
        category = "adware"
    strings:
        $ext1 = "\\Extensions\\" ascii nocase
        $ext2 = "manifest.json" ascii
        $ext3 = "chrome-extension://" ascii
        $ext4 = "content_scripts" ascii
        $ads1 = "inject" ascii nocase
        $ads2 = "advertisement" ascii nocase
        $ads3 = "popup" ascii nocase
        $reg = "RegSetValueEx" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($ext*) and 1 of ($ads*) and $reg
}

rule PUP_Bundleware
{
    meta:
        description = "Detects software bundling/PUP installer patterns"
        severity = "low"
        author = "HashGuard"
        category = "adware"
    strings:
        $b1 = "InstallCore" ascii nocase
        $b2 = "Crossrider" ascii nocase
        $b3 = "OpenCandy" ascii nocase
        $b4 = "DownloadManager" ascii nocase
        $b5 = "bundled" ascii nocase
        $b6 = "sponsored" ascii nocase
        $b7 = "partner" ascii nocase
        $inst = "MsiExec" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of ($b*) and $inst
}

rule Miner_Resource_Abuse
{
    meta:
        description = "Detects resource-abusing miner behavior"
        severity = "high"
        author = "HashGuard"
        category = "miners"
    strings:
        $th1 = "CreateThread" ascii
        $th2 = "GetSystemInfo" ascii
        $th3 = "SetThreadPriority" ascii
        $th4 = "THREAD_PRIORITY_LOWEST" ascii
        $alloc = "VirtualAlloc" ascii
        $huge = "PAGE_EXECUTE_READWRITE" ascii
        $port = ":3333" ascii
        $port2 = ":14444" ascii
        $port3 = ":45700" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($th*) and $alloc and ($huge or 1 of ($port*))
}
