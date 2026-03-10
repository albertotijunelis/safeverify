/*
    HashGuard - C2 (Command & Control) and Backdoor YARA Rules
    Detects C2 frameworks, beacons, and communication patterns.
*/

rule C2_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon artifacts"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $config1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 }
        $str1 = "%s.4444" ascii
        $str2 = "beacon.dll" ascii
        $str3 = "beacon.x64.dll" ascii
        $str4 = "ReflectiveLoader" ascii
        $str5 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $pipe = "\\\\.\\pipe\\msagent_" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($str*) or $config1 or $pipe)
}

rule C2_Cobalt_Strike_Stager
{
    meta:
        description = "Detects Cobalt Strike stager shellcode"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $stager = { FC E8 ?? 00 00 00 [0-32] EB 27 5? 8B ?? 00 }
        $http = "/submit.php" ascii
        $http2 = "Cookie: " ascii
        $ua = "Mozilla/5.0" ascii
    condition:
        $stager or (uint16(0) == 0x5A4D and $http and $http2 and $ua)
}

rule C2_Metasploit_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter patterns"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $met1 = "metsrv" ascii
        $met2 = "stdapi_" ascii
        $met3 = "priv_elevate" ascii
        $met4 = "ext_server_" ascii
        $met5 = "core_channel_" ascii
        $rev = { 6A 05 6A 01 6A 02 }
    condition:
        uint16(0) == 0x5A4D and (3 of ($met*) or $rev)
}

rule C2_Sliver_Implant
{
    meta:
        description = "Detects Sliver C2 framework implant"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $go1 = "github.com/bishopfox/sliver" ascii
        $go2 = "sliverpb." ascii
        $go3 = "implant/sliver" ascii
        $fn1 = "StartBeaconLoop" ascii
        $fn2 = "SliverHTTPClient" ascii
        $fn3 = "PivotListener" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule C2_Brute_Ratel
{
    meta:
        description = "Detects Brute Ratel C4 badger artifacts"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $br1 = "badger_" ascii
        $br2 = "BRc4" ascii
        $br3 = "bruteratel" ascii nocase
        $br4 = "badger.x64" ascii
        $br5 = "1768.dll" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule C2_Mythic_Agent
{
    meta:
        description = "Detects Mythic C2 framework agents"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $m1 = "mythic" ascii nocase
        $m2 = "apollo" ascii nocase
        $m3 = "apfell" ascii nocase
        $m4 = "poseidon" ascii nocase
        $m5 = "callback_host" ascii
        $m6 = "encrypted_exchange_check" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule C2_Havoc_Demon
{
    meta:
        description = "Detects Havoc C2 framework demon agent"
        severity = "critical"
        author = "HashGuard"
        category = "c2"
    strings:
        $h1 = "demon.x64" ascii
        $h2 = "HavocFramework" ascii
        $h3 = "DemonMain" ascii
        $h4 = "havoc" ascii nocase
        $go = "github.com/HavocFramework" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule C2_Generic_HTTP_Beacon
{
    meta:
        description = "Detects generic HTTP-based C2 beacon patterns"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $ua = "User-Agent:" ascii
        $http1 = "POST" ascii
        $http2 = "Content-Type" ascii
        $enc1 = "base64" ascii nocase
        $jitter = "Sleep" ascii
        $cmd = "cmd" ascii
        $shell = "shell" ascii
        $exec = "execute" ascii
        $download = "download" ascii
        $upload = "upload" ascii
        $b64_1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
    condition:
        uint16(0) == 0x5A4D and $ua and ($http1 or $http2) and $jitter and 3 of ($cmd, $shell, $exec, $download, $upload) and ($enc1 or $b64_1)
}

rule C2_DNS_Tunneling
{
    meta:
        description = "Detects DNS-based C2 tunneling"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $dns1 = "DnsQuery" ascii
        $dns2 = "DnsQueryEx" ascii
        $dns3 = "getaddrinfo" ascii
        $dns4 = "gethostbyname" ascii
        $txt = "DNS_TYPE_TEXT" ascii
        $enc = "base" ascii nocase
        $sub = /[a-z0-9]{30,}\.[a-z]{2,6}/ ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($dns*) and ($txt or $enc or $sub)
}

rule C2_IRC_Bot
{
    meta:
        description = "Detects IRC-based C2 bot patterns"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $irc1 = "PRIVMSG" ascii
        $irc2 = "JOIN #" ascii
        $irc3 = "NICK " ascii
        $irc4 = "USER " ascii
        $irc5 = "PING :" ascii
        $irc6 = "PONG :" ascii
        $port = ":6667" ascii
    condition:
        4 of them
}

rule C2_Telegram_Bot
{
    meta:
        description = "Detects Telegram-based C2 communication"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $tg1 = "api.telegram.org" ascii
        $tg2 = "/bot" ascii
        $tg3 = "/sendMessage" ascii
        $tg4 = "/sendDocument" ascii
        $tg5 = "/getUpdates" ascii
        $tg6 = "chat_id" ascii
    condition:
        $tg1 and 2 of ($tg2, $tg3, $tg4, $tg5, $tg6)
}

rule C2_Discord_Webhook
{
    meta:
        description = "Detects Discord webhook-based exfiltration/C2"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $wh1 = "discord.com/api/webhooks/" ascii
        $wh2 = "discordapp.com/api/webhooks/" ascii
        $embed = "embeds" ascii
        $content = "content" ascii
    condition:
        ($wh1 or $wh2) and ($embed or $content)
}

rule C2_Pastebin_Exfil
{
    meta:
        description = "Detects Pastebin/paste-site based C2"
        severity = "medium"
        author = "HashGuard"
        category = "c2"
    strings:
        $p1 = "pastebin.com" ascii nocase
        $p2 = "paste.ee" ascii nocase
        $p3 = "hastebin.com" ascii nocase
        $p4 = "ghostbin.com" ascii nocase
        $p5 = "raw/" ascii
        $api = "api_dev_key" ascii
    condition:
        1 of ($p*) and ($p5 or $api) and filesize < 5MB
}

rule C2_ICMP_Tunnel
{
    meta:
        description = "Detects ICMP-based covert channel"
        severity = "high"
        author = "HashGuard"
        category = "c2"
    strings:
        $icmp1 = "IcmpSendEcho" ascii
        $icmp2 = "IcmpCreateFile" ascii
        $icmp3 = "SOCK_RAW" ascii
        $icmp4 = "IPPROTO_ICMP" ascii
        $buf = "VirtualAlloc" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($icmp*) and $buf
}
