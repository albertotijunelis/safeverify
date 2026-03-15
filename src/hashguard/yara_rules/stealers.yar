/*
    HashGuard - Stealer / InfoStealer YARA Rules
    Detects credential-stealing malware targeting browsers, wallets, and applications.
*/

rule Stealer_Browser_Credential_Harvesting
{
    meta:
        description = "Detects browser credential harvesting patterns"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
    strings:
        $chrome1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase
        $chrome2 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii nocase
        $chrome3 = "\\Google\\Chrome\\User Data\\Local State" ascii nocase
        $ff1 = "\\Mozilla\\Firefox\\Profiles" ascii nocase
        $ff2 = "logins.json" ascii nocase
        $ff3 = "key4.db" ascii nocase
        $edge1 = "\\Microsoft\\Edge\\User Data" ascii nocase
        $opera1 = "\\Opera Software\\Opera Stable" ascii nocase
        $brave1 = "\\BraveSoftware\\Brave-Browser" ascii nocase
    condition:
        3 of them
}

rule Stealer_Crypto_Wallet_Targeting
{
    meta:
        description = "Detects cryptocurrency wallet theft"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
    strings:
        $w1 = "wallet.dat" ascii nocase
        $w2 = "\\Electrum\\wallets" ascii nocase
        $w3 = "\\Exodus\\exodus.wallet" ascii nocase
        $w4 = "\\Ethereum\\keystore" ascii nocase
        $w5 = "\\Atomic\\Local Storage" ascii nocase
        $w6 = "\\Coinomi\\wallets" ascii nocase
        $w7 = "\\Jaxx\\Local Storage" ascii nocase
        $w8 = "\\com.liberty.jaxx" ascii nocase
        $w9 = "\\Guarda\\Local Storage" ascii nocase
        $w10 = "\\Binance" ascii nocase
        $meta = "\\MetaMask" ascii nocase
        $phantom = "\\Phantom" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Stealer_Discord_Token
{
    meta:
        description = "Detects Discord token stealing"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $d1 = "discord" ascii nocase
        $d2 = "\\discord\\Local Storage" ascii nocase
        $d3 = "discordcanary" ascii nocase
        $d4 = "discordptb" ascii nocase
        $r1 = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/ ascii
        $api1 = "discord.com/api" ascii
        $api2 = "discordapp.com/api" ascii
        $hook = "webhook" ascii nocase
    condition:
        2 of ($d*) and (1 of ($r*) or 1 of ($api*) or $hook)
}

rule Stealer_Telegram_Session
{
    meta:
        description = "Detects Telegram session stealing"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $tg1 = "\\Telegram Desktop\\tdata" ascii nocase
        $tg2 = "\\Telegram Desktop" ascii nocase
        $tg3 = "D877F783D5D3EF8C" ascii
        $tg4 = "key_datas" ascii
        $tg5 = "usertag" ascii
    condition:
        uint16(0) == 0x5A4D and $tg1 and 1 of ($tg2, $tg3, $tg4, $tg5)
}

rule Stealer_Steam_Credentials
{
    meta:
        description = "Detects Steam credential theft"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $s1 = "\\Steam\\config\\loginusers.vdf" ascii nocase
        $s2 = "\\Steam\\ssfn" ascii nocase
        $s3 = "\\Steam\\config\\config.vdf" ascii nocase
        $s4 = "steamcommunity.com" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Stealer_FTP_Credentials
{
    meta:
        description = "Detects FTP credential harvesting"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $f1 = "\\FileZilla\\recentservers.xml" ascii nocase
        $f2 = "\\FileZilla\\sitemanager.xml" ascii nocase
        $f3 = "\\WinSCP\\WinSCP.ini" ascii nocase
        $f4 = "\\CoreFTP\\sites" ascii nocase
        $f5 = "\\FlashFXP" ascii nocase
        $f6 = "\\SmartFTP" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Stealer_Email_Client
{
    meta:
        description = "Detects email client credential theft"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $o1 = "\\Microsoft\\Office\\16.0\\Outlook\\Profiles" ascii nocase
        $o2 = "\\Thunderbird\\Profiles" ascii nocase
        $o3 = "\\The Bat!" ascii nocase
        $o4 = "IMAP Password" ascii nocase
        $o5 = "POP3 Password" ascii nocase
        $o6 = "SMTP Password" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Stealer_VPN_Credentials
{
    meta:
        description = "Detects VPN credential harvesting"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $v1 = "\\OpenVPN\\config" ascii nocase
        $v2 = "\\NordVPN" ascii nocase
        $v3 = "\\ProtonVPN" ascii nocase
        $v4 = "\\ExpressVPN" ascii nocase
        $v5 = ".ovpn" ascii nocase
        $v6 = "auth-user-pass" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Stealer_Password_Recovery
{
    meta:
        description = "Detects mass password recovery tool patterns"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $s1 = "CryptUnprotectData" ascii
        $s2 = "CredEnumerate" ascii
        $s3 = "LsaRetrievePrivateData" ascii
        $s4 = "vaultcli.dll" ascii nocase
        $s5 = "VaultOpenVault" ascii
        $s6 = "VaultEnumerateItems" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Stealer_SystemInfo_Fingerprinting
{
    meta:
        description = "Detects system fingerprinting common in stealers"
        severity = "medium"
        author = "HashGuard"
        category = "stealers"
    strings:
        $s1 = "systeminfo" ascii nocase
        $s2 = "ipconfig /all" ascii nocase
        $s3 = "GetAdaptersInfo" ascii
        $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor" ascii nocase
        $s5 = "SELECT * FROM Win32_" ascii nocase
        $s6 = "GetComputerName" ascii
        $s7 = "GetUserName" ascii
        $net = "HttpSendRequest" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of ($s*) and $net
}

rule Stealer_Clipboard_Monitor
{
    meta:
        description = "Detects clipboard hijacking for crypto addresses"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $c1 = "GetClipboardData" ascii
        $c2 = "SetClipboardData" ascii
        $c3 = "AddClipboardFormatListener" ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth = "0x" ascii
        $sleep = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($c*) and ($btc or $eth) and $sleep
}

rule Stealer_Screenshot_Capture
{
    meta:
        description = "Detects screenshot capabilities in stealer context"
        severity = "high"
        author = "HashGuard"
        category = "stealers"
    strings:
        $gdi1 = "CreateCompatibleDC" ascii
        $gdi2 = "BitBlt" ascii
        $gdi3 = "GetDesktopWindow" ascii
        $gdi4 = "CreateDIBSection" ascii
        $save1 = "SaveDC" ascii
        $save2 = ".png" ascii nocase
        $save3 = ".jpg" ascii nocase
        $save4 = ".bmp" ascii nocase
        $net = "InternetOpen" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of ($gdi*) and 1 of ($save*) and $net
}

rule Stealer_Lumma_Indicators
{
    meta:
        description = "Detects Lumma Stealer (LummaC2) indicators"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1555.003"
    strings:
        $ua1 = "LummaC" ascii nocase
        $ua2 = "Lumma" ascii nocase
        $c2_1 = "/api" ascii
        $c2_2 = "/c2conf" ascii
        $c2_3 = "/c2sock" ascii
        $str1 = "lid=" ascii
        $str2 = "hwid=" ascii
        $str3 = "Passwords.txt" ascii
        $str4 = "Autofills.txt" ascii
        $str5 = "CreditCards.txt" ascii
        $browser1 = "\\Login Data" ascii nocase
        $browser2 = "\\Cookies" ascii nocase
        $crypto1 = "\\Electrum\\wallets" ascii nocase
        $crypto2 = "\\Exodus\\exodus.wallet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((1 of ($ua*) and 1 of ($c2_*)) or
        (3 of ($str*) and 1 of ($browser*)) or
        (2 of ($str*) and 1 of ($browser*) and 1 of ($crypto*)))
}

rule Stealer_Raccoon_V2
{
    meta:
        description = "Detects Raccoon Stealer v2 (RecordBreaker) indicators"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1555.003"
    strings:
        $r1 = "machineId=" ascii
        $r2 = "configId=" ascii
        $r3 = "raccoon" ascii nocase
        $rc4 = "RC4" ascii
        $zip = "zip" ascii
        $b1 = "sqlite3_open" ascii
        $b2 = "sqlite3_prepare" ascii
        $tg = "api.telegram.org" ascii nocase
        $dl1 = "DLL_LIST" ascii
        $dl2 = "nss3.dll" ascii
        $dl3 = "msvcp140.dll" ascii
        $dl4 = "vcruntime140.dll" ascii
        $dl5 = "mozglue.dll" ascii
    condition:
        uint16(0) == 0x5A4D and ((2 of ($r*) and $zip) or
        (2 of ($b*) and 3 of ($dl*)) or
        ($r1 and $r2 and $rc4))
}

rule Stealer_RedLine
{
    meta:
        description = "Detects RedLine Stealer indicators"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1555.003"
    strings:
        $rl1 = "RedLine" ascii nocase
        $rl2 = "\\Yandex\\YandexBrowser\\User Data" ascii nocase
        $rl3 = "\\Chromium\\User Data" ascii nocase
        $net1 = "net.tcp://" ascii
        $net2 = "BasicHttpBinding" ascii
        $soap = "SOAP" ascii
        $hw1 = "Win32_Processor" ascii
        $hw2 = "Win32_DiskDrive" ascii
        $hw3 = "Win32_VideoController" ascii
        $hw4 = "GraphicsCards" ascii
        $hw5 = "InstalledBrowsers" ascii
        $scan1 = "ScannedFiles" ascii
        $scan2 = "ScannedWallets" ascii
        $scan3 = "ScanDetails" ascii
    condition:
        uint16(0) == 0x5A4D and (($rl1 and 1 of ($net*)) or
        (3 of ($hw*) and 1 of ($scan*)) or
        ($rl2 and $rl3 and 2 of ($hw*)))
}

rule Stealer_Vidar
{
    meta:
        description = "Detects Vidar infostealer indicators"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1555.003"
    strings:
        $v1 = "Vidar" ascii nocase
        $v2 = "profile_id=" ascii
        $v3 = "hwid=" ascii
        $c2_1 = "/ip.php" ascii
        $c2_2 = "/get.php" ascii
        $prof = "steam/steamcommunity.com/profiles/" ascii nocase
        $dead1 = "t.me/" ascii
        $dead2 = "steamcommunity.com" ascii
        $grab1 = "Autofill" ascii
        $grab2 = "passwords.txt" ascii nocase
        $grab3 = "cc.txt" ascii nocase
        $grab4 = "\\cookies\\" ascii nocase
        $dll1 = "freebl3.dll" ascii
        $dll2 = "softokn3.dll" ascii
        $dll3 = "nss3.dll" ascii
    condition:
        uint16(0) == 0x5A4D and ((1 of ($v*) and 1 of ($c2_*)) or
        ($prof or 1 of ($dead*)) and 2 of ($grab*) or
        (2 of ($dll*) and 2 of ($grab*)))
}

rule Stealer_RisePro
{
    meta:
        description = "Detects RisePro stealer indicators"
        severity = "critical"
        author = "HashGuard"
        category = "stealers"
        mitre = "T1555.003"
    strings:
        $rp1 = "RisePro" ascii nocase
        $rp2 = "risepro" ascii nocase
        $tcp1 = "TcpClient" ascii
        $tcp2 = "NetworkStream" ascii
        $grab1 = "GrabBrowsers" ascii
        $grab2 = "GrabCryptoWallets" ascii
        $grab3 = "GrabPasswords" ascii
        $grab4 = "GrabFTP" ascii
        $grab5 = "GrabVPN" ascii
        $b1 = "\\User Data\\Default\\Login Data" ascii nocase
        $b2 = "CryptUnprotectData" ascii
        $b3 = "sqlite3_column_text" ascii
    condition:
        uint16(0) == 0x5A4D and ((1 of ($rp*) and 1 of ($tcp*)) or
        (3 of ($grab*)) or
        ($b1 and $b2 and $b3 and 1 of ($grab*)))
}
