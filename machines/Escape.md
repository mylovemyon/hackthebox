https://app.hackthebox.com/machines/531

## STEP 1
```sh
└─$ rustscan -a 10.129.228.253 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.253:53
Open 10.129.228.253:88
Open 10.129.228.253:593
Open 10.129.228.253:636
Open 10.129.228.253:1433
Open 10.129.228.253:3268
Open 10.129.228.253:3269
Open 10.129.228.253:5985
Open 10.129.228.253:9389
Open 10.129.228.253:49667
Open 10.129.228.253:49690
Open 10.129.228.253:49689
Open 10.129.228.253:49711
Open 10.129.228.253:49721
Open 10.129.228.253:49742
10.129.228.253 -> [53,88,593,636,1433,3268,3269,5985,9389,49667,49690,49689,49711,49721,49742]
```


## STEP 2
guestでsmb列挙
```sh
└─$ netexec smb 10.129.228.253 -u ' ' -p '' --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.253  445    DC               [+] sequel.htb\ : (Guest)
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share
```
pdfファイルを発見・ダウンロード
```sh
└─$ smbclient -N -c ls //10.129.228.253/Public          
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1447083 blocks available

└─$ smbget -N 'smb://10.129.228.253/Public/SQL Server Procedures.pdf'
Using domain: WORKGROUP, user: kali
smb://10.129.228.253/Public/SQL Server Procedures.pdf 
Downloaded 48.39kB in 15 seconds
```
pdfはmssqlに関するもの、step1で1433番がオープンであったことを確認したのでmssqlが動作している  
ユーザ名`PublicUser`パスワード`GuestUserCantWrite1@`を確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Escape_01.png">  
pdfのクレデンシャルでmssqlにログイン成功
```sh
└─$ impacket-mssqlclient 'PublicUser:GuestUserCantWrite1@10.129.228.253'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```
