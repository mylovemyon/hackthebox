## STEP 1
```sh
└─$ rustscan -a 10.129.246.117 --scripts none
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
Open 10.129.246.117:22
Open 10.129.246.117:25
Open 10.129.246.117:80
Open 10.129.246.117:111
Open 10.129.246.117:110
Open 10.129.246.117:143
Open 10.129.246.117:443
Open 10.129.246.117:857
Open 10.129.246.117:993
Open 10.129.246.117:995
Open 10.129.246.117:3306
Open 10.129.246.117:4190
Open 10.129.246.117:4445
Open 10.129.246.117:4559
Open 10.129.246.117:5038
Open 10.129.246.117:10000
10.129.246.117 -> [22,25,80,111,110,143,443,857,993,995,3306,4190,4445,4559,5038,10000]
```
```sh
└─$ nmap -n -Pn -sV 10.129.246.117 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-06 02:46 EDT
Nmap scan report for 10.129.246.117
Host is up (0.48s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Host: 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.23 seconds
```


## STEP 2
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://10.129.246.117/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.246.117/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 426ms]
.htaccess               [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 296ms]
.hta                    [Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 255ms]
admin                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 278ms]
cgi-bin/                [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 270ms]
configs                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 260ms]
favicon.ico             [Status: 200, Size: 894, Words: 6, Lines: 1, Duration: 262ms]
help                    [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 271ms]
images                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 301ms]
index.php               [Status: 200, Size: 1785, Words: 103, Lines: 35, Duration: 291ms]
lang                    [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 267ms]
libs                    [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 376ms]
mail                    [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 310ms]
modules                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 277ms]
panel                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 264ms]
robots.txt              [Status: 200, Size: 28, Words: 3, Lines: 3, Duration: 343ms]
static                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 312ms]
themes                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 261ms]
var                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 256ms]
:: Progress: [4744/4744] :: Job [1/1] :: 35 req/sec :: Duration: [0:02:16] :: Errors: 0 :
```
