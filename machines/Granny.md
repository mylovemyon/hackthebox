https://app.hackthebox.com/machines/Granny  
hacktheboxの「Grandpa」マシンと同じ手法でも攻略できるため、このマシンは別の手段使用

## STEP 1
```sh
└─$ rustscan -a 10.129.95.234 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.234:80
10.129.95.234 -> [80]
```

## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Granny_01.png">  
webdavが動いているかテスト
```sh
└─$ nmap -n -Pn -p80 -sV --script=http-webdav-scan 10.129.95.234
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-08 22:25 EDT
Nmap scan report for 10.129.95.234
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Server Date: Sun, 10 Aug 2025 04:20:46 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.63 seconds
```
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.129.95.234/FUZZ -fc 500

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.234/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 500
________________________________________________

_vti_bin                [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 555ms]
:: Progress: [29999/29999] :: Job [1/1] :: 100 req/sec :: Duration: [0:04:31] :: Errors: 1 ::
```
