https://app.hackthebox.com/machines/Grandpa

## STEP 1
```sh
└─$ rustscan -a 10.129.95.233 --scripts none
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
Open 10.129.95.233:80
10.129.95.233 -> [80]
```

## STEP 2
```sh
└─$ curl -I http://10.129.95.233                                      
HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://10.129.95.233/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:300"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Thu, 17 Jul 2025 01:26:05 GMT
```
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.95.233/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.233/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 253ms]
_private                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 302ms]
_vti_cnf                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 265ms]
_vti_log                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 300ms]
_vti_pvt                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 300ms]
_vti_txt                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 301ms]
_vti_bin                [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 343ms]
_vti_bin/_vti_aut/author.dll [Status: 200, Size: 195, Words: 5, Lines: 13, Duration: 474ms]
_vti_bin/_vti_adm/admin.dll [Status: 200, Size: 195, Words: 5, Lines: 13, Duration: 474ms]
_vti_bin/shtml.dll      [Status: 200, Size: 96, Words: 11, Lines: 1, Duration: 476ms]
aspnet_client           [Status: 403, Size: 218, Words: 14, Lines: 2, Duration: 252ms]
images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 252ms]
:: Progress: [4746/4746] :: Job [1/1] :: 150 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```
https://jlajara.gitlab.io/process-migration
