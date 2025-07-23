https://app.hackthebox.com/machines/Sauna

## STEP 1
```sh
└─$ rustscan -a 10.129.180.28 --scripts none 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.180.28:53
Open 10.129.180.28:80
Open 10.129.180.28:88
Open 10.129.180.28:135
Open 10.129.180.28:139
Open 10.129.180.28:389
Open 10.129.180.28:445
Open 10.129.180.28:464
Open 10.129.180.28:593
Open 10.129.180.28:636
Open 10.129.180.28:3268
Open 10.129.180.28:3269
Open 10.129.180.28:5985
Open 10.129.180.28:9389
Open 10.129.180.28:49668
Open 10.129.180.28:49673
Open 10.129.180.28:49675
Open 10.129.180.28:49674
Open 10.129.180.28:49696
10.129.180.28 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49675,49674,49696]
```
```sh
└─$ nmap -n -Pn -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49675,49674,49696 -sV 10.129.180.28
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-23 02:26 EDT
Nmap scan report for 10.129.180.28
Host is up (0.47s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-23 13:26:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.47 seconds
```

## STEP 2
```sh
└─$ netexec smb 10.129.180.28 -u '' -p ''          
SMB         10.129.180.28   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.180.28   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
```
