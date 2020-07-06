_[<-- Back](https://flast101.github.io/HTB-writeups)_


## 4- Privilege Escalation

### 4.1- Post-Compromise Enumeration  

We must gather more information about our user **mhope**:
~~~
*Evil-WinRM* PS C:\Users\mhope\desktop> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
~~~
Interesting to notice that mhope is member of the **"Azure Admins"** group and we found its credentials in the **"azure.xml"** file.

If we google the words “Azure Admins privesc”, we find several links. One of those was released by one of our famous active members [VbScrub](https://www.hackthebox.eu/home/users/profile/158833):    
_Azure AD Connect Database Exploit (Priv Esc)_: https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/

This article also reveals this interesting Github repo:   
_Azure AD Connect password extraction_: https://github.com/fox-it/adconnectdump

### 4.2- Post-Compromise Exploitation
Let's try it.     
We download **AdDecrypt.exe** and **mcrypt.dll** on the target. As indicated, these two files must be placed in the directory where we will launch the exploit. Once done, we have:
~~~
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> Dir -Force C:\Users\mhope\Documents\

    Directory: C:\Users\mhope\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl         1/3/2020   5:24 AM                My Music
d--hsl         1/3/2020   5:24 AM                My Pictures
d--hsl         1/3/2020   5:24 AM                My Videos
d-----        5/31/2020  11:37 PM                WindowsPowerShell
-a----        5/31/2020  11:13 PM          10866 20200531231329_BloodHound.zip
-a----        5/31/2020  11:56 PM          14848 AdDecrypt.exe
-a-hs-         1/3/2020   5:24 AM            402 desktop.ini
-a----        5/31/2020  11:57 PM         334248 mcrypt.dll
-a----        5/31/2020  11:13 PM          15037 MmU4ODNmNTctYjM2MS00N2U1LWI5NjctNDg2N2E5YmZmZmEx.bin
-a----        5/31/2020  11:22 PM          59392 nc.exe
-a----        5/31/2020  11:37 PM          90794 powerzure.ps1
-a----        5/31/2020  11:13 PM         972875 sharphound.ps1
~~~
Notice that I first tried BloodHound, but unsuccessfully...  
 
And now, this is time for execution. We must execute the exploit in the directory **"C:\Program Files\Microsoft Azure AD Sync\Bin"**, and it works fine:
![AdDecrypt](images/addecrypt.png "AdDecrypt.exe")

We finally have our Administrator credentials **"administrator:xxxxxxxxxxxxxxxx"**. We just have to login as **Administrator** and it is done:

![root.txt](images/root-txt.png "root.txt")

Happy Hacking ! 

[<img src="http://www.hackthebox.eu/badge/image/249498" alt="Hack The Box">](https://www.hackthebox.eu/profile/249498)

_[<-- Back](https://flast101.github.io/HTB-writeups)_
