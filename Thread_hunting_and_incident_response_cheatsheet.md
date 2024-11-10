# Thread Hunting & Incident Response Cheatsheet

## Network Analysis

### Quick overview with NetworkMiner

Ask the following questions:

 - Are all devices names following the naming conventions and are all devices known or is some device following the naming conventions, still not a known company device?

 - Are all devices use the OS, which is used by the organisation?  
   e.g. if all clients are Windows 10 devices, a Windows 11 or Linux device should be suspicious.

 - Do diverent devices use the same IP?  
   e.g. a device with taking later over a known good device IP must raise suspision!

 - Are all devices part of the domain?

 - Are all IP addresses in the network identifyable as known devices?

 - Are all devices showing informations (OS, Vendor, etc.)?

 - Is most traffic part of a session?

 - Is the traffic showing a normal pattern?  
   e.g. very large amount of DNS traffic can indicate data exfiltration via DNS
   A lot of ARP replyes may indicate ARP poisioning, etc.  
   Client devices not obtaining an IP via DHCP should raise suspicion.  
   Outgoint connection to many different ports may indicate a portscan.  
   ARP replies for the same IP going back and forth between 2 different MAC addresses can indicate an IP conflict or MITM attack.  
   Most DNS traffic must be A / AAAA records not TXT or something else.   

 - Are unusual ports used to send traffic?  
   e.g. port 80, 443, 22, etc. as source port (those are typical destination ports but not source ports)  
   Accessing webpages via HTTP (port 80) instead of HTTPS (port 443) allow credential theft or may indicate a phishing website, etc.  

 - Do some devices use odd ports or do some connection seem odd?  
   A non-admin device should not connect a server via RDP (3389), SQL (3306), etc. (*Check the TCP session for odd things*)  
   Devices should only use ports from known and in the organisation used applications - if some device start to use ports / services which are not used in the org., that must raise suspicion.

 - What ports are open on which device?  
   Usually only servers have open ports, so are all devices with open ports known servers?

 - Are some MAC addresses odd and not identifyabe or get identified as devices of brands, which are not used in the company?

 - What DNS queries are made by what device?  
   Many programms check for updates on startup and thus query the application websites IP via DNS - this can reveal the use of Wireshark and other tools.  
   This can also reveal what a person is looking for - e.g. Websites of know advisery tools.

 - Is a device producing a big amount of traffic?  
   Massive amount of sent data indicate data exfiltration.

 - Check files tab for unusual things...  
   HTML-files should only be send by servers and not regular devices. Ideally you should not even see HTML files, because they should be send encrypted via HTTPS.  
   Potential Malware like scripts or EXE files transfered to a server  

### Detail analysis with Wirtshark / Tshark / Zeek

Ask the following questions:

 - Do packets look normal?  
   e.g. HTTPS packets must cointain valis encrypted session (Secure Sockets Layer field) data and not cleartext, an empty Secure Sockets Layer field (indivating another encryption used) etc.
 
 - Check usernames in SMB2 packets (search for "User: ")

 - Check for filenames in SMB2 packets (search for "Create Request File: ")  
   Files like `ntds.dit` (*All usernames and PW hashes for the domain*) must raise an alarm! 

 - Check time-delta for a connection - periodically occuring connections can indicate beaconing  
   `tshark -r sample-200.pcap -T fields -e ip.src -e ip.dst -e udp.dstport -e frame.time_delta_displayed 'ip.src==1.1.1.1 && ip.dst==2.2.2.2' | head -20`

 - Check DNS query type  
   `cat dns.log | zeek-cut -c id.orig_h query qtype_name answers`  
   `cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr`

 - Check DNS queries sum by domain  
   `cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 20`
   `tshark -r sample-200.pcap -T fields -e dns.qry.name udp.dstport==53 | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 20`  
   Open **Statistics** -> **DNS** in Wireshark

 - Check IP addresses querying a domain  
   `cat dns.log | zeek-cut id.orig_h query | grep 'suspicious-domain\.com' | cut -f 1 | sort | uniq -c`  
   `cat dns.log | zeek-cut query answers | grep 'suspicious-domain\.com' | cut -f 2 | cut -d ' ' -f 3 | egrep '([0-9]{0,3}\.)[0-9]{0,3}' | sort | uniq`

 - Check what device is connecting to a speciffic IP  
   `cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c`

 - Checking the top connections  
   `cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 20`  
   Check IP addresses for anomalies - DNS queries to unknown DNS servers, HTTP traffic to unknown webservers, etc.  
   Open **Analyze** -> **Expert Information** in Wireshark to see an overview.  

 - Checking how much data is transfered to what IP  
   `cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 3 | head -n 20` (outgoing)  
   `cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3+$4 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 3 | head -n 20` (both directions)

 - Search for odd user agent values in HTTP traffic logs  
   `cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -n 20`

## Hunting malware on a webserver 

### Useful tools

 - LOKI / THOR APT Scanner (https://github.com/Neo23x0/Loki)
 - NeoPI (https://github.com/CiscoCXSecurity/NeoPI)
 - BackdoorMan (https://github.com/cys3c/BackdoorMan)
 - PHP-malware-finder (https://github.com/nbs-system/php-malware-finder)
 - UnPHP - Online PHP Decoder (https://www.unphp.net/)
 - Web Shell Detector (https://shelldetector.com/)
 - Linux Malware Detect (https://www.rfxn.com/projects/linux-malware-detect/)
 - Invoke-ExchangeWebShellHunter (https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)
 - NPROCWATCH (https://udurrani.com/0fff/tl.html)
 - Log Parser Studio (https://techcommunity.microsoft.com/t5/exchange-team-blog/log-parser-studio-2-0-is-now-available/ba-p/593266)
 - https://github.com/shr3ddersec/ThreatHunting/blob/master/THP.md

### PHP functions often used in malware

 - `fsockopen()`
 - `pfsockopen()`
 - `exec()`
 - `system()`
 - `shell_exec()`
 - `passthru()`
 - `eval()`
 - `mail()` (also often used in regular web development)
 - `base64_decode()` (also often used in regular web development)

### Techniques

 - **File-Stacking** (find recently added or modified files - e.g. changed or added source files after the last update)
 
 - **Baselining** (Having a MD5 sum for each source file allow to identify changed files)
 
 - **Statistical analysis** (Number of executions / occurences in a log or execution time can indicate many things)  
   Long execution time may indicate some unwanted activities  
   Many executions of a script may indicate attacks (SQLi, Bruteforce, ...)
 
 - **Log analysis** (Loop fo odd things)  
   Strange file-paths (e.g. `../../../../../etc/passwd`)  
   Strange parameters (e.g. `q=<script>...</script>`, ...)
 
 - **Strings** (Running the strings command againce files may reveal malware)  
   e.g. PHP code embedded in a JPEG file.

 - **Process creation hirarchy** 
   e.g. `w3wp.exe` spawning a instalce of `cmd.exe` or `apache` spawning a `bash` instance
   Use for example Get-W3WPChildren.ps1 in Windows.


## Endpoint hunting

### Windows core processes

Ask for each process the following questions:

 - Did it get started by the expected parent process?
 - Is it started the expected amount of times? (e.g. some processes sould exist only once)
 - Is the name spelled correctly?  
   Malware try to hide by using similiar names then core processes - e.g. `svchosts.exe` or `svchost32.exe` instead of `svchost.exe`
 - Is the executable stored in the correct location?  
   Programms started from temp. directories should raise suspicion
 - Is it running under the expected SID / user account?
 - Is the executable signed by Microsoft?

Use `pslist64.exe -t` from Sysinternals to get a hirarchical view or use Process Explorer.

#### Sessions

 - **Session 0**  
   Created on start to run the system processes not related to a speciffic user.

 - **Session 1**  
   First user session - created when the first user loggs in.

#### smss.exe (Session Manager)

 - Should only run once
 - Started by parent process `system`
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\smss.exe`
 - Started when the system is booted

#### csrss.exe (Client/Server Run Subsystem Process)

 - Started for each user session
 - Started by `smss.exe` but will appear as it has no parent process
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\csrss.exe`
 - Started when the system is booted and when a ne user session is created
 - Typically you will see 2 instances (one for session 0 and one for session 1)  
   Additional RDP- or user-sessions spawn additional instances.

#### winlogon.exe 

 - Started for each user session
 - Started by `smss.exe` but will appear as it has no parent process
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\winlogon.exe`
 - First instance is started when the system is booted and other instances may get started later 

Abuses may use the `SHELL` or `Userinit` registry keys to start different executables. The expected executable is: `explorer.exe`

#### winlogon.exe 

 - Started only once
 - Starts itself the child processes `services.exe`, `lsass.exe` and `lsm.exe` in session 0
 - Started by `smss.exe` but will appear as it has no parent process
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\winlogon.exe`
 - Started when the system is booted

#### lsm.exe / lsm.dll (Login Session Manager)

 - Started only once
 - Started by `wininit.exe`
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\lsm.exe` / `%SystemRoot%\System32\lsm.dll`  
   The exe-file was replaced in Windows7 by a dll run as a service.  
   You should not see in Windows 8/10/11 a `lsm.exe` running.
 - Started when the system is booted

#### services.exe (Service Control Manager)

 - Started only once
 - Starts itself the child processes `svchost.exe`, `dllhost.exe`, `taskhost.exe`, `spoolsv.exe`, etc.
 - Informations about services an be queried with `sc.exe`
 - Started by `wininit.exe`
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\services.exe`
 - Started when the system is booted

#### lsass.exe (Local Security Authority Subsystem)

 - Started only once
 - Started by `wininit.exe`
 - Started by user `NT AUTHORITY\SYSTEM`
 - Path: `%SystemRoot%\System32\lsass.exe`
 - Started when the system is booted

This process is commonly attacked to dump password hashes, etc. 

#### svchost.exe (Service Host - used to start a DLL as a service)

 - Started multiple times
 - Started by `services.exe`
 - Started by user `NT AUTHORITY\SYSTEM`, `LOCAL SERVICE` or `NETWORK SERVICE`
 - Path: `%SystemRoot%\System32\svchost.exe`
 - Started when a service is started - sone instances on boot, some later

Uses of `svchost.exe` without the `-k` option sould raise suspicion! This process is often used to start malware...

#### taskhost.exe / taskhostex.exe (Win 8) / taskhostw.exe (Win 10)

 - Run processes from DLLs, started none or even multiple times
 - Started by `services.exe`
 - Started by different users
 - Path: `%SystemRoot%\System32\taskhost.exe`
 - Started when a process is started

#### explorer.exe 

 - One processes per logged on user
 - Started by `userinit.exe` but will appear as it has no parent process because `userinit.exe` will terminate after login.
 - Started by different users
 - Path: `%SystemRoot%\explorer.exe`
 - Started when a user logs in

### All those core processes sould 

 - only start from the default location (especially not from temp. directories or the-like)
 - not communicat over the internet with some servers
 - be digitally signed by Microsoft

#### General tipps:

 - Look at all processes which started `cmd.exe`, `powershell.exe`, `wscript.exe` or processes like `svchost.exe` as child.

 - Compare the system to a known good baseline.  
   Powershell DSC (Desired State Configuration) can provide a baseline for System settings.
   Powershell or Tools like SCCM can help with other baselines - e.g.:
    - `Get-Service * | Where { $_.status -eq "Running" }`
    - `Get-Process`
    - `Get-ChildItem -Recurse | ForEach-Object { "$($_.FullName): $($(Get-FileHash $_ -Algorithm MD5).Hash)" }`
    - `Get-WmiObject Win32_SystemUsers`
    - `Get-WmiObject Win32_UserAccount`

### Windows API calls often used in malware:

**Locate process**

 - `CreateToolhelp32Snapshot()`
 - `Process32First()`
 - `Process32Next()`

**Open process/thread**

 - `GetModuleHandle()`
 - `GetProcAddress()`
 - `OpenProcess()`
 - `NtOpenProcess()`
 - `CreateProcess()`
 - `OpenThread()`

**Un-map memory**

 - `ZwUnmapViewOfSection()`
 - `NtUnmapViewOfSection()`

**Suspend/resume thread for injection**

 - `SuspendThread()`
 - `ResumeThread()`

**Set thread context**

 - `SetThreadContext()`

**Hook injection**

 - `SetWindowsHookEx()`

**Allocate memory for DLL/PE injection**

 - `VirtualAllocEx()`

**Inject**

 - `WriteProcessMemory()`

**Execute**

 - `CreateRemoteThread()`
 - `LoadLibary()`
 - `NTCreateThreadEx()`
 - `RtlCreateUserThread()`

**Process Doppelganging**

 - `CreateTransaction()`

### Evasion techniques to avoid detection / reverse engineering

 - Rootkits
 - Masquerading such as using similiar names like `svchost32.exe`, `lsasss.exe` or `lsnn.exe`
 - Packing - this reduces the size of an EXE file and thus the number of patterns
 - Recompiling with another compiler / settings to create a different EXE file signature due to different optimisations
 - Obfuscation to make reverse-engineering harder and buy time till AV updates are published
 - Adding junk-code as misdirection and to change the signature of the EXE file
 - Encrypted storage in the drive - malware get decrypted and launched by a helper programm so it exist only in RAM

### Suspicious locations from which normally no binary sould run

 - `C:\Users\*`
 - `C:\Programdata\*`
 - `C:\Windows\Temp\*`

### Malware persistance techniques

 - Adding itself to the autostart folder
 - Adding autostart entries in the Registry
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
   - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
   - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
   - `HKLM\Software\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options`
   - To detect - use `AutoRuns` from SysInternals
 - Scheduled tasks - `at.exe` and `schtasks.exe` can be used to create one  
   Tasks will be stored under `C:\Windows\Tasks\`
 - COM highjacking - changeing legitimate COM references to malicious one and waiting that they get called
 - DLL highjacking via search order - placing a equally named DLL in a folder that is in `$PATH` listed before the folder with the legitimate DLL
 - Phantom DLL placement - EXE files sometimes try to load old DLL files which no longer exist in Windows, placing a malicious DLL with the name of the old DLL file into a certail folder can cause outdated application to load the malicious DLL
 - DLL highjacking via side-loading - placing a malicious DLL in the WinSxS folder, used to keep certain version of DLLs side-by-side on the system
 - Windows service creation
 - Windows service replacement
 - Windows service recovery - setting recovery action for the failure of a legitimate service to run the malware
 - Persistence through accessability features (T1015) using:  
   `Sethc.exe`, `Utilman.exe`, `Osk.exe`, `Magnify.exe`, `Narrator.exe`, `DisplaySwitch.exe`, `AtBroker.exe`

### Malware detection and analysis tools

 - **PECapture** - Capture and display all loaded DLL and EXE files (there is also a service-only version of that tool)
 - **ProcScan.rb** - Ruby script that scans process memory, looking for code injection
 - **Meterpreter payload detection**
 - **Reflective injection detection**  
 - **PowerShellArsenal** - disassemble code, .NET malware analysis, parse various files and memory structures
 - **Get-Injected-Thread.ps1** - Scan active threads for code injection
 - **SSDeep** - Hashing parts of a file (fuzzy hashing) to match smaller sub-parts
 - **ImpHash-Generator** - creating a hach from the DLL imports / API names and there order to reduce the hash only to the core characteristics
 - **ShimCahceParser** - extract Windows ShimCache artefacts
 - **AppCompatProcessor** - extract Windows AppCompat / AmCache artefacts
 - **FTK Imager** / **Magnet RAM Cacpure** - creating a memory dump
 - **Mandiant's Redline** - memory dump collection and triage for fast overview
 - **Volatility** - memory dump analysis in full detail
 - **Memhunter** and **Captain** - triaging live systems memory
 - **PEStudio** - analyse PE-files
 - **Process Hacker** - xxx
 - **API Monitor x64** - check what API calls get executed

### UAC bypass indicators

 - Check the registry key `HKCU\Software\Classes\exefile\shell\runas\command\isolatedCommand`  
   But that location could change - therefore better search for `shell\runas\command\isolatedCommand`

#### Additional tipps for memory forensics / hunting

 - Here we have also to lookout for the same things as already described like 
   - misspelled filenames, 
   - strange locations of EXE and DDl files like temp. folders, 
   - unusual network connections, 
   - unusual used applications, 
   - etc.
 - Unmapped memeory pages with execute privileges (code injection)
 - Hooked API functions
 - known bad signatures (e.g. YARA rules)

#### Volatility 2.x tipps

 - Rootkits unlink their processes from the processes linked-list in the OS. Thatfor `pslist` not not show them. `psscan` search the whole image for a data-structure from a process and will find those but it can also find left-over structures from a alredy ended process or even false-positives.
 - `psxview` compares the results from multiple methods to find processes.
 - `pstree` show the hirachical process structure, but can't hidden processes. 
 - `netscan` can even find alredy closes network connection but can also produce false-positives.
 - `malfind` detect code injection into a process but can also produce false-positives.
 - `apihooks` detect API hooks.
 - `ssdt` detect SSDT (System Service Dispatch Table) hooks.
 - `threads` detect unlinked threads or threads using a hooked SSDT.
 - `modules` list all the modules (e.g. drivers) and base addresses.
 - `moddump` allow to dump a module for further analysis.
 - `yarascan` allow to search with a yara rule.
 - Helpful plugins for rootkit detection are: `idt`, `ssdt`, `apihooks`, `modules`, `modscan`, `driverirp` and `driverscan`.
 - `linux_check_modules` compare `/proc/module` with `/sysfs/module` to find hidden modules
 - `linux_hidden_modules` is another way to find hidden modules.
 - `linux_check_syscall` checks for modifications of the `sys_call_table` and compares it with the addresses in the Kernel syscall table to find hidden hooks.
 - `linux_check_inline_kernel` checks for inline hooking by searching for `JMP`, `CALL` or `RET` instructions in the prolog.
 - `linux_volshell` give you a interaltive shell and in this shell you can use for example: 
   - `db(0xffffffffa0523740, 128)` to get the hexdump of 128 bytes starting at the specified address.
   - `dis(0xffffffff81098d20, length=128)` to get the disassembly of 128 bytes starting at the specified address.
   - `dis(addrspace().profile.get_symbol("fillonedir"), length=128)` to find the start address instead of specifying it manually.

#### Volatility 3.x tipps

 - COMMING SOON !!!

### Programms often used to spawn malicious processes

 - `mshta.exe`
 - `rundll32.exe`
 - `regsvr32.exe`
 - `services.exe`
 - `winword.exe`
 - `wmic.exe`
 - `wmiprvse.exe`
 - `powerpnt.exe`
 - `excel.exe`
 - `msaccess.exe`
 - `mpub.exe`
 - `visio.exe`
 - `outlook.exe`
 - `chrome.exe`
 - `iexplorer.exe`
 - `sqlserver.exe`
 - `powershell.exe`
 - `wscript.exe`
 - `cscript.exe`
 - `cms.exe`

### Windows event logs

 - 3 main sections of event logs
   - Application - eventy from user software (many AV software also logs to this section)
   - System - eventy logged by Windows system components (driver loading, service start/stop, ...)
   - Security - events that are security / authentication related (valid/invalid logon, account creation, ...)
   - depending on certain factors there can be more sections

#### Important event ID numbers for user account related hunting

 - **4624** - successfull logon regardless ot the used auth. method  
   Logon-Types:
   - 2 = interctive / user logon from the machine locally
   - 3 = network - NT Hash / Kerberos
   - 4 = batch - password stored as LSA secret
   - 5 = service - password stored as LSA secret
   - 7 = unlock
   - 8 = network in cleartext - e.g. IIS Basic auth.
   - 9 = new credentials - `runas` or network-logon
   - 10 = remote interactive - RDP logon
   - 11 = cached interactive - logon cred. verified from cache, credintials did not get verified by the domain controller
 - **4625** - failed logon
   - A SubStatus of `0xC0000072` would tell us, that the account is disabled.
 - **4634** - successfull logoff
 - **4647** - user initiated logoff
 - **4648** - logon using explicit credentials
 - **4672** - special privileges assigned
 - **4662** - Domain object replication (DCsync attack) - check if initiator PC is not another DC  
   To prevent false-positives check if `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` is in Access Control -> Properties of the event.
 - **4663** - Attempt to access a object - check for accesses to XML-files in SYSVOL (those may store credentials)
 - **4768** - Kerberos ticket (TGT) requested
 - **4769** - Kerberos service ticket requested
 - **4771** - Kerberos pre-auth failed (like 4625 for Kerberos)
 - **4776** - Kerberos attempt to validate credentials
 - **4778** - Windows session reconnected
 - **4779** - Windows session disconnected 
 - **4720** - account created
 - **4722** - account enabled
 - **4724** - attempt to reset password
 - **4728** - user added to global group
 - **4732** - user added ro local group
 - **4738** - user account changed
 - **4756** - user added ro universal group
 - **4798** - user's local group membership was enumerated
 - **4799** - security-enabled local group membership was enumerated
 - **5136** - a directory service object was modiefied (e.g.: GPO - Group Policy Object)

#### Important event ID numbers for PsExec related hunting

 - **4688** - Process started (Sysmon EID 1)
 - **4697** - Service creation
 - **7045** - Service creation in depth information
 - **5140** - Windows share accessed
 - **5145** - Windows share request (look out for `IPC$` or `ADMIN$`)

Look out for `psexecsvc` or general executables that use `\\` and `-accepteula`!

#### Important event ID numbers for scheduled tasks hunting

 - **4698** - Scheduled task created
 - **4700** - Scheduled task enabled
 - **4701** - Scheduled task disabled
 - **4702** - Scheduled task updated
 - **106** - Scheduled task created (Task schueduler)
 - **200** - Scheduled task started (Task schueduler)
 - **201** - Scheduled task ended regardless if gracefully or not (Task schueduler)

#### Important event ID numbers for service hunting

 - **4697** - Service installed
 - **7040** - Service startup type changed

#### Important event ID numbers for network share hunting

 - **4776** - Network share authentication successfull / failed
 - **5140** - Network share access granted
 - **5142** - Network share added
 - **5145** - Network share access denied

#### Important event ID numbers for event manipulation hunting

 - **6005** - Event log service started (can also show system start)
 - **6006** - Event log service stoped
 - **1102** - Error in event logs (Microsoft-Windows-Kernel-Eventlog)
 - **104** - Event service started / stopped (Microsoft-Windows-Kernel-Eventlog)
 - **4656** - Handle to an object (file, reg. key, etc.) created - can indicate reg. manipulation or file creation/modification!

#### Important event ID numbers for powershell abuse hunting

 - **4104** - Powershell script started
 - **4105** - Powershell script terminated gracefully
 - **4106** - Powershell script terminated with error

Check event IDs `400`, `600` and `800` for powershell versions lower than the host version and check for applications using `System.Management.Automation.dll` in other programms than `powershell.exe` and `powershell_ise.exe`.

### Important event ID numbers for AMSI (Anti Malware Scanning Interface) related hunting

 - **4104** - Powershell script started (Search for the keyword `Amsi`)  
   Scanner: https://blog.f-secure.com/hunting-for-amsi-bypasses/

#### Other useful events

 - **1116** - Defender malware detection
 - **1118** - Defender malware remediation started
 - **1119** - Defender malware remediation succeeded
 - **1120** - Defender malware remediation failed
 - **4656** - Handle to an object (file, reg. key, etc.) created - can indicate reg. manipulation or file creation/modification!
 - **4719** - Auditing policy changed
 - **5001** - Defender real-time protection changed
 - **5157** - Defender blocked a network connection

### Sysmon events and use in detecting evil

 - **1 - Process creation (start of an executable file)**     
   Check for abnormal parent child relations
 - **2 - A process changed a file creation time**  
   Useful for detecting Timestomping
 - **3 - Network connection created**  
   Usual very noisy - check for other areas first or search for known evil activities like powershell.exe connecting to the internet, etc.
 - **4 - Sysmon service state changed (service started or stopped)**  
   Very noisy because of frequent Sysmon restarts
 - **5 - Process terminated**  
   Check for termination of key processes like AV, EDR, etc.
 - **6 - Driver loaded**  
   This eventy can show "bring your own driver" attacks but the logs are very noisy and analysing them take a lot of time - better focus first on lower hanging fruits
 - **7 - Image loaded (a process loading a DLL)**  
   Allow to detect DLL highjacks
 - **8 - CreateRemoteThread (indicate malware migrating in another process)**  
   Allow to find injected threads but can be also very noisy as many legitimate applications create threads for legitimate reasons
 - **9 - RawAccessRead (reading operations from the drive using the `\\.\` denotation)**
 - **10 - ProcessAccess (hacking tools that read the memory contents of processes)**  
   Useful for finding code injection in processes or memory dumping
   Pay attention to occurances of `UNKNOWN` in the `CallTrace` field - they can indicate calls from shellcode as those memory regions do not map to any file on disk - false positives are here also likely to take each finding with a grain of salt
 - **11 - FileCreate (a file is created or overwritten)**  
   Can be very noisy for later in the hunt very useful to correlate file origins
 - **12 - Registry entry change (key and value create and delete operations)**  
 - **13 - Registry value set (value of a key set)**
 - **14 - Registry entry renamed (key and value rename operations)**  
   Events 12-14 are very noisy but they can be very useful with targeted searches - e.g. creation of an autostart entry for persistence
 - **15 - FileCreateStreamHash (named file stream is created = file download)**  
   This can be used to identify downloads
 - **16 - ServiceConfigurationChange (event logs changes in the Sysmon configuration)**  
   Useful for spotting tampering with Sysmon.
 - **17 - PipeEvent (a named pipe is created - often used for ICP)**  
   Useful to uncover inter process communication attempts, use of `PsExec` and SMB latheral movement
 - **18 - PipeEvent (logs when a named pipe connection is made between a client and a server)**
 - **19 - WMI filter reg. (WMI event filter is registered, which is a method used by malware to execute)**
 - **20 - WMI consumer reg. (registration of WMI consumers)**
 - **21 - WMI bind (consumer binds to a filter)**
 - **22 - DNS query (whether the result is successful or fails, cached or not - only Win. 8.1 and later)**  
   Useful for finding DNS beacons and beacon resolution
   MS Defender SmartScreen usually initiate a Scan when a file is downloded and this often cause a DNS query for `*.smartscreen.microsoft.com`, which can be found in DNS logs for example. As trojan downloaders are usually pretty small the DNS query for the site from where the file was downloaded must be a short time before. 
 - **23 - FileDelete (file was deleted, additionally to logging, the deleted file is also saved in the ArchiveDirectory, which is `C:\Sysmon` by default)**  
   Can show if a thread actor tryed to destroy evidence and cover his tracks
 - **24 - ClipboardChange (new content in the clipboard)**
 - **25 - ProcessTampering**  
   Show process hiding techniques such as "hollowing" or "herpadering"
 - **26 - FileDeleteDetected (same as 23 but without file saving)**
 - **27 - FileBlockExecutable (Sysmon detects and blocks the creation of an executable PE file)**
 - **28 - FileBlockShredding (Sysmon detects and blocks file shredding from tools such as SDelete)**
 - **29 - FileExecutableDetected Sysmon detects the creation of a new executable PE file)**

### Event Tracing For Windows (ETW)

... is a general-purpose, high-speed tracing facility provided by the operating system. Using a buffering and logging mechanism implemented in the kernel, ETW provides a tracing mechanism for events raised by both user-mode applications and kernel-mode device drivers.

 - **Microsoft-Windows-Kernel-Process:** This ETW provider is instrumental in monitoring process-related activity within the Windows kernel. It can aid in detecting unusual process behaviors such as process injection, process hollowing, and other tactics commonly used by malware and advanced persistent threats (APTs).
 - **Microsoft-Windows-Kernel-File:** As the name suggests, this provider focuses on file-related operations. It can be employed for detection scenarios involving unauthorized file access, changes to critical system files, or suspicious file operations indicative of exfiltration or ransomware activity.
 - **Microsoft-Windows-Kernel-Network:** This ETW provider offers visibility into network-related activity at the kernel level. It's especially useful in detecting network-based attacks such as data exfiltration, unauthorized network connections, and potential signs of command and control (C2) communication.
 - **Microsoft-Windows-SMBClient/SMBServer:** These providers monitor Server Message Block (SMB) client and server activity, providing insights into file sharing and network communication. They can be used to detect unusual SMB traffic patterns, potentially indicating lateral movement or data exfiltration.
 - **Microsoft-Windows-DotNETRuntime:** This provider focuses on .NET runtime events, making it ideal for identifying anomalies in .NET application execution, potential exploitation of .NET vulnerabilities, or malicious .NET assembly loading.
 - **OpenSSH:** Monitoring the OpenSSH ETW provider can provide important insights into Secure Shell (SSH) connection attempts, successful and failed authentications, and potential brute force attacks.
 - **Microsoft-Windows-VPN-Client:** This provider enables tracking of Virtual Private Network (VPN) client events. It can be useful for identifying unauthorized or suspicious VPN connections.
 - **Microsoft-Windows-PowerShell:** This ETW provider tracks PowerShell execution and command activity, making it invaluable for detecting suspicious PowerShell usage, script block logging, and potential misuse or exploitation.
 - **Microsoft-Windows-Kernel-Registry:** This provider monitors registry operations, making it useful for detection scenarios related to changes in registry keys, often associated with persistence mechanisms, malware installation, or system configuration changes.
 - **Microsoft-Windows-CodeIntegrity:** This provider monitors code and driver integrity checks, which can be key in identifying attempts to load unsigned or malicious drivers or code.
 - **Microsoft-Antimalware-Service:** This ETW provider can be employed to detect potential issues with the antimalware service, including disabled services, configuration changes, or potential evasion techniques employed by malware.
 - **WinRM:** Monitoring the Windows Remote Management (WinRM) provider can reveal unauthorized or suspicious remote management activity, often indicative of lateral movement or remote command execution.
 - **Microsoft-Windows-TerminalServices-LocalSessionManager:** This provider tracks local Terminal Services sessions, making it useful for detecting unauthorized or suspicious remote desktop activity.
 - **Microsoft-Windows-Security-Mitigations:** This provider keeps tabs on the effectiveness and operations of security mitigations in place. It's essential for identifying potential bypass attempts of these security controls.
 - **Microsoft-Windows-DNS-Client:** This ETW provider gives visibility into DNS client activity, which is crucial for detecting DNS-based attacks, including DNS tunneling or unusual DNS requests that may indicate C2 communication.
 - **Microsoft-Antimalware-Protection:** This provider monitors the operations of antimalware protection mechanisms. It can be used to detect any issues with these mechanisms, such as disabled protection features, configuration changes, or signs of evasion techniques employed by malicious actors.
 - **Microsoft-Windows-Threat-Intelligence:** This provider offers crucial insights into potential security threats and is often leveraged in Digital Forensics and Incident Response (DFIR) operations. However, to access this provider, processes must be privileged with a specific right, known as Protected Process Light (PPL).


### PowerShell abuse

#### Possible switches often used for malicious purpose:

 - `-encodedcommand` or `-e` for short
 - `-bxor`
 - `-join`

#### Possible functions often used for malicious purpose:

 - `FromBase64String`
 - `Invoke-Execution` or `iex` for short
 - `Invoke-DLLInjection`
 - `Invoke-ReflectivePEInjection`
 - `Invoke-Shellcode` 
 - `Load` in combination with `ReadAllBytes` or `LoadFile`
 - `Get-GPPPassword` 
 - `Get-Keystrokes`
 - `Get-TimedScreenshot`
 - `WebClient`
 - `DownloadData`
 - `DownloadFile`
 - `DownloadString`
 - `OpenRead`
 - `WebRequest`
 - `curl`
 - `wget`
 - `RestMethod`
 - `WinHTTP`
 - `InternetExplorer.Application`
 - `Excel.Application`
 - `Word.Application`
 - `Msxml2.XMLHTTP`
 - `MsXML2.ServerXML`
 - `System.XML.XMLDocument`
 - `BitsTransfer`

#### Command combinations used in obfuscation

 - `char` and `join`
 - `ToInt` / `ToInt16` / `ToDecimal` / `ToByte` / `ToUnit` / `ToSingle` and `ToChar` / `ToString` / `String`
 - `ForEach` and `Xor`

#### DLLs often loaded to execute powershell in another process

 - `system.management.automation.dll`
 - `clr.dll`
 - `clrjit.dll`
 - `mscoree.dll`
 
#### Known malicious frameworks

 - PowerUp
 - Mimikatz 
 - NinjaCopy 
 - Get-ModifiablePath 
 - AllChecks 
 - AmsiBypass 
 - PsUACme 
 - PowerView

### .NET abuse

xxx

#### Libraries often loaded to execute .NET code directly in RAM (like CobaltStrikes `execute-assembly`)

 - `clr.dll`
 - `clrjit.dll`
 - `mscoree.dll`

### COM (Component Object Model) abuse

#### CLSIDs / Objects often abused

 - `0002DF01-0000-0000-C000-000000000046` (InternetExplorer.Application)
 - `F6D90F16-9C73-11D3-B32E-00C04F990BB4` (Msxml2.XMLHTTP)
 - `F5078F35-C551-11D3-89B9-0000F81FE221` (Msxml2.XMLHTTP.3.0)
 - `88D9D96A-F192-11D4-A65F-0040963251E5` (Msxml2.XMLHTTP.6.0)
 - `AFBA6B42-5692-48EA-8141-DC517DCF0EF1` (Msxml2.ServerXmlHttp)
 - `AFB40FFD-B609-40A3-9828-F88BBE11E4E3` (Msxml2.ServerXmlHttp.3.0)
 - `88D96A0B-F192-11D4-A65F-0040963251E5` (Msxml2.ServerXmlHttp.6.0)
 - `2087C2F4-2CEF-4953-A8AB-66779B670495` (WinHttp.WinHttpRequest.5.1)
 - `000209FF-0000-0000-C000-000000000046` (Word.Application)
 - `00023500-0000-0000-C000-000000000046` (Excel.Application)

#### COM Highjacking

COM classes and their executables are mapped in:

 - `HKCU\Software\Classes\CLSID`
 - `HKLM\Software\Classes\CLSID`

Herby definds `LocalServer32` the EXE- and `InprocServer32` the DLL-file, which get executed then a COM class is called.

Only admins can modify the values in `HKLM` but every user can modify the entries in `HKCU` and those entries take precedence over the ones in `HKLM`, thus allowing COM Highjacking.

Check `HKCU\Software\Classes\CLSID` - usually there should be none or only very few entries!

### Incident response tools

 - Sysmon from SysInternals
 - Kansa (https://github.com/davehull/Kansa)  
   Incident response framework
 - PSHunt (https://github.com/Infocyte/PSHunt)  
   Thread hunting module to scan remote hosts for IOCs and to collect various information like running processes, auutstarts, actual configuration values, etc.
 - NOAH (https://github.com/giMini/NOAH)  
   Agentless incident response framework wich allows to collect key artefacts.

### WMI abuse hunting

 - `wmiprsve.exe` spawning `powershell.exe` or some malicious executable

## Useful additional ressources

 - https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts (Guides)
 - https://lolbas-project.github.io/ (List of legitimate option which can be misuesd in attacks)


## Wazuh

Ideal for beginner threadhunting lap setups.

**Recommended additional logs for Windows**

Add those lines to `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

To ingest all logs not just those creating alerts do the following configuration changes:

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    ...
```

Set `logall` and `logall_json` to `yes` in the file `/var/ossec/etc/ossec.conf`.

Then edit `/etc/filebeat/filebeat.yml` and set `enabled` for `archives` to `true`:

```yaml
...
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
...
```

Then restart all needed services:

```bash
systemctl restart filebeat
systemctl restart wazuh-manager
```

Then open in Wazuh `Dashboard Management` -> `Dashboard Management` -> `Index pattern` and add an index for `wazuh-archives-*`.

