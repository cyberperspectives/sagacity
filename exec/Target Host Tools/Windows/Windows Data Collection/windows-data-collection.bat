@echo off
REM ########################################################################
REM windows-data-collection.bat - collects ST&E relevant data
REM Jeff A. Odegard, CISSP  15 May 13
REM 
REM ########################################################################

HOSTNAME >HOSTNAME.txt
for /F "eol=; tokens=1* delims= " %%i in (HOSTNAME.txt) do @set HOSTNAME=%%i
set OUTDIR=C:\temp\%HOSTNAME%
mkdir %OUTDIR% >nul 2>&1
set originaldir=%cd%
echo.
echo Results will be in %OUTDIR%
echo.
echo  Admin privilege required.  Checking access
net session >nul 2>&1
if %errorlevel% NEQ 0 (
	echo.
	echo.     ERROR:  Script must run with administrative privileges!
	goto end_of_script
) 
echo.   - Success
echo.
set VERSION="0.1, 15 May 13"
echo. | date /t >C:\temp\%HOSTNAME%\date.txt
echo. | time /t >C:\temp\%HOSTNAME%\time.txt
set dt=
set tm=
for /F "eol=; tokens=* delims= " %%i in (C:\temp\%HOSTNAME%\date.txt) do @set dt=%%i
for /F "eol=; tokens=5 delims= " %%i in (C:\temp\%HOSTNAME%\time.txt) do @set tm=%%i
rem This is the way you do string substitution in Batch...
set dt=%dt:/=-%
set dt=%dt: =%
REM set tm=%tm =%
REM set tm=%tm: =%

del /F C:\temp\%HOSTNAME%\date.txt C:\temp\%HOSTNAME%\time.txt HOSTNAME.txt
set OUTBASE=%HOSTNAME%.txt
set SUMMARYFILE=%OUTDIR%\%HOSTNAME%-data-collection-summary-%dt%.txt
set CHECKSUMS=%OUTDIR%\%HOSTNAME%-checksums-%dt%.txt
setlocal enableextensions enabledelayedexpansion
REM ########################################################################
REM Data Gathering Starts Here
REM ########################################################################

del /f /q c:\temp\%HOSTNAME%\*

echo User List  | tee.cmd %SUMMARYFILE%
wmic useraccount get name,sid 2>&1 > %OUTDIR%\user_list.txt

echo Windows Registry Permissions
REM This produces a 60Meg file.  Need to modify to only pull perms required for STIG
echo   * DUMPSEC.exe /rpt=registry=HKEY_LOCAL_MACHINE /outfile=%OUTDIR%\HKLM-permissions.csv /saveas=csv >> %SUMMARYFILE%
echo   * dumpsec.exe HKEY_LOCAL_MACHINE to HKLM-permissions.csv
DUMPSEC.exe /rpt=registry=HKEY_LOCAL_MACHINE /outfile=%OUTDIR%\HKLM-permissions.csv /saveas=csv
echo   * DUMPSEC.exe /rpt=registry=HKEY_USERS /outfile=%OUTDIR%\HKU-permissions.csv /saveas=csv >> %SUMMARYFILE%
echo   * dumpsec.exe HKEY_USERS to HKU-permissions.csv
DUMPSEC.exe /rpt=registry=HKEY_USERS /outfile=%OUTDIR%\HKU-permissions.csv /saveas=csv
echo.

echo   * 1.006, net localgroup "Administrators" | tee.cmd %OUTDIR%\admin_group.txt
echo     -- net localgroup "Administrators" | tee.cmd %SUMMARYFILE%
net localgroup "Administrators" > %OUTDIR%\admin_group.txt
echo.

echo   * 1.007, Backup Operators Group | tee.cmd %OUTDIR%\backup_group.txt
echo     -- net localgroup "Backup Operators" | tee.cmd %SUMMARYFILE%
net localgroup "Backup Operators" > %OUTDIR%\backup_group.txt
echo.

echo   * 2.001, Log File Permissions | tee.cmd %OUTDIR%\log_permissions.txt
echo     -- icacls C:\Windows\System32\winevt\Logs\Application.evtx | tee.cmd %SUMMARYFILE%
icacls C:\Windows\System32\winevt\Logs\Application.evtx > %OUTDIR%\log_permissions.txt
echo     -- icacls C:\Windows\System32\winevt\Logs\Security.evtx | tee.cmd %SUMMARYFILE%
icacls C:\Windows\System32\winevt\Logs\Security.evtx >> %OUTDIR%\log_permissions.txt
echo     -- icacls C:\Windows\System32\winevt\Logs\System.evtx | tee.cmd %SUMMARYFILE%
icacls C:\Windows\System32\winevt\Logs\System.evtx >> %OUTDIR%\log_permissions.txt
echo.

echo   * 2.008 NTFS Requirement | tee.cmd %OUTDIR%\disk_partitions.txt
echo list volume > listvol.scr
echo     -- diskpart /s listvol.scr | tee.cmd %SUMMARYFILE%
diskpart /s listvol.scr > %OUTDIR%\disk_partitions.txt
del listvol.scr

echo   * 2.015 File Share ACLs | tee.cmd %OUTDIR%\net_shares.txt
echo     -- net share | tee.cmd %SUMMARYFILE%
net share > %OUTDIR%\net_shares.txt
for /F "eol=; tokens=1 delims= " %%i in (%OUTDIR%\net_shares.txt) do (
	set mytest=foo
	if %%i == "2.015" set mytest=bar 
	if "%%i" == "Share" set mytest=bar
	if "%%i" == "The" set mytest=bar
	if "%%i" == "-------------------------------------------------------------------------------" set mytest=bar
	if '%%i' == '*' set mytest =bar
	if "!mytest!"=="foo" (
		echo.    - Permissions for %%i
		echo    - net share %%i >> %SUMMARYFILE%
		net share %%i >> %OUTDIR%\net_shares.txt 2>&1
	)
)
echo.

echo   * 2.005, Unsupported Service Packs | tee.cmd %OUTDIR%\os_info.txt
echo     -- systeminfo OS Name, Version, Type, Domain, Logon Server | tee.cmd %SUMMARYFILE%
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain" /C:"Logon Server" > %OUTDIR%\os_info.txt
echo.

echo   * 2.019 Security Related Software Patches | tee.cmd %OUTDIR%\hotfixes.txt
echo     -- wmic /output:hotfixes.txt qfe list | tee.cmd %SUMMARYFILE%
wmic qfe list > %OUTDIR%\hotfixes.txt
echo.

echo   * 2.021, Software Certificate Installation Files | tee.cmd %OUTDIR%\hotfixes.txt
echo     -- dir /s /b *.p12 *.pfs (C:\) | tee.cmd %SUMMARYFILE%
cd C:\
dir /s /b *.p12 *.pfs > %OUTDIR%\hotfixes.txt
cd %originaldir%
echo.

REM Miscellaneous info
echo Miscellaneous Information | tee.cmd %SUMMARYFILE%
echo   * tasklist.exe - process list | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\tasklist.txt
echo     -- tasklist.exe | tee.cmd %SUMMARYFILE%
tasklist.exe > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * net.exe start - Running Windows Services | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\net-start.txt
echo     -- net.exe start | tee.cmd %SUMMARYFILE%
net.exe start > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * tasklist /svc - Services Associated with Processes | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\tasklist-svc.txt
echo     -- tasklist.exe /svc | tee.cmd %SUMMARYFILE%
tasklist.exe /svc > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * wmic process list full - detailed process information  | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\wmic-process-list-full.txt
echo     -- wmic.exe process list full | tee.cmd %SUMMARYFILE%
wmic.exe process list full > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * wmic startup list full - List all startup tasks | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\wmic-startup-list-full.txt
echo     -- wmic.exe startup list full | tee.cmd %SUMMARYFILE%
wmic.exe startup list full > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * reg query  - list contents of startup registry keys | tee.cmd %SUMMARYFILE%
echo      - reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
echo      - reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> %SUMMARYFILE%
set OUTFILE=%OUTDIR%\reg-query-Run.txt
echo     -- reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | tee.cmd %SUMMARYFILE%
reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Run  2>&1 > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo      - reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce | tee.cmd %SUMMARYFILE% 
set OUTFILE=%OUTDIR%\reg-query-Runonce.txt
echo     -- reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce | tee.cmd %SUMMARYFILE%
reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce 2>&1 > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%
 
echo      - reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\reg-query-Runonce-Ex.txt
echo     -- reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx | tee.cmd %SUMMARYFILE%
reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx 2>&1 > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * netstat -naob - list network services, connections and processes | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\netstat-naob.txt
echo     -- netstat -naob | tee.cmd %SUMMARYFILE%
netstat -naob > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%
 
echo   * nbtstat -S - record active NetBIOS connections | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\nbtstat-S.txt
echo     -- nbtstat -S | tee.cmd %SUMMARYFILE%
nbtstat -S > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * nbtstat -c - record cached NetBIOS connections | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\nbtstat-c.txt
echo     -- nbtstat -c | tee.cmd %SUMMARYFILE%
nbtstat -c > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * arp -a - record Arp Table  | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\arp-a.txt
echo     -- arp -a | tee.cmd %SUMMARYFILE%
arp -a > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * ipconfig /all - List all network devices | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\ipconfig-all.txt
echo     -- ipconfig /all | tee.cmd %SUMMARYFILE%
ipconfig /all > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * net view \\127.0.0.1  - list file shares | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\file-shares.txt
echo     -- net view \\127.0.0.1 | tee.cmd %SUMMARYFILE%
net view \\127.0.0.1 > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * net sessions - list open NetBIOS sessions | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\net-sessions.txt
echo     -- net sessions | tee.cmd %SUMMARYFILE%
net sessions > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * netsh firewall show config - display firewall configuration | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\netsh-firewall-show-config.txt
echo     -- netsh firewall show config | tee.cmd %SUMMARYFILE%
netsh firewall show config > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * net user - list system users | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\system-users.txt
echo     -- net user | tee.cmd %SUMMARYFILE%
net user > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * net localgroup administrators - list local system administrator accounts | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\local-administrators.txt
echo     -- net localgroup administrator | tee.cmd %SUMMARYFILE%
net localgroup administrators > %OUTFILE%
fciv.exe -both "%OUTFILE%" >> %CHECKSUMS%

echo   * Installed Software | tee.cmd %SUMMARYFILE%
set OUTFILE=%OUTDIR%\installed-software.csv
echo     -- wmic product /format:csv get name,version | tee.cmd %SUMMARYFILE%
wmic product get /format:csv name,version > %OUTFILE%

echo   * Query the registry for values | tee.cmd  %SUMMARYFILE%
for /F "eol=; tokens=1,2 delims=," %%i in (reg-values-to-check.txt) do (
	echo     - reg query "%%i" | tee.cmd  %SUMMARYFILE%
	if "%%j" NEQ "" (
		if "%%j" EQU "(Default)" (reg query "%%i" /v 2>&1 >> %OUTDIR%\registry-values.txt
		) else (reg query "%%i" /v "%%j" 2>&1 >> %OUTDIR%\registry-values.txt)
	) else (reg query "%%i" 2>&1 >> %OUTDIR%\registry-values.txt)
)

echo   * Gather file version information | tee.cmd  %SUMMARYFILE%
for /F "eol=; tokens=* delims= " %%i in (files-to-version.txt) do (
	echo     -- filever.vbs %%i | tee.cmd  %SUMMARYFILE%
	cscript -nologo "%originaldir%\filever.vbs" "%%i" >> %OUTDIR%\file-version-results.txt
)

echo   * Gather auditing information | tee.cmd  %SUMMARYFILE%
set OUTFILE=%OUTDIR%\audit_information.csv
echo     -- auditpol /get /category:* /r
auditpol /get /category:* /r > %OUTFILE%

echo   * Gather Security Policy Information | tee.cmd %SUMMARYFILE%
echo     -- secedit /export /cfg security_policy.inf /areas SECURITYPOLICY
secedit /export /cfg %OUTDIR%\security_policy.inf /areas SECURITYPOLICY /quiet

REM Do this last, so they can save off the policy, zip everything up and finish the script.
REM echo Security Policy Checks | tee.cmd  %SUMMARYFILE%
REM echo   gpedit.msc will open.
REM echo      Expand: Computer Configuration 
REM echo                       - Windows Settings 
REM echo                                 -- Security Settings 
REM echo                                             --- Local Policies
REM echo.
REM echo   * Audit Policy - single click, right click - export list, 
REM echo      -- save as audit_policy.txt
REM echo   * User Rights - single click, right click - export list, 
REM echo      -- save as user_rights.txt
REM echo   * Security Options - single click, right click - export list, 
REM echo      -- save as security_options.txt
REM echo   * Under Account Policies, save Password Policies and Account Lockout Policies
REM echo      -- save as password_policy.txt
REM echo      -- save as account_policy.txt
REM echo.
REM echo   Close the Policy editor when you're finished.
REM echo   * gpedit.msc | tee.cmd %SUMMARYFILE%
REM gpedit.msc 
REM echo. 

REM ########################################################################
REM End Data Gathering
REM ########################################################################

echo Windows data collection complete.  Normality has been restored...
REM echo Zip and copy %OUTDIR% to the PTL for further analysis.
REM dir %OUTDIR%
REM PAUSE

7z u -y -tzip DataCollection.zip %OUTDIR%

cd %originaldir%
:end_of_script
cd !originaldir!