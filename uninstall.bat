@echo off

 REM File: uninstall.bat
 REM Author: Jeff Odegard
 REM Purpose: Windows / XAMPP Uninstallation Script
 REM Created: Oct 3, 2018

 REM Copyright 2018-2019: Cyber Perspective, All rights reserved
 REM Released under the Apache v2.0 License

 REM See license.txt for details
 
 REM Change Log:
 REM - Oct 3, 2018 - File created
 REM - Jan 10, 2019 - Killed stray php processes, wait for uninstall to finish in background, move www folder (and this script) deletion to the end to avoid errors.
 
@echo.
@echo This will completely uninstall Sagacity and XAMPP and delete 
@echo the findings database and all result files in www/tmp.  
@echo.
@echo This cannot be undone.
@echo.
set /p uninstall="Are you sure? (y/N) "

set result=0
if "%uninstall%"=="Y" (set result=1)
if "%uninstall%"=="y" (set result=1)
if "%uninstall%"=="Yes" (set result=1)
if "%uninstall%"=="yes" (set result=1)
if "%uninstall%"=="YES" (set result=1)

if "%result%"=="1" (
	cd C:\
	@echo - Terminating PHP processes
	taskkill /F /IM php.exe
	@echo - Stopping Apache and MySQL services.
	sc stop Apache2.4
	sc stop mysql
	@echo - Deleting the MySQL service.
	sc delete mysql
	@echo - Uninstalling XAMPP
	C:\xampp\uninstall.exe --mode unattended
	REM Deleting the www folder (and this script) has to wait until the very end
	
	@echo.
	@echo Waiting for background process uninstall.exe to finish
	:LOOP
	tasklist | find /i "uninstall" >nul 2>&1
	IF ERRORLEVEL 1 (
		timeout /T 1 >nul
		GOTO LOOP
	)
)

@echo.
if "%result%"=="1" (
	@echo Thank you for trying Sagacity.  If you have any questions or comments, please contact us at https://www.cyberperspectives.com/contact_us
	@echo.
	set /p foo="Uninstall complete.  Press enter to continue."
	rmdir /S /Q C:\xampp\www >nul 2>&1
	exit /b
) else (
	set /p foo="Whew, that was a close one! Uninstall aborted.  Press enter to continue."
)